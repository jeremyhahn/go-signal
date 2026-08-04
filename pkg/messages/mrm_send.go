package messages

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"
)

// MRMAccountLookup resolves a destination account by its UUID string. Used by
// SendMRMBinary to map each recipient ServiceId in the multi-recipient
// ciphertext back to a full account record (so device-set/registration-id
// validation can run, and the envelope can be addressed to the right ACI/PNI).
//
// Implementations should return a non-nil account on success and a typed
// not-found error otherwise. The exact error type is not inspected: any
// non-nil error is treated as "recipient missing" and added to UUIDs404.
type MRMAccountLookup func(ctx context.Context, uuidStr string) (account *MRMRecipientAccount, err error)

// MRMRecipientAccount is the minimal subset of an account record needed to
// route a multi-recipient send: the canonical UUID and the list of valid
// device IDs. Additional fields can be added later (e.g. for registration-id
// validation parity with Java) without churning callers.
type MRMRecipientAccount struct {
	UUID string
}

// MRMSendRequest carries the inputs for a binary multi-recipient send.
//
// Body is the raw SealedSender v2 multi-recipient ciphertext as supplied by
// the client. Timestamp is the per-message wallclock timestamp (milliseconds
// since epoch). Lookup resolves each recipient's account.
type MRMSendRequest struct {
	Body      []byte
	Timestamp uint64
	Lookup    MRMAccountLookup
}

// MRMSendResult carries the per-call outcomes that callers need to surface
// to clients: the list of recipient UUIDs that did not resolve to an
// account.
type MRMSendResult struct {
	UUIDs404 []string
}

// ErrMRMNoCache is returned by SendMRMBinary when the manager was not
// configured with an MRM cache (SetMRMCache was never called or was called
// with nil). Callers should reject the request with a 503-equivalent.
var ErrMRMNoCache = errors.New("mrm: cache not configured")

// ErrMRMNoRecipients is returned by SendMRMBinary when the parsed ciphertext
// contains no recipients with at least one device. Callers should treat this
// as a 400-equivalent.
var ErrMRMNoRecipients = errors.New("mrm: no recipients in ciphertext")

// SendMRMBinary parses a SealedSender v2 multi-recipient ciphertext, stores
// the shared payload in the MRM cache once, and enqueues a per-recipient
// envelope referencing the cached payload for every (resolved) recipient
// device. Mirrors Java Signal-Server's binary multi-recipient endpoint.
//
// Recipients whose UUID does not resolve to an account via the supplied
// lookup are skipped and their UUIDs are returned in MRMSendResult.UUIDs404.
// All other failures (parse error, cache insert error, envelope insert
// error) are returned as errors.
//
// All envelopes are tagged as EnvelopeTypeUnidentifiedSender (sealed sender)
// since the multi-recipient endpoint is anonymous.
func (m *MessagesManager) SendMRMBinary(ctx context.Context, req MRMSendRequest) (*MRMSendResult, error) {
	if req.Lookup == nil {
		return nil, errors.New("mrm: account lookup is required")
	}
	cache := m.loadMRMCache()
	if cache == nil {
		return nil, ErrMRMNoCache
	}

	parsed, err := sealed.ParseSealedSenderV2SentMessage(req.Body)
	if err != nil {
		return nil, &MRMSendError{Op: "parse ciphertext", Cause: err}
	}
	if len(parsed.RecipientOrder) == 0 {
		return nil, ErrMRMNoRecipients
	}

	// Build per-recipient view headers and resolve destination accounts in a
	// single pass so any lookup error short-circuits cache insertion.
	type plan struct {
		account     *MRMRecipientAccount
		serviceID   protocol.ServiceId
		deviceIDs   []uint64
		viewHeader  []byte
		viewKeyByID map[uint64]string
	}
	plans := make([]plan, 0, len(parsed.RecipientOrder))
	views := make(map[string][]byte, len(parsed.RecipientOrder)*2)
	uuids404 := make([]string, 0)

	for _, sidStr := range parsed.RecipientOrder {
		recip := parsed.Recipients[sidStr]
		serviceID, err := parseServiceIDLabel(sidStr)
		if err != nil {
			return nil, &MRMSendError{Op: "invalid recipient service id", Cause: err}
		}

		uuidStr := serviceID.UUIDString()
		acct, err := req.Lookup(ctx, uuidStr)
		if err != nil || acct == nil {
			uuids404 = append(uuids404, uuidStr)
			continue
		}

		viewHeader, err := parsed.SerializedRecipientView(serviceID)
		if err != nil {
			return nil, &MRMSendError{Op: "serialized view for", UUID: uuidStr, Cause: err}
		}

		deviceIDs := make([]uint64, 0, len(recip.DeviceIDs))
		viewKeyByID := make(map[uint64]string, len(recip.DeviceIDs))
		for _, did := range recip.DeviceIDs {
			deviceID := uint64(did)
			deviceIDs = append(deviceIDs, deviceID)
			vk := SharedMRMViewKey(serviceID, byte(did))
			viewKeyByID[deviceID] = vk
			views[vk] = viewHeader
		}

		plans = append(plans, plan{
			account:     acct,
			serviceID:   serviceID,
			deviceIDs:   deviceIDs,
			viewHeader:  viewHeader,
			viewKeyByID: viewKeyByID,
		})
	}

	if len(plans) == 0 {
		return &MRMSendResult{UUIDs404: uuids404}, nil
	}

	mrmGUID := uuid.New()
	sharedKey := SharedMRMKey(mrmGUID)
	if err := cache.Insert(ctx, sharedKey, req.Body, views); err != nil {
		return nil, &MRMSendError{Op: "cache insert", Cause: err}
	}

	for _, p := range plans {
		for _, deviceID := range p.deviceIDs {
			envelope := &Envelope{
				Type:                   EnvelopeTypeUnidentifiedSender,
				DestinationUUID:        p.account.UUID,
				DestinationDevice:      deviceID,
				Timestamp:              req.Timestamp,
				Urgent:                 true,
				SharedMrmKey:           []byte(sharedKey),
				SharedMrmRecipientView: []byte(p.viewKeyByID[deviceID]),
			}
			if err := m.Insert(ctx, p.account.UUID, deviceID, envelope); err != nil {
				return nil, &MRMSendError{Op: "envelope insert for", UUID: p.account.UUID, Device: deviceID, Cause: err}
			}
		}
	}

	return &MRMSendResult{UUIDs404: uuids404}, nil
}

// parseServiceIDLabel parses a Signal canonical ServiceId string ("PNI:<uuid>"
// or a bare ACI UUID, since the ACI form omits the prefix). Mirrors the
// REST-handler-local helper of the same name; lifted here so SendMRMBinary
// is self-contained.
func parseServiceIDLabel(s string) (protocol.ServiceId, error) {
	if strings.HasPrefix(s, "PNI:") {
		return protocol.ServiceIdFromString(protocol.ServiceIdKindPNI, strings.TrimPrefix(s, "PNI:"))
	}
	if strings.HasPrefix(s, "ACI:") {
		return protocol.ServiceIdFromString(protocol.ServiceIdKindACI, strings.TrimPrefix(s, "ACI:"))
	}
	return protocol.ServiceIdFromString(protocol.ServiceIdKindACI, s)
}
