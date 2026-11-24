package messages

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"
)

// MRMAccountLookup resolves a recipient UUID to its account; any error counts the recipient as missing (UUIDs404).
type MRMAccountLookup func(ctx context.Context, uuidStr string) (account *MRMRecipientAccount, err error)

// MRMRecipientAccount is the UUID and device IDs needed to route a multi-recipient send.
type MRMRecipientAccount struct {
	UUID string
}

// MRMSendRequest is a binary multi-recipient send: the Sealed Sender v2 body, a millisecond timestamp and the account lookup.
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

// SendMRMBinary stores the Sealed Sender v2 payload once and enqueues sealed-sender envelopes for every resolved recipient device; unresolved UUIDs go to UUIDs404.
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

// parseServiceIDLabel parses "PNI:<uuid>" or a bare ACI UUID.
func parseServiceIDLabel(s string) (protocol.ServiceId, error) {
	if strings.HasPrefix(s, "PNI:") {
		return protocol.ServiceIdFromString(protocol.ServiceIdKindPNI, strings.TrimPrefix(s, "PNI:"))
	}
	if strings.HasPrefix(s, "ACI:") {
		return protocol.ServiceIdFromString(protocol.ServiceIdKindACI, strings.TrimPrefix(s, "ACI:"))
	}
	return protocol.ServiceIdFromString(protocol.ServiceIdKindACI, s)
}
