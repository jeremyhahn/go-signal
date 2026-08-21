package rest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/spam"
)

const (
	// maxMessageTimestamp is the upper bound for envelope timestamps, matching
	// the Java Signal-Server MAX_TIMESTAMP constant (~274 years in milliseconds).
	maxMessageTimestamp int64 = 86_400_000 * 100_000_000

	// maxMessagesPerRequest is the maximum number of per-device messages
	// allowed in a single send request.
	maxMessagesPerRequest = 1000
)

// validEnvelopeTypes is the set of client-submittable envelope types.
// Type 0 (unknown) and type 4 (key exchange legacy) and type 7 (server-only
// SERVER_DELIVERY_RECEIPT) are excluded. EnvelopeTypePlaintextContent (8) is
// included because clients may send sender-key distribution messages.
var validEnvelopeTypes = map[messages.EnvelopeType]struct{}{
	messages.EnvelopeTypeCiphertext:         {},
	messages.EnvelopeTypeKeyExchange:        {},
	messages.EnvelopeTypePrekeyBundle:       {},
	messages.EnvelopeTypeReceipt:            {},
	messages.EnvelopeTypeUnidentifiedSender: {},
	messages.EnvelopeTypePlaintextContent:   {},
}

// validateIncomingMessages checks structural constraints on the message list
// submitted by a sender. It returns a non-empty error string on the first
// violation; the caller should write a 400 response with that string.
//
// The timestamp is validated at the list level because that is the one the
// envelope carries — see the note on IncomingMessageList.Timestamp. Checking a
// per-message value would leave the value that actually reaches the client
// unbounded.
//
// Constraints enforced:
//  1. Request size: len(req.Messages) <= maxMessagesPerRequest.
//  2. Content non-empty: each message entity must carry a non-empty content string.
//  3. Timestamp range: 0 <= req.Timestamp <= maxMessageTimestamp.
//  4. Envelope type valid: must be a client-submittable EnvelopeType.
//  5. No duplicate destination device IDs within the batch.
func validateIncomingMessages(req IncomingMessageListEntity) string {
	msgs := req.Messages
	if len(msgs) > maxMessagesPerRequest {
		return "too many messages in request"
	}
	if req.Timestamp > uint64(maxMessageTimestamp) {
		return "message timestamp out of range"
	}
	seen := make(map[uint64]struct{}, len(msgs))
	for _, msg := range msgs {
		if msg.Content == "" {
			return "message content must not be empty"
		}
		if _, ok := validEnvelopeTypes[messages.EnvelopeType(msg.Type)]; !ok {
			return "invalid envelope type"
		}
		deviceID := msg.DestinationDeviceId
		if deviceID == 0 {
			deviceID = accounts.PrimaryDeviceID
		}
		if _, dup := seen[deviceID]; dup {
			return "duplicate destination device ID"
		}
		seen[deviceID] = struct{}{}
	}
	return ""
}

// handleSendMessage processes PUT /v1/messages/{destination} and stores
// message envelopes for delivery to the destination account's devices.
// The device set addressed by the sender is validated against the recipient's
// actual enabled devices before any envelopes are stored:
//   - 401 Unauthorized: neither valid Basic auth nor a valid UAK was provided.
//   - 403 Forbidden:    spam checker blocked the message, or the destination
//     account does not allow unidentified access.
//   - 428 Precondition Required: spam checker requires a challenge.
//   - 409 Conflict:   mismatched devices (sender addressed wrong device set).
//   - 410 Gone:       stale devices (sender holds outdated registration IDs).
//
// When the request is authenticated via the Unidentified-Access-Key header
// (sealed sender), the envelope type is forced to
// EnvelopeTypeUnidentifiedSender (6) and the source UUID is left empty to
// preserve sender anonymity. The request must have been pre-authorised by
// optionalAuthMiddleware.
func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	unidentified := isUnidentifiedSender(ctx)

	acct := accountFromContext(ctx)
	if acct == nil && !unidentified {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	destination := r.PathValue("destination")
	if destination == "" {
		writeError(w, http.StatusBadRequest, "missing destination")
		return
	}
	if destination = parseUUID(w, destination, "destination"); destination == "" {
		return
	}

	var req IncomingMessageListEntity
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode send message request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if errMsg := validateIncomingMessages(req); errMsg != "" {
		writeError(w, http.StatusBadRequest, errMsg)
		return
	}

	destAcct, err := s.resolveAccount(r, destination)
	if err != nil {
		writeError(w, http.StatusNotFound, "destination account not found")
		return
	}

	// For sealed-sender requests, the destination account must allow
	// unidentified access. An account with no UAK set or with
	// UnrestrictedUnidentifiedAccess == false and an empty UAK rejects sealed
	// sender delivery to protect user privacy.
	if unidentified && len(destAcct.UnidentifiedAccessKey) == 0 {
		writeError(w, http.StatusForbidden, "destination does not allow unidentified access")
		return
	}

	// Spam check — performed before device validation and message storage to
	// short-circuit blocked or challenged senders as early as possible.
	// For unidentified (sealed-sender) messages the sender UUID is empty.
	senderUUID := ""
	var sourceDevice uint32
	if acct != nil {
		senderUUID = acct.UUID
		// Attribute the envelope to the device that actually authenticated.
		// Sealed-sender (unidentified) envelopes keep SourceDevice at 0 to
		// preserve sender anonymity.
		sourceDevice = uint32(deviceIDFromContext(r.Context()))
	}
	msgType := 0
	if len(req.Messages) > 0 {
		msgType = int(req.Messages[0].Type)
	}
	checkCtx := &spam.CheckContext{
		SenderUUID:    senderUUID,
		RecipientUUID: destAcct.UUID,
		SenderIP:      r.RemoteAddr,
		UserAgent:     r.Header.Get("User-Agent"),
		MessageType:   msgType,
		Timestamp:     time.Now(),
	}
	spamResult, spamErr := s.spamChecker.Check(ctx, checkCtx)
	if spamErr != nil {
		s.logger.Error("spam checker error", slog.String("error", spamErr.Error()))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	spamActions := map[spam.SpamCheckResult]func(){
		spam.SpamCheckBlock: func() {
			writeError(w, http.StatusForbidden, "message blocked")
		},
		spam.SpamCheckChallenge: func() {
			writeJSON(w, http.StatusPreconditionRequired, SpamChallengeResponse{
				Token:         "",
				ChallengeType: "captcha",
			})
		},
	}
	if action, ok := spamActions[spamResult]; ok {
		action()
		return
	}

	// Build the device-message list used for both validation passes. A
	// DestinationDeviceId of 0 is normalised to PrimaryDeviceID here so that
	// validation sees the canonical device ID.
	deviceMsgs := make([]messages.DeviceMessage, len(req.Messages))
	for i, msg := range req.Messages {
		deviceID := msg.DestinationDeviceId
		if deviceID == 0 {
			deviceID = accounts.PrimaryDeviceID
		}
		deviceMsgs[i] = messages.DeviceMessage{
			DestinationDeviceID: deviceID,
			RegistrationID:      msg.RegistrationId,
		}
	}

	// Pass 1 – device-set validation (HTTP 409 on mismatch).
	if err := messages.ValidateDeviceSet(destAcct, deviceMsgs); err != nil {
		var mismatch *signalerrors.MismatchedDevicesError
		if errors.As(err, &mismatch) {
			writeJSON(w, http.StatusConflict, MismatchedDevicesResponse{
				MissingDevices: nilToEmpty(mismatch.MissingDevices),
				ExtraDevices:   nilToEmpty(mismatch.ExtraDevices),
			})
			return
		}
		s.logger.Error("unexpected error during device-set validation", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Pass 2 – registration-ID validation (HTTP 410 on stale).
	if err := messages.ValidateRegistrationIDs(destAcct, deviceMsgs); err != nil {
		var stale *signalerrors.StaleDevicesError
		if errors.As(err, &stale) {
			writeJSON(w, http.StatusGone, StaleDevicesResponse{
				StaleDevices: nilToEmpty(stale.StaleDevices),
			})
			return
		}
		s.logger.Error("unexpected error during registration-ID validation", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	for i, msg := range req.Messages {
		content, err := decodeBase64(msg.Content)
		if err != nil {
			s.logger.Error("failed to decode message content", slog.String("error", err.Error()))
			writeError(w, http.StatusBadRequest, "invalid message content encoding")
			return
		}

		deviceID := deviceMsgs[i].DestinationDeviceID

		// Sealed-sender envelopes always use EnvelopeTypeUnidentifiedSender
		// and carry no source UUID to preserve sender anonymity. Authenticated
		// senders use the type supplied by the client.
		envelopeType := messages.EnvelopeType(msg.Type)
		if unidentified {
			envelopeType = messages.EnvelopeTypeUnidentifiedSender
		}

		// Pre-assign the ServerGUID so the loop detector can Check the same
		// GUID it will later Record. The manager preserves caller-supplied
		// GUIDs (it only mints a fresh one when ServerGUID is empty).
		serverGUID := uuid.New().String()

		envelope := &messages.Envelope{
			Type:              envelopeType,
			SourceUUID:        senderUUID,
			SourceDevice:      sourceDevice,
			DestinationUUID:   destAcct.UUID,
			DestinationDevice: deviceID,
			// The LIST timestamp, not a per-message one. libsignal
			// cross-checks this against the timestamp sealed inside the
			// content and rejects a mismatch with
			// InvalidMessageStructureException, so sourcing it from a field
			// clients do not populate delivers an envelope no client will
			// accept. handlers_messages_multi.go does the same.
			Timestamp:  req.Timestamp,
			Content:    content,
			Urgent:     req.Urgent,
			ServerGUID: serverGUID,
		}

		// Delivery loop detection: trips when the recipient already sent the
		// current sender a message carrying the same ServerGUID inside the
		// detector window. Only meaningful for authenticated senders since
		// sealed-sender paths conceal the sender identity.
		if s.loopDetector != nil && !unidentified && senderUUID != "" {
			if err := s.loopDetector.Check(ctx, senderUUID, destAcct.UUID, serverGUID); err != nil {
				var loopErr *messages.DeliveryLoopError
				if errors.As(err, &loopErr) {
					s.logger.Warn("delivery loop detected",
						slog.String("sender", senderUUID),
						slog.String("recipient", destAcct.UUID),
						slog.String("serverGuid", serverGUID),
					)
					writeError(w, http.StatusLoopDetected, "delivery loop detected")
					return
				}
			}
		}

		if err := s.messages.Insert(ctx, destAcct.UUID, deviceID, envelope); err != nil {
			s.logger.Error("failed to insert message",
				slog.String("destination", destAcct.UUID),
				slog.Uint64("deviceId", deviceID),
				slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "failed to store message")
			return
		}

		// Record the successful delivery path for future loop detection.
		if s.loopDetector != nil && !unidentified && senderUUID != "" {
			s.loopDetector.Record(ctx, senderUUID, destAcct.UUID, envelope.ServerGUID)
		}
	}

	// Indicate sync is needed if the authenticated sender has multiple
	// devices. Unidentified senders are anonymous so no sync is needed.
	needsSync := acct != nil && len(acct.Devices) > 1
	writeJSON(w, http.StatusOK, SendMessageResponseEntity{NeedsSync: needsSync})
}

// handleGetMessages processes GET /v1/messages and returns all pending
// messages for the authenticated user's primary device.
func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	envelopes, err := s.messages.GetMessagesForDevice(r.Context(), acct.UUID, deviceIDFromContext(r.Context()))
	if err != nil {
		s.logger.Error("failed to get messages",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to get messages")
		return
	}

	outgoing := make([]OutgoingMessageEntity, 0, len(envelopes))
	for _, env := range envelopes {
		outgoing = append(outgoing, OutgoingMessageEntity{
			Type:            int32(env.Type),
			Timestamp:       env.Timestamp,
			Source:          env.SourceUUID,
			SourceDevice:    env.SourceDevice,
			Content:         base64.StdEncoding.EncodeToString(env.Content),
			ServerTimestamp: env.ServerTimestamp,
			GUID:            env.ServerGUID,
			Urgent:          env.Urgent,
		})
	}

	writeJSON(w, http.StatusOK, OutgoingMessageEntityList{
		Messages: outgoing,
		More:     false,
	})
}

// handleDeleteMessage processes DELETE /v1/messages/uuid/{guid} and removes
// the specified message from the authenticated user's pending queue.
func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	guid := r.PathValue("guid")
	if guid == "" {
		writeError(w, http.StatusBadRequest, "missing message guid")
		return
	}
	if guid = parseUUID(w, guid, "guid"); guid == "" {
		return
	}

	if err := s.messages.Delete(r.Context(), acct.UUID, guid); err != nil {
		s.logger.Error("failed to delete message",
			slog.String("uuid", acct.UUID),
			slog.String("guid", guid),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to delete message")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// nilToEmpty returns an empty non-nil slice when s is nil. This ensures JSON
// serialisation produces [] rather than null for device ID lists in 409/410
// responses, matching the Java Signal-Server behaviour.
func nilToEmpty(s []uint64) []uint64 {
	if s == nil {
		return []uint64{}
	}
	return s
}
