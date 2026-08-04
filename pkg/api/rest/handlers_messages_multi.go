package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/spam"
)

// mrmContentType is the HTTP request Content-Type used by clients sending a
// SealedSender v2 multi-recipient ciphertext directly to the server. Java
// Signal-Server uses this same media type.
const mrmContentType = "application/vnd.signal-messenger.mrm"

// maxMRMRequestBytes caps the size of a binary multi-recipient request body
// so a single send cannot exhaust server memory. The figure mirrors Java's
// `MaxRecipients * AverageRecipientSize` budget order-of-magnitude (~10 MiB
// of ciphertext is enough for thousands of recipients with typical payloads).
const maxMRMRequestBytes = 10 * 1024 * 1024

// maxMultiRecipients is the maximum number of recipients allowed in a single
// multi-recipient message request. Matches the Java Signal-Server limit.
const maxMultiRecipients = 5000

// handleSendMultiRecipientMessage processes PUT /v1/messages/multi_recipient
// and delivers a sealed-sender message to multiple recipients. For each
// recipient, individual message envelopes are created and stored after
// device-set and stale-device validation:
//   - Recipients whose accounts cannot be found are returned in uuids404.
//   - 409 Conflict: a recipient's device set does not match the addressed IDs.
//   - 410 Gone:     a recipient has stale registration IDs in the request.
func (s *Server) handleSendMultiRecipientMessage(w http.ResponseWriter, r *http.Request) {
	// Java Signal-Server distinguishes legacy JSON multi-recipient sends
	// from the optimized binary path by Content-Type. The binary path
	// uploads the SealedSender v2 multi-recipient ciphertext once and the
	// server fans out per-recipient envelopes referencing a shared MRM
	// cache row; the JSON path delivers per-recipient pre-encrypted bodies.
	if isMRMContentType(r.Header.Get("Content-Type")) {
		s.handleSendMultiRecipientMessageBinary(w, r)
		return
	}

	acct := accountFromContext(r.Context())
	// For sealed-sender (unidentified) multi-recipient messages, the sender
	// is anonymous — no account is in the context. Both authenticated and
	// unidentified paths are valid.
	if acct == nil && !isUnidentifiedSender(r.Context()) {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Spam check for authenticated senders.
	if acct != nil && s.spamChecker != nil {
		checkCtx := &spam.CheckContext{SenderUUID: acct.UUID}
		result, spamErr := s.spamChecker.Check(r.Context(), checkCtx)
		if spamErr != nil {
			s.logger.Error("spam checker error", slog.String("error", spamErr.Error()))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if result == spam.SpamCheckBlock {
			writeError(w, http.StatusForbidden, "message blocked")
			return
		}
	}

	var req MultiRecipientMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode multi-recipient message request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Reject oversized recipient lists before any processing.
	if len(req.Recipients) > maxMultiRecipients {
		writeError(w, http.StatusBadRequest, "too many recipients")
		return
	}

	// Validate recipient UUIDs before any per-recipient processing.
	for _, rec := range req.Recipients {
		if _, err := uuid.Parse(rec.UUID); err != nil {
			writeError(w, http.StatusBadRequest, "invalid recipient UUID")
			return
		}
	}

	// Validate the shared envelope timestamp.
	if req.Timestamp > uint64(maxMessageTimestamp) {
		writeError(w, http.StatusBadRequest, "message timestamp out of range")
		return
	}

	payload, err := decodeBase64(req.CommonPayload)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid commonPayload encoding")
		return
	}

	// For sealed-sender (unidentified) requests the source UUID must be
	// cleared on all envelopes to preserve sender anonymity. The multi-recipient
	// endpoint is always treated as sealed-sender (UNIDENTIFIED_SENDER type 6),
	// so we never propagate the authenticated sender's UUID to recipients.
	var sourceUUID string
	var sourceDevice uint32
	if acct != nil {
		sourceUUID = acct.UUID
		sourceDevice = uint32(deviceIDFromContext(r.Context()))
	}
	if isUnidentifiedSender(r.Context()) {
		// Sealed sender: clear both the source UUID and device to preserve
		// the sender's anonymity in the unsealed envelope fields.
		sourceUUID = ""
		sourceDevice = 0
	}

	uuids404 := make([]string, 0)

	for _, recipient := range req.Recipients {
		destAcct, err := s.accounts.Get(r.Context(), recipient.UUID)
		if err != nil {
			s.logger.Warn("multi-recipient: recipient not found",
				slog.String("uuid", recipient.UUID),
				slog.String("error", err.Error()))
			uuids404 = append(uuids404, recipient.UUID)
			continue
		}

		// Build DeviceMessage list pairing each device ID with its registration
		// ID. The RegistrationIds slice is positionally aligned with DeviceIds
		// per the Signal protocol; if the lists have different lengths we only
		// pair entries that exist in both.
		deviceMsgs := buildDeviceMessages(recipient.DeviceIds, recipient.RegistrationIds)

		// Device-set validation (HTTP 409).
		if err := messages.ValidateDeviceSet(destAcct, deviceMsgs); err != nil {
			var mismatch *signalerrors.MismatchedDevicesError
			if errors.As(err, &mismatch) {
				writeJSON(w, http.StatusConflict, MismatchedDevicesResponse{
					MissingDevices: nilToEmpty(mismatch.MissingDevices),
					ExtraDevices:   nilToEmpty(mismatch.ExtraDevices),
				})
				return
			}
			s.logger.Error("unexpected error during device-set validation",
				slog.String("uuid", recipient.UUID),
				slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// Registration-ID validation (HTTP 410).
		if err := messages.ValidateRegistrationIDs(destAcct, deviceMsgs); err != nil {
			var stale *signalerrors.StaleDevicesError
			if errors.As(err, &stale) {
				writeJSON(w, http.StatusGone, StaleDevicesResponse{
					StaleDevices: nilToEmpty(stale.StaleDevices),
				})
				return
			}
			s.logger.Error("unexpected error during registration-ID validation",
				slog.String("uuid", recipient.UUID),
				slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		for _, deviceID := range recipient.DeviceIds {
			envelope := &messages.Envelope{
				Type:              messages.EnvelopeType(6), // UNIDENTIFIED_SENDER
				SourceUUID:        sourceUUID,
				SourceDevice:      sourceDevice,
				DestinationUUID:   destAcct.UUID,
				DestinationDevice: deviceID,
				Timestamp:         req.Timestamp,
				Content:           payload,
				Urgent:            true,
			}

			if err := s.messages.Insert(r.Context(), destAcct.UUID, deviceID, envelope); err != nil {
				s.logger.Error("failed to insert multi-recipient message",
					slog.String("destination", destAcct.UUID),
					slog.Uint64("deviceId", deviceID),
					slog.String("error", err.Error()))
				writeError(w, http.StatusInternalServerError, "failed to store message")
				return
			}
		}
	}

	writeJSON(w, http.StatusOK, MultiRecipientMessageResponse{
		UUIDs404: uuids404,
	})
}

// handleReportSpam processes POST /v1/messages/report/{source}/{messageGuid}
// and records a spam report for the specified message. The report is logged and,
// when a ReportStore is configured, persisted for downstream abuse-detection
// processing.
func (s *Server) handleReportSpam(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	source := parseUUID(w, r.PathValue("source"), "source")
	if source == "" {
		return
	}
	messageGuid := parseUUID(w, r.PathValue("messageGuid"), "messageGuid")
	if messageGuid == "" {
		return
	}

	s.logger.Info("spam report received",
		slog.String("reporter", acct.UUID),
		slog.String("source", source),
		slog.String("messageGuid", messageGuid),
	)

	if s.reportStore != nil {
		report := &messages.SpamReport{
			ReporterUUID: acct.UUID,
			SourceUUID:   source,
			MessageGUID:  messageGuid,
			Timestamp:    time.Now().UTC(),
		}
		if err := s.reportStore.Store(r.Context(), report); err != nil {
			s.logger.Error("failed to store spam report",
				slog.String("reporter", acct.UUID),
				slog.String("source", source),
				slog.String("messageGuid", messageGuid),
				slog.String("error", err.Error()),
			)
			writeError(w, http.StatusInternalServerError, "failed to store spam report")
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

// buildDeviceMessages creates a []messages.DeviceMessage from parallel slices
// of device IDs and registration IDs. Entries beyond the shorter slice length
// are included with RegistrationID 0 (skipped in stale-device validation).
func buildDeviceMessages(deviceIDs []uint64, registrationIDs []uint32) []messages.DeviceMessage {
	result := make([]messages.DeviceMessage, len(deviceIDs))
	for i, id := range deviceIDs {
		var regID uint32
		if i < len(registrationIDs) {
			regID = registrationIDs[i]
		}
		result[i] = messages.DeviceMessage{
			DestinationDeviceID: id,
			RegistrationID:      regID,
		}
	}
	return result
}

// isMRMContentType reports whether the supplied Content-Type header value
// matches the binary multi-recipient media type (with optional parameters
// such as ;charset=...).
func isMRMContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), mrmContentType)
}

// handleSendMultiRecipientMessageBinary processes a binary SealedSender v2
// multi-recipient send. The request body is the raw SSv2 multi-recipient
// ciphertext; the server parses it, stores the shared payload in the MRM
// cache once, and enqueues a per-recipient envelope referencing the cached
// payload via MessagesManager.SendMRMBinary. Always treated as sealed-sender
// (UNIDENTIFIED_SENDER), so the route is anonymous. Mirrors Java Signal-
// Server's binary multi-recipient endpoint.
func (s *Server) handleSendMultiRecipientMessageBinary(w http.ResponseWriter, r *http.Request) {
	if s.mrmCache == nil {
		writeError(w, http.StatusServiceUnavailable, "mrm cache not configured")
		return
	}

	// The binary endpoint expects the timestamp in a header (mirroring Java).
	tsHeader := r.Header.Get("X-Signal-Timestamp")
	if tsHeader == "" {
		writeError(w, http.StatusBadRequest, "missing X-Signal-Timestamp header")
		return
	}
	timestamp, err := parseUnsignedTimestamp(tsHeader)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid X-Signal-Timestamp header")
		return
	}
	if timestamp > uint64(maxMessageTimestamp) {
		writeError(w, http.StatusBadRequest, "message timestamp out of range")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxMRMRequestBytes)+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if len(body) > maxMRMRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	result, err := s.messages.SendMRMBinary(r.Context(), messages.MRMSendRequest{
		Body:      body,
		Timestamp: timestamp,
		Lookup: func(ctx context.Context, uuidStr string) (*messages.MRMRecipientAccount, error) {
			acct, lookupErr := s.accounts.Get(ctx, uuidStr)
			if lookupErr != nil {
				return nil, lookupErr
			}
			return &messages.MRMRecipientAccount{UUID: acct.UUID}, nil
		},
	})
	if err != nil {
		switch {
		case errors.Is(err, messages.ErrMRMNoRecipients):
			writeError(w, http.StatusBadRequest, "no recipients in ciphertext")
		case errors.Is(err, messages.ErrMRMNoCache):
			writeError(w, http.StatusServiceUnavailable, "mrm cache not configured")
		default:
			s.logger.Warn("mrm: send failed", slog.String("error", err.Error()))
			// Parse failures and oversize-recipient lists are client errors.
			// Storage failures are server errors. Treat anything we can't
			// disambiguate as a 500 to keep semantics conservative.
			if strings.Contains(err.Error(), "parse ciphertext") {
				writeError(w, http.StatusBadRequest, "invalid multi-recipient ciphertext")
			} else if strings.Contains(err.Error(), "invalid recipient service id") {
				writeError(w, http.StatusBadRequest, "invalid recipient service id")
			} else {
				writeError(w, http.StatusInternalServerError, "mrm send failed")
			}
		}
		return
	}

	writeJSON(w, http.StatusOK, MultiRecipientMessageResponse{UUIDs404: result.UUIDs404})
}

// invalidTimestampError indicates a malformed or out-of-range unsigned
// timestamp header value.
type invalidTimestampError struct{ reason string }

func (e *invalidTimestampError) Error() string { return "invalid timestamp: " + e.reason }

// parseUnsignedTimestamp parses a positive integer timestamp from a string.
// It rejects empty input, signs, non-digit characters, and — unlike a manual
// digit accumulator — values that overflow uint64 (strconv reports ErrRange),
// so an all-digit header cannot silently wrap to a small in-range value.
func parseUnsignedTimestamp(s string) (uint64, error) {
	if s == "" {
		return 0, &invalidTimestampError{reason: "empty"}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &invalidTimestampError{reason: err.Error()}
	}
	return n, nil
}
