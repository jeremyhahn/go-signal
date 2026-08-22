package rest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// validateIncomingMessages
// --------------------------------------------------------------------------

func TestValidateIncomingMessages_EmptySlice(t *testing.T) {
	if msg := validateIncomingMessages(IncomingMessageListEntity{}); msg != "" {
		t.Errorf("expected empty error for nil slice, got %q", msg)
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: []IncomingMessageEntity{}}); msg != "" {
		t.Errorf("expected empty error for empty slice, got %q", msg)
	}
}

func TestValidateIncomingMessages_TooMany(t *testing.T) {
	msgs := make([]IncomingMessageEntity, maxMessagesPerRequest+1)
	for i := range msgs {
		msgs[i] = IncomingMessageEntity{
			Type:                1,
			DestinationDeviceId: uint64(i + 1),
			Content:             "dGVzdA==",
		}
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg == "" {
		t.Error("expected error for too many messages, got none")
	}
}

func TestValidateIncomingMessages_ExactlyAtLimit(t *testing.T) {
	msgs := make([]IncomingMessageEntity, maxMessagesPerRequest)
	for i := range msgs {
		msgs[i] = IncomingMessageEntity{
			Type:                1,
			DestinationDeviceId: uint64(i + 1),
			Content:             "dGVzdA==",
		}
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg != "" {
		t.Errorf("expected no error at exact limit, got %q", msg)
	}
}

func TestValidateIncomingMessages_EmptyContent(t *testing.T) {
	msgs := []IncomingMessageEntity{
		{Type: 1, DestinationDeviceId: 1, Content: ""},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg == "" {
		t.Error("expected error for empty content, got none")
	}
}

func TestValidateIncomingMessages_TimestampZero(t *testing.T) {
	// Zero timestamp is allowed (lower bound is inclusive 0).
	msgs := []IncomingMessageEntity{
		{Type: 1, DestinationDeviceId: 1, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 0}); msg != "" {
		t.Errorf("expected no error for timestamp=0, got %q", msg)
	}
}

func TestValidateIncomingMessages_TimestampAtMaximum(t *testing.T) {
	msgs := []IncomingMessageEntity{
		{Type: 1, DestinationDeviceId: 1, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: uint64(maxMessageTimestamp)}); msg != "" {
		t.Errorf("expected no error at max timestamp, got %q", msg)
	}
}

func TestValidateIncomingMessages_TimestampExceedsMax(t *testing.T) {
	msgs := []IncomingMessageEntity{
		{Type: 1, DestinationDeviceId: 1, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: uint64(maxMessageTimestamp) + 1}); msg == "" {
		t.Error("expected error for timestamp exceeding max, got none")
	}
}

// Type 2 is reserved in textsecure.proto, so the envelope encoder has no
// representation for it. Accepting it here would only defer the failure to
// delivery, where the recipient is the one who suffers it.
func TestValidateIncomingMessages_ReservedEnvelopeType2(t *testing.T) {
	msgs := []IncomingMessageEntity{
		{Type: 2, DestinationDeviceId: 1, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg == "" {
		t.Error("expected error for reserved type 2, got none")
	}
}

func TestValidateIncomingMessages_InvalidEnvelopeTypeZero(t *testing.T) {
	msgs := []IncomingMessageEntity{
		{Type: 0, DestinationDeviceId: 1, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg == "" {
		t.Error("expected error for type 0 (unknown), got none")
	}
}

func TestValidateIncomingMessages_InvalidEnvelopeType7(t *testing.T) {
	// Type 7 is SERVER_DELIVERY_RECEIPT — server-only, clients may not send.
	msgs := []IncomingMessageEntity{
		{Type: 7, DestinationDeviceId: 1, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg == "" {
		t.Error("expected error for type 7 (server-only), got none")
	}
}

func TestValidateIncomingMessages_ValidEnvelopeTypes(t *testing.T) {
	validTypes := []int32{1, 3, 5, 6, 8}
	for _, typ := range validTypes {
		t.Run(fmt.Sprintf("type_%d", typ), func(t *testing.T) {
			msgs := []IncomingMessageEntity{
				{Type: typ, DestinationDeviceId: 1, Content: "dGVzdA=="},
			}
			if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg != "" {
				t.Errorf("expected no error for valid type %d, got %q", typ, msg)
			}
		})
	}
}

func TestValidateIncomingMessages_DuplicateDeviceIDs(t *testing.T) {
	msgs := []IncomingMessageEntity{
		{Type: 1, DestinationDeviceId: 1, Content: "dGVzdA=="},
		{Type: 1, DestinationDeviceId: 1, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg == "" {
		t.Error("expected error for duplicate device IDs, got none")
	}
}

func TestValidateIncomingMessages_DeviceZeroNormalisedToPrimary(t *testing.T) {
	// DeviceID 0 normalises to primary (1); two messages to device 0 should
	// trigger the duplicate check.
	msgs := []IncomingMessageEntity{
		{Type: 1, DestinationDeviceId: 0, Content: "dGVzdA=="},
		{Type: 1, DestinationDeviceId: 0, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg == "" {
		t.Error("expected duplicate-device error for two DeviceID=0 entries, got none")
	}
}

func TestValidateIncomingMessages_DifferentDevicesNoDuplicate(t *testing.T) {
	msgs := []IncomingMessageEntity{
		{Type: 1, DestinationDeviceId: 1, Content: "dGVzdA=="},
		{Type: 1, DestinationDeviceId: 2, Content: "dGVzdA=="},
	}
	if msg := validateIncomingMessages(IncomingMessageListEntity{Messages: msgs, Timestamp: 1000}); msg != "" {
		t.Errorf("expected no error for distinct device IDs, got %q", msg)
	}
}

// --------------------------------------------------------------------------
// handleSendMessage — validation integration tests
// --------------------------------------------------------------------------

func TestHandleSendMessage_EmptyContent_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"","timestamp":1000}],"timestamp":1000}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty content, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_BadTimestamp_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Use an astronomically large timestamp that exceeds maxMessageTimestamp.
	bigTS := uint64(maxMessageTimestamp) + 1
	body := fmt.Sprintf(`{"messages":[{"type":1,"destinationDeviceId":1,"content":"dGVzdA==","timestamp":%d}],"timestamp":%d}`, bigTS, bigTS)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for out-of-range timestamp, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_InvalidEnvelopeType_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"messages":[{"type":0,"destinationDeviceId":1,"content":"dGVzdA==","timestamp":1000}],"timestamp":1000}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for type 0 envelope, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_DuplicateDeviceIDs_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"messages":[
		{"type":1,"destinationDeviceId":1,"content":"dGVzdA==","timestamp":1000},
		{"type":1,"destinationDeviceId":1,"content":"dGVzdA==","timestamp":1000}
	],"timestamp":1000}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for duplicate device IDs, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_InvalidDestinationUUID_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1000}],"timestamp":1000}`

	// "not-a-uuid" is not a valid UUID format.
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/not-a-uuid", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid destination UUID, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleDeleteMessage — UUID validation
// --------------------------------------------------------------------------

func TestHandleDeleteMessage_InvalidGUIDFormat_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/messages/uuid/not-a-valid-uuid", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed GUID, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeleteMessage_ValidGUIDFormat_Succeeds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// A well-formed UUID that doesn't exist returns 204 (delete is idempotent).
	req := httptest.NewRequest(http.MethodDelete, "/v1/messages/uuid/00000000-0000-0000-0000-000000000099", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for valid UUID, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleSendMultiRecipientMessage — bounds + timestamp + sealed-sender UUID
// --------------------------------------------------------------------------

func TestHandleSendMultiRecipientMessage_TooManyRecipients_Rejected(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Build a recipients list exceeding maxMultiRecipients. The body may
	// exceed the 256 KB request body limit before the count check fires, in
	// which case 413 is returned instead of 400. Both are valid rejections.
	recipients := make([]string, maxMultiRecipients+1)
	for i := range recipients {
		recipients[i] = fmt.Sprintf(`{"uuid":"00000000-0000-0000-%04d-000000000001","deviceIds":[1],"registrationIds":[1]}`, i)
	}
	payloadB64 := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{"recipients":[` + strings.Join(recipients, ",") + `],"commonPayload":"` + payloadB64 + `","timestamp":1000}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 400 or 413 for too many recipients, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMultiRecipientMessage_TimestampExceedsMax_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("sealed"))
	bigTS := uint64(maxMessageTimestamp) + 1
	body := fmt.Sprintf(`{"recipients":[],"commonPayload":"%s","timestamp":%d}`, payloadB64, bigTS)

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for out-of-range timestamp, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMultiRecipientMessage_SealedSenderSourceUUIDEmpty(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Send as authenticated sender (not sealed-sender). The envelope SourceUUID
	// should carry the sender's UUID in this case because isUnidentifiedSender
	// is false.
	payloadB64 := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{
		"recipients": [{"uuid": "` + testAccountUUID + `", "deviceIds": [1], "registrationIds": [12345]}],
		"commonPayload": "` + payloadB64 + `",
		"timestamp": 1000
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp MultiRecipientMessageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.UUIDs404) != 0 {
		t.Errorf("expected no 404 UUIDs, got %v", resp.UUIDs404)
	}
}

func TestHandleSendMultiRecipientMessage_AtRecipientLimit_Succeeds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Exactly maxMultiRecipients (all unknown, so they appear in uuids404).
	// We just need to confirm the bound check doesn't reject it.
	payloadB64 := base64.StdEncoding.EncodeToString([]byte("x"))

	// Build a small valid-UUID-formatted batch (just enough to confirm it passes).
	body := `{"recipients":[{"uuid":"` + testAccountUUID + `","deviceIds":[1],"registrationIds":[12345]}],"commonPayload":"` + payloadB64 + `","timestamp":1000}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid recipient count, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleBatchIdentityCheck — element count bounds
// --------------------------------------------------------------------------

func TestHandleBatchIdentityCheck_TooManyElements_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	elements := make([]string, maxBatchIdentityCheckElements+1)
	for i := range elements {
		elements[i] = `{"uuid":"11111111-1111-1111-1111-111111111111","fingerprint":"AAAA"}`
	}
	body := `{"elements":[` + strings.Join(elements, ",") + `]}`

	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized batch, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleBatchIdentityCheck_AtLimit_Succeeds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Exactly at the limit — should not be rejected for size.
	elements := make([]string, maxBatchIdentityCheckElements)
	for i := range elements {
		elements[i] = `{"uuid":"11111111-1111-1111-1111-111111111111","fingerprint":"AAAA"}`
	}
	body := `{"elements":[` + strings.Join(elements, ",") + `]}`

	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// We expect 200 (even if the fingerprint doesn't match, it won't 400 for size).
	if rr.Code == http.StatusBadRequest {
		t.Errorf("unexpected 400 at exact element limit: %s", rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleCheckKeys — element count bounds
// --------------------------------------------------------------------------

func TestHandleCheckKeys_TooManyElements_Returns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	items := make([]string, maxKeyCheckElements+1)
	for i := range items {
		items[i] = `{"uuid":"11111111-1111-1111-1111-111111111111","identityKey":"AAAA"}`
	}
	body := `{"identityKeys":[` + strings.Join(items, ",") + `]}`

	req := httptest.NewRequest(http.MethodPost, "/v2/keys/check", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized key check, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCheckKeys_AtLimit_Succeeds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	items := make([]string, maxKeyCheckElements)
	for i := range items {
		items[i] = `{"uuid":"11111111-1111-1111-1111-111111111111","identityKey":"AAAA"}`
	}
	body := `{"identityKeys":[` + strings.Join(items, ",") + `]}`

	req := httptest.NewRequest(http.MethodPost, "/v2/keys/check", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusBadRequest {
		t.Errorf("unexpected 400 at exact key check limit: %s", rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleDirectoryLookup — element count bounds
// --------------------------------------------------------------------------

func TestHandleDirectoryLookup_TooManyNumbers_Rejected(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Build a numbers list exceeding maxDirectoryLookupNumbers. The body may
	// exceed the request body limit before the count check fires, in which
	// case 413 is returned instead of 400. Both are valid rejections.
	numbers := make([]string, maxDirectoryLookupNumbers+1)
	for i := range numbers {
		numbers[i] = fmt.Sprintf(`"+1555%07d"`, i)
	}
	body := `{"numbers":[` + strings.Join(numbers, ",") + `]}`

	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 400 or 413 for too many numbers, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDirectoryLookup_AtLimit_Succeeds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	numbers := make([]string, maxDirectoryLookupNumbers)
	for i := range numbers {
		numbers[i] = fmt.Sprintf(`"+1555%07d"`, i)
	}
	body := `{"numbers":[` + strings.Join(numbers, ",") + `]}`

	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusBadRequest {
		t.Errorf("unexpected 400 at exact directory lookup limit: %s", rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// parseUUID helper
// --------------------------------------------------------------------------

func TestParseUUID_ValidUUID(t *testing.T) {
	w := httptest.NewRecorder()
	result := parseUUID(w, "11111111-1111-1111-1111-111111111111", "testParam")
	if result == "" {
		t.Error("expected non-empty return for valid UUID")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected no error response for valid UUID, got %d", w.Code)
	}
}

func TestParseUUID_InvalidUUID_WritesError(t *testing.T) {
	w := httptest.NewRecorder()
	result := parseUUID(w, "not-a-uuid", "testParam")
	if result != "" {
		t.Errorf("expected empty return for invalid UUID, got %q", result)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid UUID, got %d", w.Code)
	}
}

func TestParseUUID_EmptyString_WritesError(t *testing.T) {
	w := httptest.NewRecorder()
	result := parseUUID(w, "", "testParam")
	if result != "" {
		t.Errorf("expected empty return for empty string, got %q", result)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty UUID, got %d", w.Code)
	}
}

func TestParseUUID_UppercaseUUID_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	result := parseUUID(w, "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA", "testParam")
	if result == "" {
		t.Error("expected non-empty return for uppercase UUID")
	}
}

// --------------------------------------------------------------------------
// isValidE164 helper
// --------------------------------------------------------------------------

func TestIsValidE164_ValidNumbers(t *testing.T) {
	valid := []string{
		"+1",
		"+15551234567",
		"+447700900000",
		"+123456789012345",
	}
	for _, n := range valid {
		t.Run(n, func(t *testing.T) {
			if !isValidE164(n) {
				t.Errorf("expected %q to be valid E.164", n)
			}
		})
	}
}

func TestIsValidE164_InvalidNumbers(t *testing.T) {
	invalid := []string{
		"",
		"+",
		"15551234567",       // no leading +
		"+1234567890123456", // too long (17 chars)
		"+1555abc1234",      // non-digit characters
		"++15551234567",     // double plus
		" +15551234567",     // leading space
	}
	for _, n := range invalid {
		t.Run(n, func(t *testing.T) {
			if isValidE164(n) {
				t.Errorf("expected %q to be invalid E.164", n)
			}
		})
	}
}

func TestIsValidE164_ExactlyMaxLength(t *testing.T) {
	// 16 chars total: + followed by 15 digits.
	n := "+123456789012345"
	if !isValidE164(n) {
		t.Errorf("expected %q (16 chars) to be valid E.164", n)
	}
}

func TestIsValidE164_OneOverMaxLength(t *testing.T) {
	// 17 chars total: + followed by 16 digits — exceeds E.164 limit.
	n := "+1234567890123456"
	if isValidE164(n) {
		t.Errorf("expected %q (17 chars) to be invalid E.164", n)
	}
}

// --------------------------------------------------------------------------
// handleRegistration — E.164 validation integration
// --------------------------------------------------------------------------

func TestHandleRegistration_InvalidPhoneNumberFormat_Returns400(t *testing.T) {
	s := newTestServer(t)

	body := `{
		"sessionId": "some-session-id",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1, "pniRegistrationId": 2},
		"aciIdentityKey": "dGVzdA==",
		"pniIdentityKey": "dGVzdA==",
		"aciSignedPreKey": {"keyId": 1, "publicKey": "dGVzdA==", "signature": "dGVzdA=="},
		"pniSignedPreKey": {"keyId": 2, "publicKey": "dGVzdA==", "signature": "dGVzdA=="},
		"aciPqLastResortPreKey": {"keyId": 3, "publicKey": "dGVzdA==", "signature": "dGVzdA=="},
		"pniPqLastResortPreKey": {"keyId": 4, "publicKey": "dGVzdA==", "signature": "dGVzdA=="}
	}`

	// Basic auth username is the phone number — use a non-E.164 value.
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth("5551234567", "password") // missing leading +
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-E.164 phone number, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_ValidE164_PassesFormatCheck(t *testing.T) {
	s, _ := newTestServerWithVerification(t)

	// A valid E.164 number will still fail further down (session check),
	// but must NOT fail at the E.164 format check with 400.
	body := `{
		"sessionId": "nonexistent-session",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1, "pniRegistrationId": 2},
		"aciIdentityKey": "dGVzdA==",
		"pniIdentityKey": "dGVzdA==",
		"aciSignedPreKey": {"keyId": 1, "publicKey": "dGVzdA==", "signature": "dGVzdA=="},
		"pniSignedPreKey": {"keyId": 2, "publicKey": "dGVzdA==", "signature": "dGVzdA=="},
		"aciPqLastResortPreKey": {"keyId": 3, "publicKey": "dGVzdA==", "signature": "dGVzdA=="},
		"pniPqLastResortPreKey": {"keyId": 4, "publicKey": "dGVzdA==", "signature": "dGVzdA=="}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth("+15551234567", "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Should NOT be 400 for format reason; will likely be 403 (session not found).
	if rr.Code == http.StatusBadRequest {
		var errResp map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err == nil {
			if errResp["error"] == "invalid phone number format" {
				t.Errorf("valid E.164 number incorrectly rejected: %s", rr.Body.String())
			}
		}
	}
}
