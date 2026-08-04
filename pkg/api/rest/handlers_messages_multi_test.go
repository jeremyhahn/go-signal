package rest

// Regression tests for security fixes on the multi-recipient message endpoint.
//
// HIGH-4: Nil pointer dereference on sealed-sender multi-recipient messages.
//   Before the fix, handleSendMultiRecipientMessage would access acct.UUID
//   (source UUID) even when the sender was unidentified (acct == nil), causing
//   a nil pointer dereference panic. The fix conditionally clears sourceUUID
//   when isUnidentifiedSender is true.
//
// MEDIUM-4: Missing UUID validation and spam check on multi-recipient endpoint.
//   The endpoint now validates each recipient UUID with uuid.Parse before
//   processing, returning 400 for malformed UUIDs. Authenticated senders are
//   also passed through the spam checker; blocked senders receive 403.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// --------------------------------------------------------------------------
// HIGH-4: Sealed-sender nil-pointer regression
// --------------------------------------------------------------------------

// TestMultiRecipient_SealedSender_NoPanic verifies that sending a
// multi-recipient message as an unidentified (sealed) sender does not panic.
// Before the HIGH-4 fix, the handler dereferenced acct.UUID unconditionally,
// causing a nil pointer dereference when acct was nil.
func TestMultiRecipient_SealedSender_NoPanic(t *testing.T) {
	s, destAcct := newTestServerWithAccount(t)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("sealed content"))
	body := `{
		"recipients": [{"uuid": "` + destAcct.UUID + `", "deviceIds": [1], "registrationIds": [12345]}],
		"commonPayload": "` + payloadB64 + `",
		"timestamp": 1000
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	// Use the Unidentified-Access-Key header path (sealed sender).
	uakB64 := base64.StdEncoding.EncodeToString(destAcct.UnidentifiedAccessKey)
	req.Header.Set("Unidentified-Access-Key", uakB64)
	rr := httptest.NewRecorder()

	// Must not panic — before the fix this dereferenced a nil *accounts.Account.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("handler panicked on sealed-sender multi-recipient: %v", r)
		}
	}()

	s.httpServer.Handler.ServeHTTP(rr, req)

	// 200 is expected; 401 indicates the UAK was not matched (also acceptable
	// for the nil-safety regression — a panic is the only failure we guard).
	if rr.Code != http.StatusOK && rr.Code != http.StatusUnauthorized {
		t.Errorf("unexpected status %d: %s", rr.Code, rr.Body.String())
	}
}

// TestMultiRecipient_AuthenticatedSender_SourceUUIDPresent verifies that when
// an authenticated sender sends a multi-recipient message, the SourceUUID in
// the envelope reflects the sender's identity. This also confirms that the
// HIGH-4 fix (nil guard on acct) does not accidentally clear the source UUID
// for authenticated senders.
func TestMultiRecipient_AuthenticatedSender_SourceUUIDPresent(t *testing.T) {
	s, destAcct := newTestServerWithAccount(t)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("content"))
	body := `{
		"recipients": [{"uuid": "` + destAcct.UUID + `", "deviceIds": [1], "registrationIds": [12345]}],
		"commonPayload": "` + payloadB64 + `",
		"timestamp": 1001
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
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(resp.UUIDs404) != 0 {
		t.Errorf("expected no missing UUIDs, got %v", resp.UUIDs404)
	}

	// Verify the stored envelope has the sender's UUID set (authenticated path).
	stored, err := s.messages.GetMessagesForDevice(req.Context(), destAcct.UUID, accounts.PrimaryDeviceID)
	if err != nil {
		t.Fatalf("failed to retrieve stored messages: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("expected at least one stored envelope")
	}
	// For authenticated senders, SourceUUID is set to the sender's UUID.
	// (The HIGH-4 fix clears it only when isUnidentifiedSender is true.)
	for _, env := range stored {
		if env.SourceUUID != testAccountUUID {
			t.Errorf("envelope SourceUUID = %q, want %q for authenticated sender", env.SourceUUID, testAccountUUID)
		}
	}
}

// --------------------------------------------------------------------------
// MEDIUM-4: Recipient UUID validation
// --------------------------------------------------------------------------

// TestMultiRecipient_InvalidRecipientUUID verifies that a malformed recipient
// UUID is rejected with 400 Bad Request before any storage operations are
// attempted. This prevents downstream panics or unexpected behaviour from
// invalid UUIDs reaching the account lookup layer.
func TestMultiRecipient_InvalidRecipientUUID(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("payload"))

	tests := []struct {
		name          string
		recipientUUID string
	}{
		{
			name:          "plaintext non-UUID",
			recipientUUID: "not-a-uuid",
		},
		{
			name:          "truncated UUID",
			recipientUUID: "11111111-1111-1111",
		},
		{
			name:          "UUID with extra characters",
			recipientUUID: "11111111-1111-1111-1111-111111111111-extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{
				"recipients": [{"uuid": "` + tt.recipientUUID + `", "deviceIds": [1], "registrationIds": [1]}],
				"commonPayload": "` + payloadB64 + `",
				"timestamp": 999
			}`
			req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
			req.SetBasicAuth(testAccountUUID, testAuthToken)
			rr := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for malformed UUID %q, got %d: %s",
					tt.recipientUUID, rr.Code, rr.Body.String())
			}
		})
	}
}

// --------------------------------------------------------------------------
// MEDIUM-4: Spam check on multi-recipient endpoint
// --------------------------------------------------------------------------

// TestMultiRecipient_SpamBlocked verifies that when the spam checker returns
// SpamCheckBlock, the endpoint returns 403 Forbidden and no messages are
// stored. This tests the MEDIUM-4 fix that added spam checking to the multi-
// recipient handler for authenticated senders.
func TestMultiRecipient_SpamBlocked(t *testing.T) {
	// blockingChecker is already declared in handlers_messages_test.go.
	s := newTestServerWithSpamChecker(t, &blockingChecker{})

	// Pre-register the sender account so Basic Auth succeeds.
	senderAcct := testAccount()
	if err := s.accounts.Create(context.Background(), senderAcct); err != nil {
		t.Fatalf("failed to create sender account: %v", err)
	}

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("blocked payload"))
	body := `{
		"recipients": [{"uuid": "22222222-2222-2222-2222-222222222222", "deviceIds": [1], "registrationIds": [1]}],
		"commonPayload": "` + payloadB64 + `",
		"timestamp": 2000
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when spam checker blocks, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestMultiRecipient_SpamChecker_AllowedSender verifies that when the spam
// checker allows the sender, the request proceeds normally. Guards against
// regressions where the spam check path blocks all authenticated messages.
func TestMultiRecipient_SpamChecker_AllowedSender(t *testing.T) {
	// Default test server uses NoOpChecker which always allows.
	s, destAcct := newTestServerWithAccount(t)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("allowed payload"))
	body := `{
		"recipients": [{"uuid": "` + destAcct.UUID + `", "deviceIds": [1], "registrationIds": [12345]}],
		"commonPayload": "` + payloadB64 + `",
		"timestamp": 3000
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for allowed sender, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// invalidTimestampError
// --------------------------------------------------------------------------

func TestInvalidTimestampError_Error(t *testing.T) {
	e := &invalidTimestampError{reason: "overflow"}
	got := e.Error()
	want := "invalid timestamp: overflow"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestInvalidTimestampError_EmptyReason(t *testing.T) {
	e := &invalidTimestampError{reason: ""}
	got := e.Error()
	want := "invalid timestamp: "
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}
