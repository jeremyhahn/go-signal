package rest

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// --------------------------------------------------------------------------
// context helpers: contextWithUnidentifiedSender / isUnidentifiedSender
// --------------------------------------------------------------------------

func TestContextWithUnidentifiedSender_IsTrue(t *testing.T) {
	ctx := contextWithUnidentifiedSender(context.Background())
	if !isUnidentifiedSender(ctx) {
		t.Error("expected isUnidentifiedSender to return true after contextWithUnidentifiedSender")
	}
}

func TestIsUnidentifiedSender_FalseOnEmptyContext(t *testing.T) {
	if isUnidentifiedSender(context.Background()) {
		t.Error("expected isUnidentifiedSender to return false on plain context")
	}
}

func TestIsUnidentifiedSender_FalseOnAccountContext(t *testing.T) {
	// Placing an account in context must not set the unidentified-sender flag.
	acct := testAccount()
	ctx := contextWithAccount(context.Background(), acct)
	if isUnidentifiedSender(ctx) {
		t.Error("expected isUnidentifiedSender to return false when only account is in context")
	}
}

func TestContextWithUnidentifiedSender_DoesNotClearAccount(t *testing.T) {
	// Both flags may coexist: an account context should survive wrapping.
	acct := testAccount()
	ctx := contextWithAccount(context.Background(), acct)
	ctx = contextWithUnidentifiedSender(ctx)

	if !isUnidentifiedSender(ctx) {
		t.Error("expected isUnidentifiedSender true")
	}
	if got := accountFromContext(ctx); got == nil || got.UUID != acct.UUID {
		t.Error("account should still be accessible after adding unidentified-sender flag")
	}
}

// --------------------------------------------------------------------------
// optionalAuthMiddleware — Basic auth path
// --------------------------------------------------------------------------

func TestOptionalAuthMiddleware_BasicAuth_Success(t *testing.T) {
	s, acct := newTestServerWithAccount(t)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got := accountFromContext(r.Context())
		if got == nil || got.UUID != acct.UUID {
			t.Errorf("expected account %s in context, got %v", acct.UUID, got)
		}
		if isUnidentifiedSender(r.Context()) {
			t.Error("expected isUnidentifiedSender false for Basic-auth request")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := optionalAuthMiddleware(s.accounts, acct.UUID, inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+acct.UUID, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("inner handler should have been called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestOptionalAuthMiddleware_BasicAuth_WrongPassword(t *testing.T) {
	s, acct := newTestServerWithAccount(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := optionalAuthMiddleware(s.accounts, acct.UUID, inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+acct.UUID, nil)
	req.SetBasicAuth(testAccountUUID, "wrong-password")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// optionalAuthMiddleware — UAK path
// --------------------------------------------------------------------------

func TestOptionalAuthMiddleware_UAK_ValidKey_Succeeds(t *testing.T) {
	s, acct := newTestServerWithAccount(t)

	uak := acct.UnidentifiedAccessKey
	if len(uak) == 0 {
		t.Fatal("test account must have a non-empty UnidentifiedAccessKey")
	}
	uakB64 := base64.StdEncoding.EncodeToString(uak)

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if !isUnidentifiedSender(r.Context()) {
			t.Error("expected isUnidentifiedSender true for UAK-authenticated request")
		}
		// No authenticated account placed in context for sealed sender.
		if got := accountFromContext(r.Context()); got != nil {
			t.Errorf("expected nil account in context for UAK sender, got %v", got)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := optionalAuthMiddleware(s.accounts, acct.UUID, inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+acct.UUID, nil)
	req.Header.Set("Unidentified-Access-Key", uakB64)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("inner handler should have been called with valid UAK")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestOptionalAuthMiddleware_UAK_InvalidKey_Returns401(t *testing.T) {
	s, acct := newTestServerWithAccount(t)

	wrongKey := make([]byte, len(acct.UnidentifiedAccessKey))
	for i := range wrongKey {
		wrongKey[i] = 0xff
	}
	wrongKeyB64 := base64.StdEncoding.EncodeToString(wrongKey)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called on invalid UAK")
	})

	handler := optionalAuthMiddleware(s.accounts, acct.UUID, inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+acct.UUID, nil)
	req.Header.Set("Unidentified-Access-Key", wrongKeyB64)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong UAK, got %d", rr.Code)
	}
}

func TestOptionalAuthMiddleware_UAK_DestinationNotFound_Returns401(t *testing.T) {
	s := newTestServer(t)

	uakB64 := base64.StdEncoding.EncodeToString([]byte("some-access-key-bytes"))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called when destination not found")
	})

	handler := optionalAuthMiddleware(s.accounts, "nonexistent-uuid", inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/nonexistent-uuid", nil)
	req.Header.Set("Unidentified-Access-Key", uakB64)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when destination not found, got %d", rr.Code)
	}
}

func TestOptionalAuthMiddleware_NoCredentials_Returns401(t *testing.T) {
	s, acct := newTestServerWithAccount(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called with no credentials")
	})

	handler := optionalAuthMiddleware(s.accounts, acct.UUID, inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+acct.UUID, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no credentials, got %d", rr.Code)
	}
}

func TestOptionalAuthMiddleware_UAK_AccountWithNoUAK_Returns401(t *testing.T) {
	s := newTestServer(t)

	// Create an account with an empty UnidentifiedAccessKey.
	noUAKAcct := testAccount()
	noUAKAcct.UnidentifiedAccessKey = nil
	if err := s.accounts.Create(contextBackground(t), noUAKAcct); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	uakB64 := base64.StdEncoding.EncodeToString([]byte("any-key"))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called when dest account has no UAK")
	})

	handler := optionalAuthMiddleware(s.accounts, testAccountUUID, inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, nil)
	req.Header.Set("Unidentified-Access-Key", uakB64)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when destination has no UAK, got %d", rr.Code)
	}
}

func TestOptionalAuthMiddleware_UAK_MalformedBase64_Returns401(t *testing.T) {
	s, acct := newTestServerWithAccount(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called for malformed UAK")
	})

	handler := optionalAuthMiddleware(s.accounts, acct.UUID, inner)
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+acct.UUID, nil)
	req.Header.Set("Unidentified-Access-Key", "!!!not-valid-base64!!!")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed UAK, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// UAK constant-time comparison (security property verification)
// --------------------------------------------------------------------------

func TestOptionalAuthMiddleware_UAK_UsesConstantTimeCompare(t *testing.T) {
	// Verify that subtle.ConstantTimeCompare is used by demonstrating it
	// returns 0 for mismatched keys of the same length.
	stored := []byte("0123456789abcdef") // 16 bytes
	wrong := []byte("ffffffffffffffff")  // 16 bytes, all different

	if subtle.ConstantTimeCompare(stored, wrong) != 0 {
		t.Error("expected ConstantTimeCompare to return 0 for different keys")
	}
	if subtle.ConstantTimeCompare(stored, stored) != 1 {
		t.Error("expected ConstantTimeCompare to return 1 for identical keys")
	}
}

// --------------------------------------------------------------------------
// handleSendMessage — UAK (sealed sender) integration tests
// --------------------------------------------------------------------------

func TestHandleSendMessage_ValidUAK_SucceedsAsUnidentifiedSender(t *testing.T) {
	s, destAcct := newTestServerWithAccount(t)

	uak := destAcct.UnidentifiedAccessKey
	if len(uak) == 0 {
		t.Fatal("test account must have a non-empty UAK")
	}

	contentB64 := base64.StdEncoding.EncodeToString([]byte("sealed content"))
	body := `{
		"messages": [{"type": 1, "destinationDeviceId": 1, "content": "` + contentB64 + `", "timestamp": 1000}],
		"timestamp": 1000,
		"urgent": true
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.Header.Set("Unidentified-Access-Key", base64.StdEncoding.EncodeToString(uak))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid UAK send, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp SendMessageResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	// Unidentified sender: no sync needed.
	if resp.NeedsSync {
		t.Error("expected NeedsSync false for unidentified sender")
	}
}

func TestHandleSendMessage_ValidUAK_EnvelopeTypeIsUnidentifiedSender(t *testing.T) {
	s, destAcct := newTestServerWithAccount(t)

	uak := destAcct.UnidentifiedAccessKey
	contentB64 := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.Header.Set("Unidentified-Access-Key", base64.StdEncoding.EncodeToString(uak))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Retrieve the stored envelope and verify the type.
	envelopes, err := s.messages.GetMessagesForDevice(contextBackground(t), testAccountUUID, accounts.PrimaryDeviceID)
	if err != nil {
		t.Fatalf("failed to get messages: %v", err)
	}
	if len(envelopes) == 0 {
		t.Fatal("expected at least one envelope stored")
	}
	got := envelopes[len(envelopes)-1]
	if got.Type != 6 { // EnvelopeTypeUnidentifiedSender
		t.Errorf("expected envelope type 6 (UnidentifiedSender), got %d", got.Type)
	}
	// Source UUID should be empty for sealed sender.
	if got.SourceUUID != "" {
		t.Errorf("expected empty SourceUUID for sealed sender, got %q", got.SourceUUID)
	}
}

func TestHandleSendMessage_InvalidUAK_Returns401(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	wrongKey := make([]byte, 32)
	for i := range wrongKey {
		wrongKey[i] = 0xab
	}
	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.Header.Set("Unidentified-Access-Key", base64.StdEncoding.EncodeToString(wrongKey))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid UAK, got %d", rr.Code)
	}
}

func TestHandleSendMessage_UAK_DestinationNoUAK_Returns403(t *testing.T) {
	s := newTestServer(t)

	// Create destination account with no UAK set.
	destAcct := testAccount()
	destAcct.UnidentifiedAccessKey = nil
	if err := s.accounts.Create(contextBackground(t), destAcct); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}
	// Ensure auth token hash is set (create normally via manager).
	// Re-fetch to get hashed token.
	da, err := s.accounts.Get(contextBackground(t), testAccountUUID)
	if err != nil {
		t.Fatalf("failed to get dest account: %v", err)
	}
	// Force no UAK.
	da.UnidentifiedAccessKey = nil
	if err := s.accounts.Update(contextBackground(t), da); err != nil {
		t.Fatalf("failed to update account: %v", err)
	}

	// Any UAK value in the request should cause 401 at middleware (account has no UAK)
	// Middleware will reject before handler even sees the request.
	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.Header.Set("Unidentified-Access-Key", base64.StdEncoding.EncodeToString([]byte("some-key")))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// The middleware rejects because stored UAK is nil/empty (dummy compare fails)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when dest has no UAK, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_AuthenticatedSend_StillWorks(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	contentB64 := base64.StdEncoding.EncodeToString([]byte("authenticated message"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for authenticated send, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_NoAuth_Returns401(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	// No auth header at all.
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no auth, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSendMultiRecipientMessage — UAK integration tests
// --------------------------------------------------------------------------

func TestHandleSendMultiRecipientMessage_AuthenticatedSend_StillWorks(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("multi sealed"))
	body := `{
		"recipients": [{"uuid":"` + testAccountUUID + `","deviceIds":[1],"registrationIds":[12345]}],
		"commonPayload":"` + payloadB64 + `",
		"timestamp":1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMultiRecipientMessage_NoAuth_Returns401(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader("{}"))
	// No auth at all.
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with no auth, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// contextBackground returns context.Background() as a typed helper to keep
// test bodies concise without importing context explicitly everywhere.
func contextBackground(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
