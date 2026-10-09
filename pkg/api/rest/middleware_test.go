package rest

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// jsonMiddleware
// --------------------------------------------------------------------------

func TestJsonMiddleware_SetsContentType(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := jsonMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestJsonMiddleware_PreservesInnerHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	})

	handler := jsonMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", rr.Code)
	}
	if rr.Body.String() != `{"ok":true}` {
		t.Errorf("unexpected body: %s", rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// loggingMiddleware
// --------------------------------------------------------------------------

func TestLoggingMiddleware_ReturnsStatusOK(t *testing.T) {
	logger := testLogger()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := loggingMiddleware(logger, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
}

func TestLoggingMiddleware_RecordsStatusFromHandler(t *testing.T) {
	logger := testLogger()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := loggingMiddleware(logger, inner)
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// authMiddleware
// --------------------------------------------------------------------------

func TestAuthMiddleware_MissingCredentials(t *testing.T) {
	s := newTestServer(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := authMiddleware(s.accounts, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestAuthMiddleware_InvalidUUID(t *testing.T) {
	s := newTestServer(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := authMiddleware(s.accounts, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	req.SetBasicAuth("nonexistent-uuid", "wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_WrongPassword(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := authMiddleware(s.accounts, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	req.SetBasicAuth(testAccountUUID, "wrong-password")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestAuthMiddleware_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		acct := accountFromContext(r.Context())
		if acct == nil {
			t.Error("expected account in context")
			return
		}
		if acct.UUID != testAccountUUID {
			t.Errorf("expected UUID %s, got %s", testAccountUUID, acct.UUID)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := authMiddleware(s.accounts, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected inner handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddleware_UUIDWithDeviceIdSuffix(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		acct := accountFromContext(r.Context())
		if acct == nil {
			t.Error("expected account in context")
			return
		}
		if acct.UUID != testAccountUUID {
			t.Errorf("expected UUID %s, got %s", testAccountUUID, acct.UUID)
		}
	})

	handler := authMiddleware(s.accounts, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	req.SetBasicAuth(testAccountUUID+".1", testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected inner handler to be called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddleware_EmptyPassword(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := authMiddleware(s.accounts, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	req.SetBasicAuth(testAccountUUID, "")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for empty password, got %d", rr.Code)
	}
}

func TestAuthMiddleware_MalformedBasicAuth(t *testing.T) {
	s := newTestServer(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := authMiddleware(s.accounts, inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	// Set a garbled Authorization header that is not valid base64.
	req.Header.Set("Authorization", "Basic !!!not-valid-base64!!!")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed Authorization header, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// writeJSON
// --------------------------------------------------------------------------

func TestWriteJSON_Success(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, map[string]string{"key": "value"})

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type")
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if body["key"] != "value" {
		t.Errorf("unexpected body: %v", body)
	}
}

func TestWriteJSON_MarshalError(t *testing.T) {
	rr := httptest.NewRecorder()
	// Functions cannot be marshaled to JSON.
	writeJSON(rr, http.StatusOK, func() {})

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// writeError
// --------------------------------------------------------------------------

func TestWriteError_WritesJSONError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, http.StatusBadRequest, "test error")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type")
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if body["error"] != "test error" {
		t.Errorf("expected error message 'test error', got %q", body["error"])
	}
}

func TestWriteError_InternalServerError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, http.StatusInternalServerError, "something broke")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// statusRecorder
// --------------------------------------------------------------------------

func TestStatusRecorder_WriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rr, statusCode: http.StatusOK}
	sr.WriteHeader(http.StatusNotFound)

	if sr.statusCode != http.StatusNotFound {
		t.Errorf("expected 404 captured, got %d", sr.statusCode)
	}
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 on underlying recorder, got %d", rr.Code)
	}
}

func TestStatusRecorder_DefaultStatusCode(t *testing.T) {
	rr := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rr, statusCode: http.StatusOK}

	if sr.statusCode != http.StatusOK {
		t.Errorf("expected default 200, got %d", sr.statusCode)
	}
}

// --------------------------------------------------------------------------
// statusRecorder.Hijack
// --------------------------------------------------------------------------

type mockHijacker struct {
	http.ResponseWriter
	hijacked bool
}

func (h *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestStatusRecorder_Hijack_Success(t *testing.T) {
	hj := &mockHijacker{ResponseWriter: httptest.NewRecorder()}
	sr := &statusRecorder{ResponseWriter: hj, statusCode: http.StatusOK}

	_, _, err := sr.Hijack()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hj.hijacked {
		t.Error("expected Hijack to be called on underlying writer")
	}
}

func TestStatusRecorder_Hijack_NotSupported(t *testing.T) {
	rr := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rr, statusCode: http.StatusOK}

	_, _, err := sr.Hijack()
	if err == nil {
		t.Fatal("expected error when hijacking non-hijackable ResponseWriter")
	}
	var he *HijackError
	if _, ok := err.(*HijackError); !ok {
		t.Errorf("expected HijackError, got %T: %v", err, he)
	}
}

// brokenWriter is a ResponseWriter whose Write always fails. It is used to
// exercise the error-logging branches in writeJSON and writeError that handle
// a write failure gracefully (log and continue rather than panic).
type brokenWriter struct {
	http.ResponseWriter
	header http.Header
	code   int
}

func newBrokenWriter() *brokenWriter {
	return &brokenWriter{
		ResponseWriter: httptest.NewRecorder(),
		header:         make(http.Header),
		code:           http.StatusOK,
	}
}

func (b *brokenWriter) Header() http.Header         { return b.header }
func (b *brokenWriter) WriteHeader(code int)        { b.code = code }
func (b *brokenWriter) Write(_ []byte) (int, error) { return 0, errors.New("write error") }

func TestWriteJSON_WriteFailure_DoesNotPanic(t *testing.T) {
	bw := newBrokenWriter()
	// Should not panic even though the underlying Write fails.
	writeJSON(bw, http.StatusOK, map[string]string{"key": "value"})
	// The function logs the error but does not return it; verify no panic.
}

func TestWriteError_WriteFailure_DoesNotPanic(t *testing.T) {
	bw := newBrokenWriter()
	// Should not panic even though the underlying Write fails.
	writeError(bw, http.StatusBadRequest, "some error")
	// The function logs the error but does not return it; verify no panic.
}

// --------------------------------------------------------------------------
// HijackError
// --------------------------------------------------------------------------

func TestHijackError_ErrorMessage(t *testing.T) {
	e := &HijackError{}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

// --------------------------------------------------------------------------
// contextWithAccount / accountFromContext
// --------------------------------------------------------------------------

func TestContextWithAccount_RoundTrip(t *testing.T) {
	acct := testAccount()
	ctx := contextWithAccount(context.Background(), acct)
	got := accountFromContext(ctx)
	if got == nil {
		t.Fatal("expected account from context")
		return
	}
	if got.UUID != acct.UUID {
		t.Errorf("expected UUID %s, got %s", acct.UUID, got.UUID)
	}
}

func TestAccountFromContext_NilWhenMissing(t *testing.T) {
	got := accountFromContext(context.Background())
	if got != nil {
		t.Error("expected nil account from empty context")
	}
}

// --------------------------------------------------------------------------
// decodeBase64
// --------------------------------------------------------------------------

func TestDecodeBase64_StandardWithPadding(t *testing.T) {
	original := []byte("hello world base64 test data")
	encoded := base64.StdEncoding.EncodeToString(original)

	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("expected %q, got %q", original, decoded)
	}
}

func TestDecodeBase64_StandardWithoutPadding(t *testing.T) {
	original := []byte("hello world base64 test data")
	encoded := base64.RawStdEncoding.EncodeToString(original)

	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("expected %q, got %q", original, decoded)
	}
}

func TestDecodeBase64_URLSafeWithPadding(t *testing.T) {
	// Use data that produces + and / in standard encoding to differentiate.
	original := []byte{0xfb, 0xff, 0xfe, 0xfb, 0xff, 0xfe}
	encoded := base64.URLEncoding.EncodeToString(original)

	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded mismatch: got %x, want %x", decoded, original)
	}
}

func TestDecodeBase64_URLSafeWithoutPadding(t *testing.T) {
	original := []byte{0xfb, 0xff, 0xfe, 0xfb, 0xff, 0xfe}
	encoded := base64.RawURLEncoding.EncodeToString(original)

	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("decoded mismatch: got %x, want %x", decoded, original)
	}
}

func TestDecodeBase64_InvalidInput(t *testing.T) {
	_, err := decodeBase64("!!!not-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64 input")
	}
}

func TestDecodeBase64_EmptyString(t *testing.T) {
	decoded, err := decodeBase64("")
	if err != nil {
		t.Fatalf("unexpected error for empty string: %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(decoded))
	}
}

// --------------------------------------------------------------------------
// bodyLimitMiddleware
// --------------------------------------------------------------------------

func TestBodyLimitMiddleware_SmallBodyPassesThrough(t *testing.T) {
	body := make([]byte, 1024) // 1 KB – well under 256 KB limit
	for i := range body {
		body[i] = 'a'
	}

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := bodyLimitMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected inner handler to be called for small body")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for small body, got %d", rr.Code)
	}
}

func TestBodyLimitMiddleware_ExactLimitBodyPassesThrough(t *testing.T) {
	// Body exactly at DefaultBodyLimit must pass through.
	body := make([]byte, DefaultBodyLimit)
	for i := range body {
		body[i] = 'b'
	}

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Read the entire body to trigger MaxBytesReader checks.
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := bodyLimitMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages/dest", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected inner handler to be called for exact-limit body")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for exact-limit body, got %d", rr.Code)
	}
}

func TestBodyLimitMiddleware_OversizedBodyReturns413(t *testing.T) {
	// Body larger than DefaultBodyLimit must return 413.
	body := make([]byte, DefaultBodyLimit+1)
	for i := range body {
		body[i] = 'x'
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Trigger the MaxBytesReader by reading the body.
		if _, err := io.ReadAll(r.Body); err != nil {
			// MaxBytesError: the middleware's limitWriter must intercept.
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := bodyLimitMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d", rr.Code)
	}
}

func TestBodyLimitMiddleware_UploadPathAllowsLargeBody(t *testing.T) {
	// A body under UploadBodyLimit on a CDN path must pass through.
	body := make([]byte, DefaultBodyLimit+1) // larger than default but under upload limit
	for i := range body {
		body[i] = 'u'
	}

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "read failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := bodyLimitMiddleware(inner)
	req := httptest.NewRequest(http.MethodPut, "/cdn/some/path", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected inner handler to be called for upload path")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for upload path under limit, got %d", rr.Code)
	}
}

func TestBodyLimitMiddleware_UploadPathOversizedReturns413(t *testing.T) {
	body := make([]byte, UploadBodyLimit+1)
	for i := range body {
		body[i] = 'y'
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := bodyLimitMiddleware(inner)
	req := httptest.NewRequest(http.MethodPut, "/cdn/upload", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized upload body, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// isUploadPath
// --------------------------------------------------------------------------

func TestIsUploadPath_CDNPaths(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"/cdn/file.jpg", true},
		{"/cdn2/attachment", true},
		{"/cdn3/object/key", true},
		{"/v4/attachments/form/upload", true},
		{"/v1/archives/upload/form", true},
		{"/v1/registration", false},
		{"/v1/messages/dest", false},
		{"/v2/keys", false},
		{"/", false},
		{"", false},
	}

	for _, tc := range tests {
		got := isUploadPath(tc.path)
		if got != tc.expected {
			t.Errorf("isUploadPath(%q) = %v, want %v", tc.path, got, tc.expected)
		}
	}
}

// --------------------------------------------------------------------------
// securityHeadersMiddleware
// --------------------------------------------------------------------------

func TestSecurityHeadersMiddleware_SetsAllRequiredHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeadersMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	tests := []struct {
		header string
		value  string
	}{
		{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Content-Security-Policy", "default-src 'none'"},
		{"X-XSS-Protection", "0"},
		{"Cache-Control", "no-store"},
		{"Referrer-Policy", "no-referrer"},
	}

	for _, tc := range tests {
		got := rr.Header().Get(tc.header)
		if got != tc.value {
			t.Errorf("header %q: expected %q, got %q", tc.header, tc.value, got)
		}
	}
}

func TestSecurityHeadersMiddleware_InnerHandlerStatusPreserved(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	handler := securityHeadersMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201 from inner handler, got %d", rr.Code)
	}
	// Security headers must still be present.
	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("expected X-Frame-Options: DENY even on non-200 response")
	}
}

func TestSecurityHeadersMiddleware_STSIncludesSubdomains(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeadersMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	sts := rr.Header().Get("Strict-Transport-Security")
	if !strings.Contains(sts, "includeSubDomains") {
		t.Errorf("STS header should include 'includeSubDomains', got %q", sts)
	}
	if !strings.Contains(sts, "max-age=31536000") {
		t.Errorf("STS header should include max-age=31536000, got %q", sts)
	}
}

// --------------------------------------------------------------------------
// limitWriter / limitedBody internals
// --------------------------------------------------------------------------

func TestLimitWriter_WriteHeader_OncePreventsDouble(t *testing.T) {
	rr := httptest.NewRecorder()
	lb := &limitedBody{rc: io.NopCloser(strings.NewReader(""))}
	lw := &limitWriter{ResponseWriter: rr, body: lb}

	lw.WriteHeader(http.StatusOK)
	lw.WriteHeader(http.StatusNotFound) // second call must be ignored

	if rr.Code != http.StatusOK {
		t.Errorf("expected first WriteHeader (200) to win, got %d", rr.Code)
	}
}

func TestLimitWriter_Write_TriggersImplicitWriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	lb := &limitedBody{rc: io.NopCloser(strings.NewReader(""))}
	lw := &limitWriter{ResponseWriter: rr, body: lb}

	n, err := lw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected implicit 200, got %d", rr.Code)
	}
}

func TestLimitWriter_Hijack_NotSupported(t *testing.T) {
	rr := httptest.NewRecorder()
	lb := &limitedBody{rc: io.NopCloser(strings.NewReader(""))}
	lw := &limitWriter{ResponseWriter: rr, body: lb}

	_, _, err := lw.Hijack()
	if err == nil {
		t.Fatal("expected error when hijacking non-hijackable ResponseWriter")
	}
	if _, ok := err.(*HijackError); !ok {
		t.Errorf("expected *HijackError, got %T", err)
	}
}

func TestLimitedBody_Close_DelegatesOK(t *testing.T) {
	lb := &limitedBody{rc: io.NopCloser(strings.NewReader("data"))}
	if err := lb.Close(); err != nil {
		t.Errorf("unexpected error from Close: %v", err)
	}
}

func TestLimitWriter_WriteHeader_OverflowForces413(t *testing.T) {
	rr := httptest.NewRecorder()
	lb := &limitedBody{rc: io.NopCloser(strings.NewReader(""))}
	lb.overflowErr = &http.MaxBytesError{}
	lw := &limitWriter{ResponseWriter: rr, body: lb}

	lw.WriteHeader(http.StatusOK)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 when overflow detected, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// redactNumber
// --------------------------------------------------------------------------

func TestRedactNumber_NormalNumber(t *testing.T) {
	got := redactNumber("1234567890")
	if got != "1234****" {
		t.Errorf("expected %q, got %q", "1234****", got)
	}
}

func TestRedactNumber_ShortNumber(t *testing.T) {
	got := redactNumber("123")
	if got != "****" {
		t.Errorf("expected %q, got %q", "****", got)
	}
}

func TestRedactNumber_EmptyString(t *testing.T) {
	got := redactNumber("")
	if got != "****" {
		t.Errorf("expected %q, got %q", "****", got)
	}
}

func TestRedactNumber_ExactlyFourChars(t *testing.T) {
	// Four characters is still < 5, so fully redacted.
	got := redactNumber("1234")
	if got != "****" {
		t.Errorf("expected %q, got %q", "****", got)
	}
}

func TestRedactNumber_FiveChars(t *testing.T) {
	// Five characters: show first four, redact remainder.
	got := redactNumber("12345")
	if got != "1234****" {
		t.Errorf("expected %q, got %q", "1234****", got)
	}
}

// --------------------------------------------------------------------------
// ipKeyWithProxies
// --------------------------------------------------------------------------

func TestIpKeyWithProxies_NoTrustedProxies_IgnoresXFF(t *testing.T) {
	// When no trusted proxies are configured, XFF is ignored entirely and
	// RemoteAddr is used. Trusting XFF unconditionally is trivially spoofable
	// by any client that can set request headers.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9000"
	req.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.2")

	got := ipKeyWithProxies(req, nil)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr IP %q, got %q", "10.0.0.1", got)
	}
}

func TestIpKeyWithProxies_TrustedProxy_ExtractsRightmostUntrusted(t *testing.T) {
	// When RemoteAddr is within the trusted CIDR, the rightmost untrusted
	// XFF hop is used as the client IP.
	_, trustedNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:9000"
	// Leftmost is spoofable; rightmost untrusted is the real client.
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.99, 10.0.0.2")

	got := ipKeyWithProxies(req, []*net.IPNet{trustedNet})
	if got != "203.0.113.99" {
		t.Errorf("expected rightmost untrusted XFF hop %q, got %q", "203.0.113.99", got)
	}
}

func TestIpKeyWithProxies_UntrustedProxy_IgnoresXFF(t *testing.T) {
	// When RemoteAddr is NOT in a trusted CIDR, XFF is ignored entirely and
	// the RemoteAddr IP is returned directly.
	_, trustedNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:9000" // not in 10.0.0.0/8
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := ipKeyWithProxies(req, []*net.IPNet{trustedNet})
	if got != "203.0.113.1" {
		t.Errorf("expected RemoteAddr IP %q, got %q", "203.0.113.1", got)
	}
}

func TestIpKeyWithProxies_NoXFF_UsesRemoteAddr(t *testing.T) {
	// When no X-Forwarded-For header is present, RemoteAddr IP is returned
	// regardless of whether any trusted proxies are configured.
	_, trustedNet, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:4321"
	// No X-Forwarded-For header.

	got := ipKeyWithProxies(req, []*net.IPNet{trustedNet})
	if got != "10.0.0.5" {
		t.Errorf("expected RemoteAddr IP %q, got %q", "10.0.0.5", got)
	}
}

func TestLimitWriter_Write_SwallowsBodyOnOverflow(t *testing.T) {
	rr := httptest.NewRecorder()
	lb := &limitedBody{rc: io.NopCloser(strings.NewReader(""))}
	lb.overflowErr = &http.MaxBytesError{}
	lw := &limitWriter{ResponseWriter: rr, body: lb}

	// WriteHeader must be called first to lock in the 413.
	lw.WriteHeader(http.StatusRequestEntityTooLarge)

	// Write should report all bytes consumed (swallowed) and no error.
	data := []byte("should be swallowed")
	n, err := lw.Write(data)
	if err != nil {
		t.Fatalf("unexpected error from Write on overflow: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes consumed, got %d", len(data), n)
	}
	// Body must not reach the underlying recorder.
	if rr.Body.Len() != 0 {
		t.Errorf("expected underlying recorder body to be empty, got %d bytes", rr.Body.Len())
	}
}

// --------------------------------------------------------------------------
// redactQueryParams
// --------------------------------------------------------------------------

func TestRedactQueryParams_NoSensitiveParams(t *testing.T) {
	got := redactQueryParams("foo=bar&baz=qux")
	if strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected no redaction for non-sensitive params, got %q", got)
	}
}

func TestRedactQueryParams_RedactsLoginParam(t *testing.T) {
	// params.Encode() URL-encodes values; "[REDACTED]" becomes "%5BREDACTED%5D".
	got := redactQueryParams("login=myuser&other=value")
	if strings.Contains(got, "myuser") {
		t.Errorf("expected login value to be removed from output, got %q", got)
	}
	// Sentinel must appear in some form (encoded or literal).
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("expected REDACTED sentinel in output, got %q", got)
	}
}

func TestRedactQueryParams_RedactsPasswordParam(t *testing.T) {
	got := redactQueryParams("password=secret123&other=value")
	if strings.Contains(got, "secret123") {
		t.Errorf("expected password value to be removed from output, got %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("expected REDACTED sentinel in output, got %q", got)
	}
}

func TestRedactQueryParams_RedactsBothLoginAndPassword(t *testing.T) {
	got := redactQueryParams("login=user&password=pass&token=abc")
	if strings.Contains(got, "=user") || strings.Contains(got, "=pass") {
		t.Errorf("expected credential values to be removed from output, got %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("expected REDACTED sentinel in output, got %q", got)
	}
	// Non-sensitive params must be preserved.
	if !strings.Contains(got, "token=abc") {
		t.Errorf("expected non-sensitive param token=abc to be preserved, got %q", got)
	}
}

func TestRedactQueryParams_InvalidQueryString(t *testing.T) {
	// A query string that cannot be parsed must be fully redacted.
	got := redactQueryParams(";invalid=%%%")
	if got != "[REDACTED]" {
		t.Errorf("expected [REDACTED] for unparseable query, got %q", got)
	}
}

func TestRedactQueryParams_EmptyString(t *testing.T) {
	got := redactQueryParams("")
	// Empty query should parse cleanly and return an empty string.
	if got != "" {
		t.Errorf("expected empty string for empty query, got %q", got)
	}
}

// =============================================================================
// writeJSON must encode through secrets.JSONAppender when the payload offers
// one. This is the whole mechanism that keeps credential plaintext in a single
// owned buffer: json.Marshal on a credential cannot do it, because MarshalJSON
// must RETURN a fresh buffer, encoding/json copies it and drops the original,
// and the abandoned copy holds the password with no owner left to wipe it.
// =============================================================================

// appenderProbe implements BOTH interfaces, with deliberately different output,
// so the response body itself reveals which path writeJSON took. A test that
// only checked for valid JSON would pass either way.
type appenderProbe struct{ marshalCalled *bool }

func (p appenderProbe) AppendJSON(dst []byte) ([]byte, error) {
	return append(dst, `{"via":"appender"}`...), nil
}

func (p appenderProbe) MarshalJSON() ([]byte, error) {
	*p.marshalCalled = true
	return []byte(`{"via":"marshaler"}`), nil
}

func TestWriteJSON_PrefersJSONAppenderOverMarshalJSON(t *testing.T) {
	marshalCalled := false
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, appenderProbe{marshalCalled: &marshalCalled})

	if got := strings.TrimSpace(rr.Body.String()); got != `{"via":"appender"}` {
		t.Errorf("writeJSON did not use the appender path: body = %s", got)
	}
	// The stronger assertion: MarshalJSON must not have run at all. If it had,
	// encoding/json would have copied and abandoned its buffer — which for a
	// real credential is precisely the unwiped plaintext this design removes.
	if marshalCalled {
		t.Error("writeJSON called MarshalJSON, abandoning an unwiped buffer")
	}
}

// A payload with no AppendJSON must still marshal correctly — the appender is
// an optimisation of ownership, not a requirement for every response type.
func TestWriteJSON_FallsBackToMarshalForOrdinaryPayloads(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, map[string]string{"key": "value"})
	if got := strings.TrimSpace(rr.Body.String()); got != `{"key":"value"}` {
		t.Errorf("non-appender payload marshalled wrong: %s", got)
	}
}

// An appender that fails partway has already written the username and the
// opening of the password literal into the buffer. writeJSON must wipe on that
// path too, and must not emit the partial body as if it were a response.
type failingAppender struct{ partial *[]byte }

func (f failingAppender) AppendJSON(dst []byte) ([]byte, error) {
	dst = append(dst, `{"username":"u","password":"secr`...)
	*f.partial = dst
	return dst, errors.New("credential unavailable")
}

func TestWriteJSON_WipesPartialBodyWhenAppenderFails(t *testing.T) {
	var partial []byte
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, failingAppender{partial: &partial})

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on appender failure, got %d", rr.Code)
	}
	if len(partial) == 0 {
		t.Fatal("probe never produced a partial buffer; the test proves nothing")
	}
	for i, b := range partial {
		if b != 0 {
			t.Fatalf("partial body left unwiped at byte %d (%q): the plaintext "+
				"written before the failure is still resident", i, partial)
		}
	}
}
