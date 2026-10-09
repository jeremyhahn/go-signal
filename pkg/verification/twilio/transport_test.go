package twilio

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// fakeTwilio captures the requests and lets each test override the response.
type fakeTwilio struct {
	mu             sync.Mutex
	server         *httptest.Server
	lastBody       string
	lastAuthUser   string
	lastPath       string
	verificationOK bool
	statusCode     int
	body           string
}

func newFakeTwilio() *fakeTwilio {
	f := &fakeTwilio{statusCode: http.StatusCreated, body: `{"sid":"v1","status":"pending"}`, verificationOK: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastPath = r.URL.Path
		u, _, _ := r.BasicAuth()
		f.lastAuthUser = u
		body, _ := io.ReadAll(r.Body)
		f.lastBody = string(body)
		if strings.HasSuffix(r.URL.Path, "/VerificationCheck") {
			status := "approved"
			if !f.verificationOK {
				status = "pending"
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"sid":"vc1","status":"` + status + `"}`))
			return
		}
		w.WriteHeader(f.statusCode)
		_, _ = w.Write([]byte(f.body))
	})
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeTwilio) Close() { f.server.Close() }

func newTestTransport(t *testing.T, f *fakeTwilio) *Transport {
	t.Helper()
	tr, err := NewTransport(t.Context(), Config{
		AccountSID: "ACtest",
		AuthToken:  secrets.MustNewSecureString(t.Context(), "auth-secret"),
		ServiceSID: "VAservice",
		BaseURL:    f.server.URL,
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return tr
}

func TestNewTransport_ValidatesRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no AccountSID", Config{AuthToken: secrets.MustNewSecureString(t.Context(), "x"), ServiceSID: "s"}},
		{"no AuthToken", Config{AccountSID: "a", ServiceSID: "s"}},
		{"empty AuthToken", Config{AccountSID: "a", AuthToken: secrets.MustNewSecureString(t.Context(), ""), ServiceSID: "s"}},
		{"no ServiceSID", Config{AccountSID: "a", AuthToken: secrets.MustNewSecureString(t.Context(), "x")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewTransport(t.Context(), c.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewTransport_DefaultsChannelAndBaseURL(t *testing.T) {
	tr, err := NewTransport(t.Context(), Config{
		AccountSID: "a", AuthToken: secrets.MustNewSecureString(t.Context(), "x"), ServiceSID: "s",
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if tr.channel != "sms" {
		t.Errorf("channel default = %q, want sms", tr.channel)
	}
	if tr.baseURL != defaultBaseURL {
		t.Errorf("baseURL default = %q, want %q", tr.baseURL, defaultBaseURL)
	}
}

func TestTransport_Name(t *testing.T) {
	tr, _ := NewTransport(t.Context(), Config{AccountSID: "a", AuthToken: secrets.MustNewSecureString(t.Context(), "x"), ServiceSID: "s"})
	if got := tr.Name(); got != "twilio" {
		t.Errorf("Name = %q, want twilio", got)
	}
}

func TestSendCode_HappyPath(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	tr := newTestTransport(t, f)

	if err := tr.SendCode(context.Background(), "+15551112222", "ignored"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasSuffix(f.lastPath, "/Services/VAservice/Verifications") {
		t.Errorf("unexpected path: %s", f.lastPath)
	}
	if f.lastAuthUser != "ACtest" {
		t.Errorf("Basic auth user = %q, want ACtest", f.lastAuthUser)
	}
	if !strings.Contains(f.lastBody, "To=%2B15551112222") {
		t.Errorf("missing To form value: %s", f.lastBody)
	}
	if !strings.Contains(f.lastBody, "Channel=sms") {
		t.Errorf("missing Channel form value: %s", f.lastBody)
	}
}

func TestSendCode_NonSMSChannel(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	tr, _ := NewTransport(t.Context(), Config{
		AccountSID: "ACtest", AuthToken: secrets.MustNewSecureString(t.Context(), "x"),
		ServiceSID: "VAservice", BaseURL: f.server.URL, Channel: "whatsapp",
	})
	if err := tr.SendCode(context.Background(), "+1555", ""); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	f.mu.Lock()
	body := f.lastBody
	f.mu.Unlock()
	if !strings.Contains(body, "Channel=whatsapp") {
		t.Errorf("expected Channel=whatsapp, got %s", body)
	}
}

func TestSendCode_APIErrorWrapped(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	tr := newTestTransport(t, f)

	f.mu.Lock()
	f.statusCode = http.StatusBadRequest
	f.body = `{"code":60200,"message":"Invalid parameter","status":400}`
	f.mu.Unlock()

	err := tr.SendCode(context.Background(), "+1", "")
	if err == nil {
		t.Fatal("expected error")
	}
	var te *verification.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %T", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", te.Cause)
	}
	if apiErr.Code != 60200 {
		t.Errorf("Code = %d, want 60200", apiErr.Code)
	}
}

func TestSendCode_UnparsableErrorFallsBackToBody(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	tr := newTestTransport(t, f)
	f.mu.Lock()
	f.statusCode = http.StatusInternalServerError
	f.body = `not json`
	f.mu.Unlock()
	err := tr.SendCode(context.Background(), "+1", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not json") {
		t.Errorf("expected raw body in error, got %v", err)
	}
}

func TestSendCode_TransportErrorWrapped(t *testing.T) {
	tr, _ := NewTransport(t.Context(), Config{
		AccountSID: "a", AuthToken: secrets.MustNewSecureString(t.Context(), "x"),
		ServiceSID: "s", BaseURL: "http://127.0.0.1:1",
	})
	err := tr.SendCode(context.Background(), "+1", "")
	if err == nil {
		t.Fatal("expected error on unreachable host")
	}
	var te *verification.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %T", err)
	}
}

// A destroyed auth token must fail the call before any request is sent,
// never authenticate with an empty password.
func TestSendCode_DestroyedTokenFailsWithoutRequest(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	token := secrets.MustNewSecureString(t.Context(), "auth-secret")
	tr, err := NewTransport(t.Context(), Config{
		AccountSID: "ACtest", AuthToken: token,
		ServiceSID: "VAservice", BaseURL: f.server.URL,
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	token.Destroy()

	err = tr.SendCode(context.Background(), "+1", "")
	var te *verification.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %T", err)
	}
	var ue *secrets.UnavailableSecretError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UnavailableSecretError cause, got %v", err)
	}
}

func TestVerify_DestroyedTokenFails(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	token := secrets.MustNewSecureString(t.Context(), "auth-secret")
	tr, err := NewTransport(t.Context(), Config{
		AccountSID: "ACtest", AuthToken: token,
		ServiceSID: "VAservice", BaseURL: f.server.URL,
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	token.Destroy()

	ok, err := tr.Verify(context.Background(), "+1", "123456")
	if ok || err == nil {
		t.Fatalf("Verify = (%v, %v), want (false, error)", ok, err)
	}
}

func TestVerify_Approved(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	tr := newTestTransport(t, f)
	ok, err := tr.Verify(context.Background(), "+15551112222", "123456")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("expected approved=true")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasSuffix(f.lastPath, "/Services/VAservice/VerificationCheck") {
		t.Errorf("unexpected path: %s", f.lastPath)
	}
	if !strings.Contains(f.lastBody, "Code=123456") {
		t.Errorf("missing Code: %s", f.lastBody)
	}
}

func TestVerify_PendingReturnsFalse(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	tr := newTestTransport(t, f)
	f.mu.Lock()
	f.verificationOK = false
	f.mu.Unlock()
	ok, err := tr.Verify(context.Background(), "+1", "1")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("expected approved=false")
	}
}

func TestVerify_NotFoundReturnsFalse(t *testing.T) {
	// Override the mux to return 404 explicitly.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	tr, _ := NewTransport(t.Context(), Config{
		AccountSID: "a", AuthToken: secrets.MustNewSecureString(t.Context(), "x"),
		ServiceSID: "s", BaseURL: srv.URL,
	})
	ok, err := tr.Verify(context.Background(), "+1", "999")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Error("expected approved=false on 404")
	}
}

func TestVerify_APIErrorReturnsError(t *testing.T) {
	f := newFakeTwilio()
	defer f.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":20003,"message":"Auth denied"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	tr, _ := NewTransport(t.Context(), Config{
		AccountSID: "a", AuthToken: secrets.MustNewSecureString(t.Context(), "x"),
		ServiceSID: "s", BaseURL: srv.URL,
	})
	_, err := tr.Verify(context.Background(), "+1", "1")
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Code != 20003 {
		t.Errorf("Code = %d, want 20003", apiErr.Code)
	}
}

func TestAPIError_StringFormats(t *testing.T) {
	cases := []struct {
		name string
		err  *APIError
		want string
	}{
		{"with code", &APIError{HTTPStatus: 400, Code: 60200, Message: "bad"}, "twilio: http 400 code=60200: bad"},
		{"no code", &APIError{HTTPStatus: 500, Message: "boom"}, "twilio: http 500: boom"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.err.Error(); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestImplementsVerificationTransport(t *testing.T) {
	var _ verification.VerificationTransport = (*Transport)(nil)
}
