package ses

import (
	"context"
	"encoding/json"
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

// fakeSES records the inbound request bytes + lets each test override the
// response. Only SES SendEmail (POST /v2/email/outbound-emails) is handled.
type fakeSES struct {
	mu         sync.Mutex
	server     *httptest.Server
	lastBody   []byte
	lastAuth   string
	lastPath   string
	statusCode int
	body       string
}

func newFakeSES() *fakeSES {
	f := &fakeSES{statusCode: http.StatusOK, body: `{"MessageId":"abc"}`}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		f.lastBody = body
		f.lastAuth = r.Header.Get("Authorization")
		f.lastPath = r.URL.Path
		w.WriteHeader(f.statusCode)
		_, _ = w.Write([]byte(f.body))
	})
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeSES) Close() { f.server.Close() }

func newTestTransport(t *testing.T, f *fakeSES) *Transport {
	t.Helper()
	tr, err := NewTransport(Config{
		Region:          "us-east-1",
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: secrets.NewSecureString("secret-key"),
		FromAddress:     "verify@signal.test",
		Endpoint:        f.server.URL,
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	return tr
}

func TestNewTransport_RequiredFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no Region", Config{AccessKeyID: "a", SecretAccessKey: secrets.NewSecureString("s"), FromAddress: "f@a"}},
		{"no AccessKeyID", Config{Region: "r", SecretAccessKey: secrets.NewSecureString("s"), FromAddress: "f@a"}},
		{"no SecretAccessKey", Config{Region: "r", AccessKeyID: "a", FromAddress: "f@a"}},
		{"empty SecretAccessKey", Config{Region: "r", AccessKeyID: "a", SecretAccessKey: secrets.NewSecureString(""), FromAddress: "f@a"}},
		{"no FromAddress", Config{Region: "r", AccessKeyID: "a", SecretAccessKey: secrets.NewSecureString("s")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewTransport(c.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewTransport_DefaultsEndpointAndSubject(t *testing.T) {
	tr, err := NewTransport(Config{
		Region: "us-east-1", AccessKeyID: "a",
		SecretAccessKey: secrets.NewSecureString("s"), FromAddress: "f@a",
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	if tr.endpoint != "https://email.us-east-1.amazonaws.com" {
		t.Errorf("endpoint default = %q", tr.endpoint)
	}
	if tr.subject != "Signal verification code" {
		t.Errorf("subject default = %q", tr.subject)
	}
}

func TestTransport_Name(t *testing.T) {
	tr, _ := NewTransport(Config{
		Region: "us-east-1", AccessKeyID: "a",
		SecretAccessKey: secrets.NewSecureString("s"), FromAddress: "f@a",
	})
	if tr.Name() != "ses" {
		t.Errorf("Name = %q", tr.Name())
	}
}

func TestSendCode_HappyPath(t *testing.T) {
	f := newFakeSES()
	defer f.Close()
	tr := newTestTransport(t, f)
	if err := tr.SendCode(context.Background(), "user@example.com", "123456"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasSuffix(f.lastPath, "/v2/email/outbound-emails") {
		t.Errorf("path = %q", f.lastPath)
	}
	if !strings.HasPrefix(f.lastAuth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("missing SigV4 Authorization: %s", f.lastAuth)
	}

	// Body must be a valid SES JSON envelope carrying the code.
	var req sesSendRequest
	if err := json.Unmarshal(f.lastBody, &req); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !strings.Contains(req.Content.Simple.Body.Text.Data, "123456") {
		t.Errorf("body missing code: %s", req.Content.Simple.Body.Text.Data)
	}
	if len(req.Destination.ToAddresses) != 1 || req.Destination.ToAddresses[0] != "user@example.com" {
		t.Errorf("destination wrong: %+v", req.Destination)
	}
	if req.FromEmailAddress != "verify@signal.test" {
		t.Errorf("from = %q", req.FromEmailAddress)
	}
}

func TestSendCode_RejectsEmptyDestination(t *testing.T) {
	f := newFakeSES()
	defer f.Close()
	tr := newTestTransport(t, f)
	if err := tr.SendCode(context.Background(), "", "1"); err == nil {
		t.Fatal("expected error")
	}
}

func TestSendCode_APIErrorWrapped(t *testing.T) {
	f := newFakeSES()
	defer f.Close()
	tr := newTestTransport(t, f)
	f.mu.Lock()
	f.statusCode = http.StatusBadRequest
	f.body = `{"__type":"MessageRejected","message":"Email address is not verified"}`
	f.mu.Unlock()
	err := tr.SendCode(context.Background(), "x@y", "1")
	if err == nil {
		t.Fatal("expected error")
	}
	var te *verification.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %T", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError underneath, got %T", te.Cause)
	}
	if apiErr.Code != "MessageRejected" {
		t.Errorf("Code = %q, want MessageRejected", apiErr.Code)
	}
}

func TestSendCode_UnparsableBodyFallsBackToRaw(t *testing.T) {
	f := newFakeSES()
	defer f.Close()
	tr := newTestTransport(t, f)
	f.mu.Lock()
	f.statusCode = http.StatusInternalServerError
	f.body = `boom`
	f.mu.Unlock()
	err := tr.SendCode(context.Background(), "x@y", "1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected raw body in error chain, got %v", err)
	}
}

func TestSendCode_TransportErrorWrapped(t *testing.T) {
	tr, err := NewTransport(Config{
		Region: "us-east-1", AccessKeyID: "a",
		SecretAccessKey: secrets.NewSecureString("s"), FromAddress: "f@a",
		Endpoint: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	err = tr.SendCode(context.Background(), "x@y", "1")
	if err == nil {
		t.Fatal("expected error on unreachable host")
	}
	var te *verification.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("expected *TransportError, got %T", err)
	}
}

func TestAPIError_Format(t *testing.T) {
	cases := []struct {
		name string
		err  *APIError
		want string
	}{
		{"with code", &APIError{HTTPStatus: 400, Code: "MessageRejected", Message: "bad"}, "ses: http 400 code=MessageRejected: bad"},
		{"no code", &APIError{HTTPStatus: 500, Message: "boom"}, "ses: http 500: boom"},
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
