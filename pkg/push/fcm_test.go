package push

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// rsaServiceAccountJSON returns a Google-shape service-account JSON whose
// private key is a freshly generated RSA-2048 key in PKCS#8 PEM.
func rsaServiceAccountJSON(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sa := map[string]string{
		"client_email": "test@signal-server.iam.gserviceaccount.com",
		"private_key":  string(pemBytes),
	}
	out, _ := json.Marshal(sa)
	return out
}

func rsaPKCS1ServiceAccountJSON(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	sa := map[string]string{
		"client_email": "t@p.iam.gserviceaccount.com",
		"private_key":  string(pemBytes),
	}
	out, _ := json.Marshal(sa)
	return out
}

// fakeFCM hosts both the OAuth2 token endpoint and the FCM /messages:send
// endpoint, configurable per request.
type fakeFCM struct {
	mu                sync.Mutex
	server            *httptest.Server
	tokenIssued       atomic.Int32
	tokenStatus       int
	tokenBody         string
	sendStatus        int
	sendBody          string
	lastSendAuthToken string
	lastSendBody      []byte
	lastSendPath      string
}

func newFakeFCM() *fakeFCM {
	f := &fakeFCM{
		tokenStatus: http.StatusOK,
		tokenBody:   `{"access_token":"alpha-1","expires_in":3600}`,
		sendStatus:  http.StatusOK,
		sendBody:    `{"name":"projects/p/messages/m1"}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenIssued.Add(1)
		w.WriteHeader(f.tokenStatus)
		_, _ = w.Write([]byte(f.tokenBody))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastSendAuthToken = r.Header.Get("Authorization")
		f.lastSendPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		f.lastSendBody = body
		w.WriteHeader(f.sendStatus)
		_, _ = w.Write([]byte(f.sendBody))
	})
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeFCM) Close() { f.server.Close() }

func newFCMTestProvider(t *testing.T, f *fakeFCM) *FCMProvider {
	t.Helper()
	p, err := NewFCMProvider(FCMConfig{
		ProjectID:          "test-proj",
		ServiceAccountJSON: rsaServiceAccountJSON(t),
		TokenEndpoint:      f.server.URL + "/token",
		SendEndpoint:       f.server.URL + "/send",
	})
	if err != nil {
		t.Fatalf("NewFCMProvider: %v", err)
	}
	return p
}

func TestNewFCMProvider_RequiresProjectID(t *testing.T) {
	_, err := NewFCMProvider(FCMConfig{ServiceAccountJSON: rsaServiceAccountJSON(t)})
	if err == nil {
		t.Fatal("expected error for missing ProjectID")
	}
}

func TestNewFCMProvider_RejectsBadJSON(t *testing.T) {
	_, err := NewFCMProvider(FCMConfig{ProjectID: "p", ServiceAccountJSON: []byte("not json")})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestNewFCMProvider_RejectsMissingFields(t *testing.T) {
	_, err := NewFCMProvider(FCMConfig{ProjectID: "p", ServiceAccountJSON: []byte(`{}`)})
	if err == nil {
		t.Fatal("expected error when client_email + private_key missing")
	}
}

func TestNewFCMProvider_RejectsBadPrivateKey(t *testing.T) {
	sa, _ := json.Marshal(map[string]string{
		"client_email": "x@y.iam.gserviceaccount.com",
		"private_key":  "not a PEM",
	})
	_, err := NewFCMProvider(FCMConfig{ProjectID: "p", ServiceAccountJSON: sa})
	if err == nil {
		t.Fatal("expected error for malformed private key")
	}
}

func TestNewFCMProvider_AcceptsPKCS1Key(t *testing.T) {
	_, err := NewFCMProvider(FCMConfig{
		ProjectID:          "p",
		ServiceAccountJSON: rsaPKCS1ServiceAccountJSON(t),
	})
	if err != nil {
		t.Fatalf("PKCS#1 key should be accepted: %v", err)
	}
}

func TestFCMProvider_Send_HappyPath(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)

	res, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "tok-1",
		Type:        NotificationTypeNotification,
		Urgent:      true,
		Data:        "hello",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !res.Accepted {
		t.Errorf("expected Accepted=true, got %+v", res)
	}
	// Authorization header should be set with the access_token we minted.
	f.mu.Lock()
	auth := f.lastSendAuthToken
	body := string(f.lastSendBody)
	f.mu.Unlock()
	if !strings.HasPrefix(auth, "Bearer alpha-1") {
		t.Errorf("Authorization = %q, want bearer alpha-1", auth)
	}
	if !strings.Contains(body, `"newMessageAlert"`) || !strings.Contains(body, `"HIGH"`) {
		t.Errorf("body missing expected fields: %s", body)
	}
}

func TestFCMProvider_Send_NonUrgentUsesNormalPriority(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	if _, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "tok-2", Type: NotificationTypeNotification, Data: "x",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	f.mu.Lock()
	body := string(f.lastSendBody)
	f.mu.Unlock()
	if !strings.Contains(body, `"NORMAL"`) {
		t.Errorf("expected NORMAL priority, body=%s", body)
	}
}

func TestFCMProvider_Send_DataKeyByType(t *testing.T) {
	cases := []struct {
		typ NotificationType
		key string
	}{
		{NotificationTypeNotification, "newMessageAlert"},
		{NotificationTypeAttemptLogin, "attemptLoginContext"},
		{NotificationTypeChallenge, "challenge"},
		{NotificationTypeRateLimitChallenge, "rateLimitChallenge"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("type-%d", c.typ), func(t *testing.T) {
			f := newFakeFCM()
			defer f.Close()
			p := newFCMTestProvider(t, f)
			if _, err := p.Send(context.Background(), &PushNotification{
				DeviceToken: "x", Type: c.typ, Data: "DATA",
			}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			f.mu.Lock()
			body := string(f.lastSendBody)
			f.mu.Unlock()
			if !strings.Contains(body, `"`+c.key+`"`) || !strings.Contains(body, `"DATA"`) {
				t.Errorf("expected key %q with DATA, body=%s", c.key, body)
			}
		})
	}
}

func TestFCMProvider_Send_UnknownTypeRejected(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	_, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "x", Type: NotificationType(99),
	})
	if err == nil {
		t.Fatal("expected error for unknown notification type")
	}
}

func TestFCMProvider_Send_NilNotificationRejected(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	if _, err := p.Send(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil notification")
	}
}

func TestFCMProvider_Send_UnregisteredFromDetails(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	f.mu.Lock()
	f.sendStatus = http.StatusNotFound
	f.sendBody = `{
        "error": {
            "code": 404,
            "status": "NOT_FOUND",
            "message": "Requested entity was not found.",
            "details": [
                {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode": "UNREGISTERED"}
            ]
        }
    }`
	f.mu.Unlock()
	res, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "stale", Type: NotificationTypeNotification, Data: "x",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Accepted {
		t.Error("expected Accepted=false")
	}
	if !res.Unregistered {
		t.Error("expected Unregistered=true")
	}
	if res.RejectionReason != "UNREGISTERED" {
		t.Errorf("RejectionReason = %q, want UNREGISTERED", res.RejectionReason)
	}
}

func TestFCMProvider_Send_GenericError(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	f.mu.Lock()
	f.sendStatus = http.StatusBadGateway
	f.sendBody = `{"error":{"status":"INTERNAL"}}`
	f.mu.Unlock()
	res, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "x", Type: NotificationTypeNotification, Data: "x",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Accepted || res.Unregistered {
		t.Errorf("expected rejection without Unregistered, got %+v", res)
	}
	if res.RejectionReason != "INTERNAL" {
		t.Errorf("RejectionReason = %q, want INTERNAL", res.RejectionReason)
	}
}

func TestFCMProvider_Send_FallsBackToHTTPStatus(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	f.mu.Lock()
	f.sendStatus = http.StatusServiceUnavailable
	f.sendBody = `{"unparseable`
	f.mu.Unlock()
	res, _ := p.Send(context.Background(), &PushNotification{
		DeviceToken: "x", Type: NotificationTypeNotification, Data: "x",
	})
	if res.RejectionReason != "http503" {
		t.Errorf("RejectionReason = %q, want http503", res.RejectionReason)
	}
}

func TestFCMProvider_TokenIsCachedAcrossSends(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	for i := 0; i < 3; i++ {
		if _, err := p.Send(context.Background(), &PushNotification{
			DeviceToken: "t", Type: NotificationTypeNotification, Data: "x",
		}); err != nil {
			t.Fatalf("Send #%d: %v", i, err)
		}
	}
	if got := f.tokenIssued.Load(); got != 1 {
		t.Errorf("expected 1 token mint across 3 sends, got %d", got)
	}
}

func TestFCMProvider_RefreshesExpiredToken(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	// First send to mint.
	if _, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "t", Type: NotificationTypeNotification, Data: "x",
	}); err != nil {
		t.Fatalf("Send 1: %v", err)
	}
	// Make the cached token look expired by rolling now into the future.
	p.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "t", Type: NotificationTypeNotification, Data: "x",
	}); err != nil {
		t.Fatalf("Send 2: %v", err)
	}
	if got := f.tokenIssued.Load(); got != 2 {
		t.Errorf("expected 2 token mints after expiry, got %d", got)
	}
}

func TestFCMProvider_TokenEndpointFailureWrapped(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	f.mu.Lock()
	f.tokenStatus = http.StatusUnauthorized
	f.tokenBody = `{"error":"invalid_grant"}`
	f.mu.Unlock()
	_, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "t", Type: NotificationTypeNotification, Data: "x",
	})
	if err == nil {
		t.Fatal("expected error when token endpoint fails")
	}
	var se *SendError
	if !errors.As(err, &se) {
		t.Errorf("expected *SendError wrapping the token failure, got %T: %v", err, err)
	}
}

func TestFCMProvider_TokenResponseMissingAccessTokenRejected(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	f.mu.Lock()
	f.tokenBody = `{"expires_in":3600}`
	f.mu.Unlock()
	if _, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "t", Type: NotificationTypeNotification, Data: "x",
	}); err == nil {
		t.Fatal("expected error when access_token missing")
	}
}

func TestFCMProvider_TokenResponseMissingExpiryUsesSafeWindow(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	f.mu.Lock()
	f.tokenBody = `{"access_token":"x"}`
	f.mu.Unlock()
	// Should succeed even when expires_in is missing.
	if _, err := p.Send(context.Background(), &PushNotification{
		DeviceToken: "t", Type: NotificationTypeNotification, Data: "x",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestFCMProvider_ImplementsInterface(t *testing.T) {
	var _ PushProvider = (*FCMProvider)(nil)
}

func TestFCMProvider_CloseSafe(t *testing.T) {
	f := newFakeFCM()
	defer f.Close()
	p := newFCMTestProvider(t, f)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
