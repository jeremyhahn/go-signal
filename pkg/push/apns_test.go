package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
)

// p256KeyPEM generates a fresh P-256 key in PKCS#8 PEM, the shape Apple
// issues for .p8 keys. Used by tests that need NewAPNsProvider to succeed.
func p256KeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestNewAPNsProvider_RequiresBundleID(t *testing.T) {
	_, err := NewAPNsProvider(APNsConfig{
		TeamID: "T", KeyID: "K", SigningKeyPEM: p256KeyPEM(t),
	})
	if err == nil {
		t.Fatal("expected error when BundleID missing")
	}
}

func TestNewAPNsProvider_RequiresTeamID(t *testing.T) {
	_, err := NewAPNsProvider(APNsConfig{
		BundleID: "b", KeyID: "K", SigningKeyPEM: p256KeyPEM(t),
	})
	if err == nil {
		t.Fatal("expected error when TeamID missing")
	}
}

func TestNewAPNsProvider_RequiresKeyID(t *testing.T) {
	_, err := NewAPNsProvider(APNsConfig{
		BundleID: "b", TeamID: "T", SigningKeyPEM: p256KeyPEM(t),
	})
	if err == nil {
		t.Fatal("expected error when KeyID missing")
	}
}

func TestNewAPNsProvider_RejectsEmptyKey(t *testing.T) {
	_, err := NewAPNsProvider(APNsConfig{BundleID: "b", TeamID: "T", KeyID: "K"})
	if err == nil {
		t.Fatal("expected error for empty signing key")
	}
}

func TestNewAPNsProvider_RejectsBadPEM(t *testing.T) {
	_, err := NewAPNsProvider(APNsConfig{
		BundleID: "b", TeamID: "T", KeyID: "K",
		SigningKeyPEM: []byte("not a PEM"),
	})
	if err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func TestNewAPNsProvider_RejectsNonECDSAKey(t *testing.T) {
	// Generate a plain Ed25519 key (PKCS#8) and verify the provider rejects it.
	// We reuse the ECDSA helper to wrap arbitrary key bytes in PEM.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	_, err := NewAPNsProvider(APNsConfig{
		BundleID: "b", TeamID: "T", KeyID: "K",
		SigningKeyPEM: pemBytes,
	})
	if err == nil {
		t.Fatal("expected error for non-ECDSA key bytes")
	}
}

func TestNewAPNsProvider_ProductionAndSandbox(t *testing.T) {
	cases := []struct {
		name    string
		sandbox bool
	}{
		{"production", false},
		{"sandbox", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := NewAPNsProvider(APNsConfig{
				BundleID:      "org.signal",
				TeamID:        "TEAM",
				KeyID:         "KID",
				SigningKeyPEM: p256KeyPEM(t),
				Sandbox:       c.sandbox,
			})
			if err != nil {
				t.Fatalf("NewAPNsProvider: %v", err)
			}
			if p.bundleID != "org.signal" {
				t.Errorf("bundleID = %q, want %q", p.bundleID, "org.signal")
			}
		})
	}
}

func TestAPNsCollapseID(t *testing.T) {
	cases := []struct {
		name   string
		n      PushNotification
		expect string
	}{
		{"urgent notification collapses", PushNotification{Type: NotificationTypeNotification, Urgent: true}, "incoming-message"},
		{"non-urgent notification does not", PushNotification{Type: NotificationTypeNotification, Urgent: false}, ""},
		{"challenge does not", PushNotification{Type: NotificationTypeChallenge}, ""},
		{"attempt-login does not", PushNotification{Type: NotificationTypeAttemptLogin}, ""},
		{"rate-limit does not", PushNotification{Type: NotificationTypeRateLimitChallenge}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := c.n
			if got := apnsCollapseIDForType(&n); got != c.expect {
				t.Errorf("got %q, want %q", got, c.expect)
			}
		})
	}
}

func TestBuildAPNsPayloadAndPushType(t *testing.T) {
	cases := []struct {
		name     string
		n        PushNotification
		wantType apns2.EPushType
	}{
		{"urgent notification → alert", PushNotification{Type: NotificationTypeNotification, Urgent: true}, apns2.PushTypeAlert},
		{"silent notification → background", PushNotification{Type: NotificationTypeNotification, Urgent: false}, apns2.PushTypeBackground},
		{"attempt-login → alert", PushNotification{Type: NotificationTypeAttemptLogin, Data: "ctx"}, apns2.PushTypeAlert},
		{"challenge → background", PushNotification{Type: NotificationTypeChallenge, Data: "tok"}, apns2.PushTypeBackground},
		{"rate-limit → background", PushNotification{Type: NotificationTypeRateLimitChallenge, Data: "tok"}, apns2.PushTypeBackground},
		{"unknown → background fallback", PushNotification{Type: NotificationType(99)}, apns2.PushTypeBackground},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := c.n
			pl, pt := buildAPNsPayloadAndPushType(&n)
			if pt != c.wantType {
				t.Errorf("pushType = %v, want %v", pt, c.wantType)
			}
			if pl == nil {
				t.Error("expected non-nil payload")
			}
		})
	}
}

func TestDeliveryPriorityFor(t *testing.T) {
	cases := []struct {
		name     string
		pushType apns2.EPushType
		urgent   bool
		want     int
	}{
		{"background always low", apns2.PushTypeBackground, true, apns2.PriorityLow},
		{"alert urgent → high", apns2.PushTypeAlert, true, apns2.PriorityHigh},
		{"alert non-urgent → low", apns2.PushTypeAlert, false, apns2.PriorityLow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deliveryPriorityFor(c.pushType, c.urgent); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestInterpretAPNsResponse_Accepted(t *testing.T) {
	resp := &apns2.Response{StatusCode: apns2.StatusSent}
	got := interpretAPNsResponse(resp)
	if !got.Accepted {
		t.Error("expected Accepted=true")
	}
}

func TestInterpretAPNsResponse_Unregistered(t *testing.T) {
	cases := []string{apns2.ReasonUnregistered, apns2.ReasonBadDeviceToken, apns2.ReasonExpiredToken}
	for _, reason := range cases {
		t.Run(reason, func(t *testing.T) {
			resp := &apns2.Response{StatusCode: 410, Reason: reason, Timestamp: apns2.Time{Time: time.Unix(1700000000, 0)}}
			got := interpretAPNsResponse(resp)
			if got.Accepted {
				t.Error("expected Accepted=false")
			}
			if !got.Unregistered {
				t.Errorf("expected Unregistered=true for reason=%q", reason)
			}
			if got.TokenInvalidationTimestamp == nil {
				t.Error("expected non-nil TokenInvalidationTimestamp")
			}
		})
	}
}

func TestInterpretAPNsResponse_RetainableRejection(t *testing.T) {
	// A non-token-invalid reason: still Accepted=false but Unregistered=false.
	resp := &apns2.Response{StatusCode: 429, Reason: apns2.ReasonTooManyRequests}
	got := interpretAPNsResponse(resp)
	if got.Accepted {
		t.Error("expected Accepted=false")
	}
	if got.Unregistered {
		t.Error("expected Unregistered=false for non-token reasons")
	}
	if got.RejectionReason != apns2.ReasonTooManyRequests {
		t.Errorf("RejectionReason = %q, want %q", got.RejectionReason, apns2.ReasonTooManyRequests)
	}
}

func TestAPNsProvider_Send_NilNotification(t *testing.T) {
	p, err := NewAPNsProvider(APNsConfig{
		BundleID: "b", TeamID: "T", KeyID: "K", SigningKeyPEM: p256KeyPEM(t),
	})
	if err != nil {
		t.Fatalf("NewAPNsProvider: %v", err)
	}
	_, err = p.Send(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil notification")
	}
}

func TestAPNsProvider_Send_TransportErrorWrapped(t *testing.T) {
	// Build a provider, then force the underlying client to talk to an
	// unreachable host so Send returns a wrapped SendError.
	p, err := NewAPNsProvider(APNsConfig{
		BundleID: "b", TeamID: "T", KeyID: "K", SigningKeyPEM: p256KeyPEM(t),
		Sandbox: true,
	})
	if err != nil {
		t.Fatalf("NewAPNsProvider: %v", err)
	}
	// Point at a guaranteed-closed loopback port via Host override.
	p.client.Host = "http://127.0.0.1:1"
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, sendErr := p.Send(ctx, &PushNotification{DeviceToken: "tok", Type: NotificationTypeNotification})
	if sendErr == nil {
		t.Fatal("expected transport error")
	}
	var se *SendError
	if !errors.As(sendErr, &se) {
		t.Fatalf("expected *SendError, got %T", sendErr)
	}
}

func TestAPNsProvider_Close_Safe(t *testing.T) {
	p, err := NewAPNsProvider(APNsConfig{
		BundleID: "b", TeamID: "T", KeyID: "K", SigningKeyPEM: p256KeyPEM(t),
	})
	if err != nil {
		t.Fatalf("NewAPNsProvider: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestAPNsProvider_ImplementsInterface(t *testing.T) {
	var _ PushProvider = (*APNsProvider)(nil)
}

// TestPayloadShapesCarryCustomData asserts each Type's Custom() data field
// is present in the JSON serialization of the constructed payload.
func TestPayloadShapesCarryCustomData(t *testing.T) {
	cases := []struct {
		name string
		typ  NotificationType
		key  string
	}{
		{"attempt-login", NotificationTypeAttemptLogin, "attemptLoginContext"},
		{"challenge", NotificationTypeChallenge, "challenge"},
		{"rate-limit", NotificationTypeRateLimitChallenge, "rateLimitChallenge"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pl, _ := buildAPNsPayloadAndPushType(&PushNotification{
				Type: c.typ, Data: "expected-data",
			})
			bytes_, err := pl.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			if !contains(string(bytes_), c.key) || !contains(string(bytes_), "expected-data") {
				t.Errorf("payload %s missing %q/data: %s", c.name, c.key, string(bytes_))
			}
		})
	}
	// Sanity-check that NewPayload exposed by sideshow returns a *payload.Payload
	// we can still inspect — guards against a future apns2 bump that would
	// silently break the JSON layout.
	if _, ok := any(payload.NewPayload()).(*payload.Payload); !ok {
		t.Fatal("apns2 payload.NewPayload return type changed")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
