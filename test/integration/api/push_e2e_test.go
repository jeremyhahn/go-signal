//go:build integration

package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/push"
	"github.com/jeremyhahn/go-signal/pkg/verification/twilio"
	"github.com/jeremyhahn/go-signal/test/integration/mocks"
)

// TestPushE2E_FCM_WakesOfflineDevice exercises the full Phase 3 path:
//
//  1. Mount a fake FCM server.
//  2. Wire a push.PushManager whose FCM provider points at the mock.
//  3. Use PushManager.Send directly — equivalent to the offline-delivery
//     callback path in signald's start.go (`schedulePush`), which
//     selects the FCM provider for devices whose GcmRegistrationID is
//     set and whose FetchesMessages flag is false.
//  4. Assert the mock received exactly one POST with the right device
//     token, OAuth2 Bearer header, and HIGH priority for an urgent
//     notification.
//
// This is the in-process equivalent of the Java reference flow:
// "account registered → receives push notification when offline →
// opens WebSocket → drains queue". The WebSocket-drain half is covered
// by TestWebSocket_* in this package; this test asserts the push half.
func TestPushE2E_FCM_WakesOfflineDevice(t *testing.T) {
	fcmSrv := mocks.NewFCMMock()
	t.Cleanup(fcmSrv.Close)

	provider, err := push.NewFCMProvider(push.FCMConfig{
		ProjectID:          "test-project",
		ServiceAccountJSON: fakeServiceAccountJSON(t),
		TokenEndpoint:      fcmSrv.TokenURL(),
		SendEndpoint:       fcmSrv.SendURL("test-project"),
	})
	if err != nil {
		t.Fatalf("NewFCMProvider: %v", err)
	}
	mgr := push.NewPushManager(push.PushManagerConfig{FCM: provider, RetryAttempts: 1})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := mgr.Send(ctx, &push.PushNotification{
		AccountUUID: "11111111-1111-1111-1111-111111111111",
		DeviceID:    1,
		DeviceToken: "device-fcm-token",
		DeviceType:  push.DeviceTypeFCM,
		Type:        push.NotificationTypeNotification,
		Urgent:      true,
	})
	if err != nil {
		t.Fatalf("PushManager.Send: %v", err)
	}
	if !res.Accepted {
		t.Errorf("expected Accepted=true; got %+v", res)
	}

	// Cross-check the mock saw exactly the right request.
	if got := fcmSrv.SendsReceived(); got != 1 {
		t.Errorf("FCM mock received %d sends, want 1", got)
	}
	if got := fcmSrv.TokensIssued(); got != 1 {
		t.Errorf("FCM mock issued %d OAuth2 tokens, want 1", got)
	}
	auth, body := fcmSrv.LastSend()
	if auth != "Bearer mock-access-token" {
		t.Errorf("Authorization = %q", auth)
	}
	if !strings.Contains(string(body), `"device-fcm-token"`) {
		t.Errorf("body missing device token: %s", body)
	}
	if !strings.Contains(string(body), `"HIGH"`) {
		t.Errorf("urgent send must have HIGH priority: %s", body)
	}
	if !strings.Contains(string(body), `"newMessageAlert"`) {
		t.Errorf("body missing notification data key: %s", body)
	}
}

// TestPushE2E_FCM_UnregisteredTokenSurfaces drives the unregistered-token
// path: the mock returns 404 + UNREGISTERED detail; the manager must
// surface Accepted=false and Unregistered=true so the production
// caller (cmd/signald/start.go schedulePush) can clear the stale token.
func TestPushE2E_FCM_UnregisteredTokenSurfaces(t *testing.T) {
	fcmSrv := mocks.NewFCMMock()
	t.Cleanup(fcmSrv.Close)
	fcmSrv.SetNextSendResponse(404, `{
        "error": {
            "code": 404, "status": "NOT_FOUND",
            "message": "Requested entity was not found.",
            "details": [{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]
        }
    }`)

	provider, err := push.NewFCMProvider(push.FCMConfig{
		ProjectID:          "p",
		ServiceAccountJSON: fakeServiceAccountJSON(t),
		TokenEndpoint:      fcmSrv.TokenURL(),
		SendEndpoint:       fcmSrv.SendURL("p"),
	})
	if err != nil {
		t.Fatalf("NewFCMProvider: %v", err)
	}
	mgr := push.NewPushManager(push.PushManagerConfig{FCM: provider, RetryAttempts: 1})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := mgr.Send(ctx, &push.PushNotification{
		DeviceToken: "stale-token",
		DeviceType:  push.DeviceTypeFCM,
		Type:        push.NotificationTypeNotification,
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if res.Accepted {
		t.Error("expected Accepted=false for UNREGISTERED")
	}
	if !res.Unregistered {
		t.Errorf("expected Unregistered=true; got %+v", res)
	}
	if res.RejectionReason != "UNREGISTERED" {
		t.Errorf("RejectionReason = %q", res.RejectionReason)
	}
}

// TestTwilioE2E_MockVerifyFlow exercises register-via-Twilio against the
// MockTwilio server. Mirrors the Phase 3.2 production flow:
//
//	twilio.SendCode → Twilio mints a code → server pre-shares with mock
//	twilio.Verify(submitted) → mock reports approved
//
// The real Twilio Verify owns code generation; the server never sees
// the code. Our mock issues a deterministic "123456" and the test
// pre-Approves that pairing.
func TestTwilioE2E_MockVerifyFlow(t *testing.T) {
	twSrv := mocks.NewTwilioMock()
	t.Cleanup(twSrv.Close)

	tr, err := twilio.NewTransport(t.Context(), twilio.Config{
		AccountSID: "ACtest",
		AuthToken:  secrets.MustNewSecureString(t.Context(), "auth-secret"),
		ServiceSID: "VAtest",
		BaseURL:    twSrv.URL(),
	})
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const dest = "+15551112222"
	if err := tr.SendCode(ctx, dest, "ignored-by-twilio"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}

	// Approve the issued (dest, code) pair so Verify returns approved.
	_, _, code := twSrv.LastSend()
	twSrv.Approve(dest, code)

	approved, err := tr.Verify(ctx, dest, code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !approved {
		t.Error("expected approved=true")
	}

	// Submitting the wrong code stays pending → approved=false.
	pendingOK, err := tr.Verify(ctx, dest, "000000")
	if err != nil {
		t.Fatalf("Verify (wrong code): %v", err)
	}
	if pendingOK {
		t.Error("wrong code must NOT report approved")
	}
}

// fakeServiceAccountJSON returns a service-account JSON envelope with a
// freshly generated RSA-2048 private key. The key is real (the FCM
// provider will load it via x509.MarshalPKCS8PrivateKey), but the mock
// FCM server doesn't validate the assertion signature so the body
// contents are otherwise arbitrary.
func fakeServiceAccountJSON(t *testing.T) []byte {
	t.Helper()
	pem, err := generateRSAKeyPEM()
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	sa := map[string]string{
		"client_email": "test@signal-server.iam.gserviceaccount.com",
		"private_key":  pem,
	}
	out, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal service account: %v", err)
	}
	return out
}
