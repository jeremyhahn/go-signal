package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/auth"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/inprocess"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/registration/sessionshim"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// createVerifiedSession creates a verification session for the given phone
// number, delivers the code via the noop transport, and submits it so the
// session is in the Verified state. It returns the session ID for inclusion
// in registration request bodies. Fails the test on any error.
func createVerifiedSession(t *testing.T, s *Server, transport *noopVerificationTransport, number string) string {
	t.Helper()
	ctx := context.Background()

	session, err := s.verification.CreateSession(ctx, number)
	if err != nil {
		t.Fatalf("createVerifiedSession: CreateSession failed: %v", err)
	}

	_, err = s.verification.SendCode(ctx, session.ID)
	if err != nil {
		t.Fatalf("createVerifiedSession: SendCode failed: %v", err)
	}

	code := transport.LastCode(number)
	if code == "" {
		t.Fatal("createVerifiedSession: no code delivered to transport")
	}

	_, err = s.verification.SubmitCode(ctx, session.ID, code)
	if err != nil {
		t.Fatalf("createVerifiedSession: SubmitCode failed: %v", err)
	}

	return session.ID
}

// newTestServerForExpiredSession creates a server with a 1ms session TTL so
// that sessions expire almost immediately. Returns the server, the transport,
// and a created session ID for number. After time.Sleep(2ms) the session will
// be expired.
func newTestServerForExpiredSession(t *testing.T, number string) (*Server, string) {
	t.Helper()
	ctx := context.Background()

	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	coreSvc := core.NewService(store, transport, core.Config{
		CodeLength:  6,
		CodeTTL:     time.Millisecond,
		SessionTTL:  time.Millisecond,
		MaxAttempts: 3,
	})
	t.Cleanup(coreSvc.Shutdown)
	verificationMgr := sessionshim.NewShim(sessionshim.Config{
		Client:       inprocess.New(coreSvc),
		CaptchaStore: sessionshim.NewMemoryCaptchaStore(),
	})

	s := buildTestServerWithVerificationMgr(t, verificationMgr)

	session, err := verificationMgr.CreateSession(ctx, number)
	if err != nil {
		t.Fatalf("newTestServerForExpiredSession: CreateSession failed: %v", err)
	}

	// Wait for the session to expire (TTL is 1ms).
	time.Sleep(5 * time.Millisecond)

	return s, session.ID
}

// registrationBodyWithRealKeys builds a valid registration JSON body using
// real Curve25519 key pairs and XEdDSA signatures from the shared test key
// material. The body is suitable for POST /v1/registration.
func registrationBodyWithRealKeys(km *signalKeyMaterial, sessionID string) string {
	return `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {
			"fetchesMessages": true,
			"registrationId": 12345,
			"pniRegistrationId": 54321,
			"name": "Test Device",
			"capabilities": {"storage": true, "transfer": true}
		},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "` + km.ACISignedPreKeyPubB64 + `",
			"signature": "` + km.ACISignedPreKeySigB64 + `"
		},
		"pniSignedPreKey": {
			"keyId": 2,
			"publicKey": "` + km.PNISignedPreKeyPubB64 + `",
			"signature": "` + km.PNISignedPreKeySigB64 + `"
		},
		"aciPqLastResortPreKey": {
			"keyId": 3,
			"publicKey": "` + km.ACIPqPubB64 + `",
			"signature": "` + km.ACIPqSigB64 + `"
		},
		"pniPqLastResortPreKey": {
			"keyId": 4,
			"publicKey": "` + km.PNIPqPubB64 + `",
			"signature": "` + km.PNIPqSigB64 + `"
		}
	}`
}

// registrationBodyWithPIN returns a complete valid registration JSON body using
// real key material. If pin is non-empty it is included in accountAttributes.registrationLock.
func registrationBodyWithPIN(km *signalKeyMaterial, sessionID, pin string) string {
	lockField := ""
	if pin != "" {
		lockField = `"registrationLock":"` + pin + `",`
	}
	return `{
		"sessionId": "` + sessionID + `",
		"accountAttributes":{
			"fetchesMessages":true,
			"registrationId":111,
			` + lockField + `
			"capabilities":{}
		},
		"aciIdentityKey":"` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey":"` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey":{"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey":{"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey":{"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey":{"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`
}

// doRegistration sends a POST /v1/registration request to s and returns the recorder.
// It creates and completes a verification session for number before sending the
// registration request so that the verification gate is satisfied.
func doRegistration(t *testing.T, s *Server, transport *noopVerificationTransport, number, password, pin string) *httptest.ResponseRecorder {
	t.Helper()
	sessionID := createVerifiedSession(t, s, transport, number)
	km := getTestKeyMaterial(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/registration",
		strings.NewReader(registrationBodyWithPIN(km, sessionID, pin)))
	req.SetBasicAuth(number, password)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func TestHandleRegistration_Success(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15551234567"
	sessionID := createVerifiedSession(t, s, transport, number)
	body := registrationBodyWithRealKeys(km, sessionID)

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp AccountCreationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.UUID == "" {
		t.Error("expected non-empty UUID")
	}
	if resp.PNI == "" {
		t.Error("expected non-empty PNI")
	}
	if !resp.StorageCapable {
		t.Error("expected StorageCapable to be true")
	}
}

func TestHandleRegistration_InvalidSignature_Returns422(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15550123456"
	sessionID := createVerifiedSession(t, s, transport, number)

	// Build a registration body but use a bad (all-zeros) ACI signed pre-key signature.
	badSig := make([]byte, 64)
	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "` + km.ACISignedPreKeyPubB64 + `",
			"signature": "` + encodeB64(badSig) + `"
		},
		"pniSignedPreKey": {
			"keyId": 2,
			"publicKey": "` + km.PNISignedPreKeyPubB64 + `",
			"signature": "` + km.PNISignedPreKeySigB64 + `"
		},
		"aciPqLastResortPreKey": {
			"keyId": 3,
			"publicKey": "` + km.ACIPqPubB64 + `",
			"signature": "` + km.ACIPqSigB64 + `"
		},
		"pniPqLastResortPreKey": {
			"keyId": 4,
			"publicKey": "` + km.PNIPqPubB64 + `",
			"signature": "` + km.PNIPqSigB64 + `"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidPniSignature_Returns422(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15550123457"
	sessionID := createVerifiedSession(t, s, transport, number)

	badSig := encodeB64(make([]byte, 64))
	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "` + km.ACISignedPreKeyPubB64 + `",
			"signature": "` + km.ACISignedPreKeySigB64 + `"
		},
		"pniSignedPreKey": {
			"keyId": 2,
			"publicKey": "` + km.PNISignedPreKeyPubB64 + `",
			"signature": "` + badSig + `"
		},
		"aciPqLastResortPreKey": {
			"keyId": 3,
			"publicKey": "` + km.ACIPqPubB64 + `",
			"signature": "` + km.ACIPqSigB64 + `"
		},
		"pniPqLastResortPreKey": {
			"keyId": 4,
			"publicKey": "` + km.PNIPqPubB64 + `",
			"signature": "` + km.PNIPqSigB64 + `"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidAciPqSignature_Returns422(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15550123458"
	sessionID := createVerifiedSession(t, s, transport, number)

	badSig := encodeB64(make([]byte, 64))
	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "` + km.ACISignedPreKeyPubB64 + `",
			"signature": "` + km.ACISignedPreKeySigB64 + `"
		},
		"pniSignedPreKey": {
			"keyId": 2,
			"publicKey": "` + km.PNISignedPreKeyPubB64 + `",
			"signature": "` + km.PNISignedPreKeySigB64 + `"
		},
		"aciPqLastResortPreKey": {
			"keyId": 3,
			"publicKey": "` + km.ACIPqPubB64 + `",
			"signature": "` + badSig + `"
		},
		"pniPqLastResortPreKey": {
			"keyId": 4,
			"publicKey": "` + km.PNIPqPubB64 + `",
			"signature": "` + km.PNIPqSigB64 + `"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidPniPqSignature_Returns422(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15550123459"
	sessionID := createVerifiedSession(t, s, transport, number)

	badSig := encodeB64(make([]byte, 64))
	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "` + km.ACISignedPreKeyPubB64 + `",
			"signature": "` + km.ACISignedPreKeySigB64 + `"
		},
		"pniSignedPreKey": {
			"keyId": 2,
			"publicKey": "` + km.PNISignedPreKeyPubB64 + `",
			"signature": "` + km.PNISignedPreKeySigB64 + `"
		},
		"aciPqLastResortPreKey": {
			"keyId": 3,
			"publicKey": "` + km.ACIPqPubB64 + `",
			"signature": "` + km.ACIPqSigB64 + `"
		},
		"pniPqLastResortPreKey": {
			"keyId": 4,
			"publicKey": "` + km.PNIPqPubB64 + `",
			"signature": "` + badSig + `"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_MissingBasicAuth(t *testing.T) {
	s := newTestServer(t)

	body := `{"accountAttributes":{},"aciIdentityKey":"","pniIdentityKey":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader("not json"))
	req.SetBasicAuth("+15551234567", "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidAciIdentityKeyBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15551234567"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {},
		"aciIdentityKey": "!!!not-base64!!!",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `"
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidPniIdentityKeyBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15551234567"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "!!!not-base64!!!"
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidAciSignedPreKeyBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15551234567"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "!!!not-base64!!!",
			"signature": "` + testSignedPreKeySigB64 + `"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidAciSignedPreKeySigBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15551234567"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "` + testSignedPreKeyPubB64 + `",
			"signature": "!!!not-base64!!!"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidUAKBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15551234567"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {
			"unidentifiedAccessKey": "!!!not-base64!!!"
		},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"aciSignedPreKey": {
			"keyId": 1,
			"publicKey": "` + testSignedPreKeyPubB64 + `",
			"signature": "` + testSignedPreKeySigB64 + `"
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_ReRegistrationDeletesExisting(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15559999999"

	// First registration.
	sessionID1 := createVerifiedSession(t, s, transport, number)
	body := `{
		"sessionId": "` + sessionID1 + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req1 := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req1.SetBasicAuth(number, "pass1")
	rr1 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d: %s", rr1.Code, rr1.Body.String())
	}

	// Second registration with same number — needs a fresh verified session.
	sessionID2 := createVerifiedSession(t, s, transport, number)
	body2 := `{
		"sessionId": "` + sessionID2 + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req2 := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body2))
	req2.SetBasicAuth(number, "pass2")
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("re-registration failed: %d: %s", rr2.Code, rr2.Body.String())
	}

	var resp1, resp2 AccountCreationResponse
	if err := json.Unmarshal(rr1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp1.UUID == resp2.UUID {
		t.Error("expected different UUIDs for re-registration")
	}
}

func TestDeviceCapabilitiesFromMap(t *testing.T) {
	caps := deviceCapabilitiesFromMap(map[string]bool{
		"storage":  true,
		"transfer": true,
	})
	if !caps.Storage {
		t.Error("expected Storage to be true")
	}
	if !caps.Transfer {
		t.Error("expected Transfer to be true")
	}
	if caps.PaymentActivation {
		t.Error("expected PaymentActivation to be false")
	}
}

func TestDeviceCapabilitiesFromMap_NilMap(t *testing.T) {
	caps := deviceCapabilitiesFromMap(nil)
	if caps.Storage || caps.Transfer || caps.PaymentActivation {
		t.Error("expected all capabilities to be false for nil map")
	}
}

func TestCapabilityValue_Present(t *testing.T) {
	m := map[string]bool{"storage": true}
	if !capabilityValue(m, "storage") {
		t.Error("expected true for present key")
	}
}

func TestCapabilityValue_Missing(t *testing.T) {
	m := map[string]bool{"storage": true}
	if capabilityValue(m, "transfer") {
		t.Error("expected false for missing key")
	}
}

func TestCapabilityValue_NilMap(t *testing.T) {
	if capabilityValue(nil, "storage") {
		t.Error("expected false for nil map")
	}
}

func TestHandleRegistration_EmptyPassword(t *testing.T) {
	s := newTestServer(t)

	body := `{"accountAttributes":{}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth("+15551234567", "")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ===========================================================================
// Registration Lock Enforcement Tests
// ===========================================================================

// lockTestNumber is the E.164 number used by registration lock tests to avoid
// collisions with other test fixtures.
const lockTestNumber = "+15558675309"

// setupAccountWithLock registers lockTestNumber and then sets an Argon2id
// registration lock with the given PIN on the resulting account.
func setupAccountWithLock(t *testing.T, s *Server, transport *noopVerificationTransport, pin string) {
	t.Helper()

	rr := doRegistration(t, s, transport, lockTestNumber, "initial-pw", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("initial registration failed: %d %s", rr.Code, rr.Body.String())
	}

	acct, err := s.accounts.GetByNumber(context.Background(), lockTestNumber)
	if err != nil {
		t.Fatalf("GetByNumber failed: %v", err)
	}

	lockHash, err := auth.HashRegistrationLock(pin)
	if err != nil {
		t.Fatalf("HashRegistrationLock failed: %v", err)
	}
	acct.RegistrationLockHash = lockHash
	if err := s.accounts.Update(context.Background(), acct); err != nil {
		t.Fatalf("Update with lock hash failed: %v", err)
	}
}

func TestHandleRegistration_NoExistingAccount_Succeeds(t *testing.T) {
	s, transport := newTestServerWithVerification(t)

	rr := doRegistration(t, s, transport, "+15550001111", "pw", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_ExistingAccountNoLock_Succeeds(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15550002222"

	// First registration — no lock.
	if rr := doRegistration(t, s, transport, number, "pw1", ""); rr.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d %s", rr.Code, rr.Body.String())
	}

	// Re-registration without PIN — should succeed because no lock is set.
	if rr := doRegistration(t, s, transport, number, "pw2", ""); rr.Code != http.StatusOK {
		t.Fatalf("re-registration without lock failed: %d %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_ExistingAccountWithLockAndCorrectPIN_Succeeds(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const pin = "correct-pin-123"
	setupAccountWithLock(t, s, transport, pin)

	rr := doRegistration(t, s, transport, lockTestNumber, "new-password", pin)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct PIN, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_ExistingAccountWithLockAndWrongPIN_Returns423(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	setupAccountWithLock(t, s, transport, "correct-pin")

	rr := doRegistration(t, s, transport, lockTestNumber, "new-password", "wrong-pin")
	if rr.Code != http.StatusLocked {
		t.Fatalf("expected 423, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_ExistingAccountWithLockAndNoPIN_Returns423(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	setupAccountWithLock(t, s, transport, "the-pin")

	// No PIN supplied — empty string is rejected by Verify.
	rr := doRegistration(t, s, transport, lockTestNumber, "new-password", "")
	if rr.Code != http.StatusLocked {
		t.Fatalf("expected 423, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_LockedResponse_ContainsTimeRemaining(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	setupAccountWithLock(t, s, transport, "some-pin")

	rr := doRegistration(t, s, transport, lockTestNumber, "pw", "wrong")
	if rr.Code != http.StatusLocked {
		t.Fatalf("expected 423, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp RegistrationLockErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal 423 response: %v", err)
	}
	if resp.TimeRemaining <= 0 {
		t.Errorf("timeRemaining = %d, want > 0", resp.TimeRemaining)
	}
}

// ===========================================================================
// Verification Enforcement Tests
// ===========================================================================

func TestHandleRegistration_MissingSessionID_Returns400(t *testing.T) {
	s := newTestServer(t)
	km := getTestKeyMaterial(t)

	// Build a body without a sessionId field.
	body := `{
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth("+15550011111", "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_NonExistentSessionID_Returns403(t *testing.T) {
	s := newTestServer(t)
	km := getTestKeyMaterial(t)

	body := `{
		"sessionId": "00000000-0000-0000-0000-000000000000",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth("+15550022222", "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_UnverifiedSession_Returns403(t *testing.T) {
	s, _ := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15550033333"

	// Create a session but do NOT submit a code — the session is not Verified.
	session, err := s.verification.CreateSession(context.Background(), number)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	body := `{
		"sessionId": "` + session.ID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_ExpiredSession_Returns403(t *testing.T) {
	km := getTestKeyMaterial(t)
	const number = "+15550044444"

	s, sessionID := newTestServerForExpiredSession(t, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_SessionNumberMismatch_Returns403(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)

	// Create a verified session for a different number.
	const sessionNumber = "+15550055555"
	const registrationNumber = "+15550066666"
	sessionID := createVerifiedSession(t, s, transport, sessionNumber)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 1},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	// Register with a different number than the session's number.
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(registrationNumber, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_VerifiedSessionMatchingNumber_Succeeds(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15550077777"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := registrationBodyWithRealKeys(km, sessionID)
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp AccountCreationResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.UUID == "" {
		t.Error("expected non-empty UUID")
	}
}

// ===========================================================================
// enforceVerifiedSession typed error tests
// ===========================================================================

func TestEnforceVerifiedSession_SessionNotFoundError(t *testing.T) {
	var e *SessionNotFoundError
	err := &SessionNotFoundError{ID: "abc"}
	if !errors.As(err, &e) {
		t.Fatal("expected *SessionNotFoundError")
	}
	if e.ID != "abc" {
		t.Errorf("expected ID abc, got %s", e.ID)
	}
}

func TestEnforceVerifiedSession_SessionPhoneNumberMismatchError(t *testing.T) {
	var e *SessionPhoneNumberMismatchError
	err := &SessionPhoneNumberMismatchError{SessionID: "xyz"}
	if !errors.As(err, &e) {
		t.Fatal("expected *SessionPhoneNumberMismatchError")
	}
	if e.SessionID != "xyz" {
		t.Errorf("expected SessionID xyz, got %s", e.SessionID)
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestEnforceVerifiedSession_SessionNotVerifiedError(t *testing.T) {
	var e *SessionNotVerifiedError
	err := &SessionNotVerifiedError{SessionID: "sess-1"}
	if !errors.As(err, &e) {
		t.Fatal("expected *SessionNotVerifiedError")
	}
	if e.SessionID != "sess-1" {
		t.Errorf("expected SessionID sess-1, got %s", e.SessionID)
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

// encodeB64 is a test helper to base64-encode bytes using standard encoding.
func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// --- Registration captcha wiring -----------------------------------------

// registrationBodyWithCaptcha appends a top-level captcha field to the
// standard registration body for handler-level captcha tests.
func registrationBodyWithCaptcha(km *signalKeyMaterial, sessionID, captchaToken string) string {
	return `{
		"sessionId": "` + sessionID + `",
		"captcha": "` + captchaToken + `",
		"accountAttributes":{
			"fetchesMessages":true,
			"registrationId":111,
			"capabilities":{}
		},
		"aciIdentityKey":"` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey":"` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey":{"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey":{"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey":{"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey":{"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`
}

func TestHandleRegistration_CaptchaAccepted(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	checker := buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: true, score: 0.9})
	s.captchaChecker = checker
	s.regCaptcha = captcha.NewRegistrationCaptchaManager(checker)

	km := getTestKeyMaterial(t)
	const number = "+15555550600"
	sessionID := createVerifiedSession(t, s, transport, number)
	body := registrationBodyWithCaptcha(km, sessionID, "recaptcha.sk.registration.opaque")

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_CaptchaRejected(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	checker := buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: false})
	s.captchaChecker = checker
	s.regCaptcha = captcha.NewRegistrationCaptchaManager(checker)

	km := getTestKeyMaterial(t)
	const number = "+15555550601"
	sessionID := createVerifiedSession(t, s, transport, number)
	body := registrationBodyWithCaptcha(km, sessionID, "recaptcha.sk.registration.opaque")

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 when captcha fails, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_CaptchaActionMismatchRejected(t *testing.T) {
	// Token has action=challenge but the registration handler expects
	// action=registration. RegistrationCaptchaManager.Assess must reject.
	s, transport := newTestServerWithVerification(t)
	checker := buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: true})
	s.captchaChecker = checker
	s.regCaptcha = captcha.NewRegistrationCaptchaManager(checker)

	km := getTestKeyMaterial(t)
	const number = "+15555550602"
	sessionID := createVerifiedSession(t, s, transport, number)
	body := registrationBodyWithCaptcha(km, sessionID, "recaptcha.sk.challenge.opaque")

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 on action mismatch, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_CaptchaWithoutCheckerReturns503(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	// Intentionally leave s.regCaptcha == nil.
	km := getTestKeyMaterial(t)
	const number = "+15555550603"
	sessionID := createVerifiedSession(t, s, transport, number)
	body := registrationBodyWithCaptcha(km, sessionID, "recaptcha.sk.registration.opaque")

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// recoveryPasswordSentinelError
// --------------------------------------------------------------------------

func TestRecoveryPasswordSentinel_Error(t *testing.T) {
	tests := []struct {
		reason   string
		expected string
	}{
		{"unsupported", "recovery password unsupported"},
		{"mismatch", "recovery password mismatch"},
		{"expired", "recovery password expired"},
		{"", "recovery password "},
	}
	for _, tc := range tests {
		t.Run(tc.reason, func(t *testing.T) {
			e := &recoveryPasswordSentinelError{Reason: tc.reason}
			got := e.Error()
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
