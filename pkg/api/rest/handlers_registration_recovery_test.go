package rest

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// registrationBodyWithRecoveryPassword returns a complete registration body
// that authorises via `recoveryPassword` instead of `sessionId`.
func registrationBodyWithRecoveryPassword(km *signalKeyMaterial, recoveryPasswordB64 string) string {
	return `{
		"recoveryPassword": "` + recoveryPasswordB64 + `",
		"accountAttributes":{"fetchesMessages":true,"registrationId":777,"capabilities":{}},
		"aciIdentityKey":"` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey":"` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey":{"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey":{"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey":{"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey":{"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`
}

// seedAccountWithRecoveryPassword creates an existing account for number,
// stores a recovery password against its PNI, and returns the password bytes
// (the cleartext input the client must reproduce on subsequent registrations).
func seedAccountWithRecoveryPassword(t *testing.T, s *Server, number string) (existingPNI string, password []byte) {
	t.Helper()
	ctx := context.Background()

	pni := "11111111-1111-4111-8111-aaaaaaaaaaaa"
	acct := &accounts.Account{
		UUID:        "00000000-0000-4000-8000-000000000001",
		PNI:         pni,
		Number:      number,
		IdentityKey: []byte("seed-identity-key"),
		Devices: []accounts.Device{{
			ID:        accounts.PrimaryDeviceID,
			AuthToken: "seed",
			SignedPreKey: &accounts.SignedPreKey{
				KeyID:     1,
				PublicKey: []byte("seed-spk-public-key"),
				Signature: []byte("seed-spk-signature"),
			},
		}},
	}
	if err := s.accounts.Create(ctx, acct); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	password = []byte("recovery-bytes-32-chars-for-test")
	if err := s.recoveryPasswords.Store(ctx, pni, password); err != nil {
		t.Fatalf("seed recovery password: %v", err)
	}
	return pni, password
}

func TestHandleRegistration_RecoveryPasswordSucceeds(t *testing.T) {
	s := newTestServer(t)
	const number = "+15551112222"
	_, pwd := seedAccountWithRecoveryPassword(t, s, number)
	km := getTestKeyMaterial(t)

	body := registrationBodyWithRecoveryPassword(km, base64.StdEncoding.EncodeToString(pwd))
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_RecoveryPasswordWrongValueReturns403(t *testing.T) {
	s := newTestServer(t)
	const number = "+15551112223"
	seedAccountWithRecoveryPassword(t, s, number)
	km := getTestKeyMaterial(t)

	body := registrationBodyWithRecoveryPassword(km, base64.StdEncoding.EncodeToString([]byte("wrong-password-bytes")))
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong recovery password, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_RecoveryPasswordNoExistingAccountReturns403(t *testing.T) {
	s := newTestServer(t)
	km := getTestKeyMaterial(t)

	body := registrationBodyWithRecoveryPassword(km, base64.StdEncoding.EncodeToString([]byte("any")))
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth("+15551112224", "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when no account exists, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_RecoveryPasswordInvalidBase64Returns400(t *testing.T) {
	s := newTestServer(t)
	const number = "+15551112225"
	seedAccountWithRecoveryPassword(t, s, number)
	km := getTestKeyMaterial(t)

	body := registrationBodyWithRecoveryPassword(km, "!!!not-base64!!!")
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid base64, got %d", rr.Code)
	}
}

func TestHandleRegistration_NeitherSessionNorRecoveryReturns400(t *testing.T) {
	s := newTestServer(t)
	km := getTestKeyMaterial(t)

	body := `{
		"accountAttributes":{"fetchesMessages":true,"registrationId":1,"capabilities":{}},
		"aciIdentityKey":"` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey":"` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey":{"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey":{"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey":{"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey":{"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth("+15551112226", "p")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when neither sessionId nor recoveryPassword supplied, got %d", rr.Code)
	}
}

func TestHandleRegistration_BothSessionAndRecoveryReturns400(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15551112227"
	_, pwd := seedAccountWithRecoveryPassword(t, s, number)
	km := getTestKeyMaterial(t)
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId":"` + sessionID + `",
		"recoveryPassword":"` + base64.StdEncoding.EncodeToString(pwd) + `",
		"accountAttributes":{"fetchesMessages":true,"registrationId":1,"capabilities":{}},
		"aciIdentityKey":"` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey":"` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey":{"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey":{"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey":{"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey":{"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "p")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when both sessionId and recoveryPassword are supplied, got %d", rr.Code)
	}
}

// TestHandleRegistration_StoresRecoveryPasswordFromAttributes confirms the
// post-registration store hook persists a recovery password supplied via
// accountAttributes.
func TestHandleRegistration_StoresRecoveryPasswordFromAttributes(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15551112228"
	sessionID := createVerifiedSession(t, s, transport, number)
	pwd := []byte("attribute-supplied-recovery-32!!")

	body := `{
		"sessionId":"` + sessionID + `",
		"accountAttributes":{
			"fetchesMessages":true,
			"registrationId":1,
			"recoveryPassword":"` + base64.StdEncoding.EncodeToString(pwd) + `",
			"capabilities":{}
		},
		"aciIdentityKey":"` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey":"` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey":{"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey":{"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey":{"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey":{"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The PNI used inside the registration handler is freshly generated for
	// each call. We can't predict it, so look up the stored account by
	// number and verify the recovery password against its PNI.
	acct, err := s.accounts.GetByNumber(context.Background(), number)
	if err != nil {
		t.Fatalf("GetByNumber: %v", err)
	}
	ok, err := s.recoveryPasswords.Verify(context.Background(), acct.PNI, pwd)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected the supplied recovery password to verify against the new PNI")
	}
}
