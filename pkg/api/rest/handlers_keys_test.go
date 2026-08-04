package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

var _ = context.Background // suppress unused import if needed

// --------------------------------------------------------------------------
// handleGetPreKeyCount
// --------------------------------------------------------------------------

func TestHandleGetPreKeyCount_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store some EC pre-keys via StoreKeys.
	ecKeys := []*keys.PreKey{
		{KeyID: 10, PublicKey: []byte("pk1")},
		{KeyID: 11, PublicKey: []byte("pk2")},
	}
	setReq := &keys.SetKeysRequest{PreKeys: ecKeys}
	if err := s.keys.StoreKeys(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, setReq); err != nil {
		t.Fatalf("failed to store EC pre-keys: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PreKeyCountResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("expected EC count 2, got %d", resp.Count)
	}
}

func TestHandleGetPreKeyCount_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleUploadKeys
// --------------------------------------------------------------------------

func TestHandleUploadKeys_Success(t *testing.T) {
	s, _, km := newTestServerWithRealKeys(t)

	// Generate a new signed pre-key signed with the ACI identity key.
	newSPKKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate new SPK: %v", err)
	}
	newSPKPub := newSPKKP.PublicKey().Serialize()
	newSPKSigArr, err := ecc.CalculateSignature(km.ACIKeyPair.PrivateKey(), newSPKPub)
	if err != nil {
		t.Fatalf("failed to sign new SPK: %v", err)
	}
	newSPKSig := newSPKSigArr[:]

	// Generate a new KEM pre-key signed with the ACI identity key.
	kemPub := make([]byte, 32)
	for i := range kemPub {
		kemPub[i] = byte(i + 100)
	}
	kemSigArr, err := ecc.CalculateSignature(km.ACIKeyPair.PrivateKey(), kemPub)
	if err != nil {
		t.Fatalf("failed to sign KEM key: %v", err)
	}
	kemSig := kemSigArr[:]

	// One-time EC pre-key (no signature required).
	ecPub := base64.StdEncoding.EncodeToString(newSPKPub)

	body := `{
		"preKeys": [{"keyId": 100, "publicKey": "` + ecPub + `"}],
		"signedPreKey": {"keyId": 200, "publicKey": "` + base64.StdEncoding.EncodeToString(newSPKPub) + `", "signature": "` + base64.StdEncoding.EncodeToString(newSPKSig) + `"},
		"pqPreKeys": [{"keyId": 300, "publicKey": "` + base64.StdEncoding.EncodeToString(kemPub) + `", "signature": "` + base64.StdEncoding.EncodeToString(kemSig) + `"}],
		"pqLastResortPreKey": {"keyId": 400, "publicKey": "` + base64.StdEncoding.EncodeToString(kemPub) + `", "signature": "` + base64.StdEncoding.EncodeToString(kemSig) + `"}
	}`

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUploadKeys_InvalidSignedPreKeySignature(t *testing.T) {
	s, _, _ := newTestServerWithRealKeys(t)

	// Use a valid public key but a garbage signature.
	newSPKKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	spkPub := base64.StdEncoding.EncodeToString(newSPKKP.PublicKey().Serialize())
	badSig := base64.StdEncoding.EncodeToString(make([]byte, 64))

	body := `{
		"signedPreKey": {"keyId": 200, "publicKey": "` + spkPub + `", "signature": "` + badSig + `"}
	}`

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUploadKeys_InvalidKEMPreKeySignature(t *testing.T) {
	s, _, _ := newTestServerWithRealKeys(t)

	// Valid KEM public key but invalid signature.
	kemPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	badSig := base64.StdEncoding.EncodeToString(make([]byte, 64))

	body := `{
		"pqPreKeys": [{"keyId": 300, "publicKey": "` + kemPub + `", "signature": "` + badSig + `"}]
	}`

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUploadKeys_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleUploadKeys_InvalidBase64InPreKey(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"preKeys": [{"keyId": 1, "publicKey": "!!!not-base64!!!"}]}`
	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUploadKeys_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetPreKeys
// --------------------------------------------------------------------------

func TestHandleGetPreKeys_SingleDevice(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/1", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PreKeyResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.IdentityKey != testIdentityKeyB64 {
		t.Errorf("expected identity key %s, got %s", testIdentityKeyB64, resp.IdentityKey)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(resp.Devices))
	}
	if resp.Devices[0].DeviceId != accounts.PrimaryDeviceID {
		t.Errorf("expected device ID %d, got %d", accounts.PrimaryDeviceID, resp.Devices[0].DeviceId)
	}
}

func TestHandleGetPreKeys_AllDevices(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/*", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetPreKeys_AccountNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Use a well-formed UUID that does not exist in the store so that the
	// handler passes identifier validation and returns 404 (not 400).
	req := httptest.NewRequest(http.MethodGet, "/v2/keys/00000000-0000-0000-0000-000000000000/1", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetPreKeys_InvalidIdentifier(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Non-UUID, non-E.164 identifier must be rejected with 400.
	req := httptest.NewRequest(http.MethodGet, "/v2/keys/not-valid-at-all/1", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetPreKeys_InvalidDeviceId(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/abc", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetPreKeys_DeviceNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/99", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetPreKeys_ByNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountNumber+"/1", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// Last-resort pre-key behaviour
// --------------------------------------------------------------------------

func TestHandleGetPreKeyCount_HasLastResort(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store a last-resort KEM pre-key via the manager.
	lrKey := &keys.KEMSignedPreKey{KeyID: 99, PublicKey: []byte("lr-pub"), Signature: []byte("lr-sig"), IsLastResort: true}
	if err := s.keys.StoreKEMLastResortPreKey(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, lrKey); err != nil {
		t.Fatalf("failed to store last-resort pre-key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PreKeyCountResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if !resp.HasLastResort {
		t.Error("expected HasLastResort=true after storing last-resort key")
	}
}

func TestHandleGetPreKeyCount_HasLastResort_False_WhenNotSet(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PreKeyCountResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.HasLastResort {
		t.Error("expected HasLastResort=false when no last-resort key is stored")
	}
}

func TestHandleUploadKeys_LastResortStoredSeparately(t *testing.T) {
	s, _, km := newTestServerWithRealKeys(t)

	kemPub := make([]byte, 32)
	for i := range kemPub {
		kemPub[i] = byte(i + 50)
	}
	kemSigArr, err := ecc.CalculateSignature(km.ACIKeyPair.PrivateKey(), kemPub)
	if err != nil {
		t.Fatalf("failed to sign KEM key: %v", err)
	}
	kemSig := kemSigArr[:]

	body := `{
		"pqLastResortPreKey": {"keyId": 400, "publicKey": "` + base64.StdEncoding.EncodeToString(kemPub) + `", "signature": "` + base64.StdEncoding.EncodeToString(kemSig) + `"}
	}`

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify the key count shows a last-resort key.
	countReq := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	countReq.SetBasicAuth(testAccountUUID, testAuthToken)
	countRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(countRR, countReq)

	var countResp PreKeyCountResponse
	if err := json.Unmarshal(countRR.Body.Bytes(), &countResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if !countResp.HasLastResort {
		t.Error("expected HasLastResort=true after uploading last-resort key")
	}
	// One-time KEM count must remain 0.
	if countResp.PqCount != 0 {
		t.Errorf("expected PqCount=0 (last-resort stored separately), got %d", countResp.PqCount)
	}
}

func TestHandleGetPreKeys_LastResortReturnedWhenOneTimeExhausted(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store a last-resort key; no one-time KEM keys.
	lrKey := &keys.KEMSignedPreKey{KeyID: 99, PublicKey: []byte("lr-pub-32bytesPADDING"), Signature: []byte("lr-sig"), IsLastResort: true}
	if err := s.keys.StoreKEMLastResortPreKey(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, lrKey); err != nil {
		t.Fatalf("failed to store last-resort pre-key: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/1", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp PreKeyResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Devices) == 0 {
		t.Fatal("expected at least one device in response")
	}
	if resp.Devices[0].PqPreKey == nil {
		t.Fatal("expected PqPreKey (last-resort) in response when one-time keys exhausted")
	}
}

func TestHandleGetPreKeys_LastResortNotConsumedAfterRetrieval(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store a last-resort key.
	lrKey := &keys.KEMSignedPreKey{KeyID: 99, PublicKey: []byte("lr-pub-32bytesPADDING"), Signature: []byte("lr-sig"), IsLastResort: true}
	if err := s.keys.StoreKEMLastResortPreKey(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, lrKey); err != nil {
		t.Fatalf("failed to store last-resort pre-key: %v", err)
	}

	// Fetch pre-keys twice; last-resort must be returned both times.
	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/1", nil)
		req.SetBasicAuth(testAccountUUID, testAuthToken)
		rr := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d: %s", i, rr.Code, rr.Body.String())
		}

		var resp PreKeyResponseEntity
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("request %d: unmarshal error: %v", i, err)
		}
		if len(resp.Devices) == 0 || resp.Devices[0].PqPreKey == nil {
			t.Fatalf("request %d: expected PqPreKey (last-resort) to still be available", i)
		}
	}

	// Check count still shows HasLastResort=true.
	countReq := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	countReq.SetBasicAuth(testAccountUUID, testAuthToken)
	countRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(countRR, countReq)

	var countResp PreKeyCountResponse
	if err := json.Unmarshal(countRR.Body.Bytes(), &countResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if !countResp.HasLastResort {
		t.Error("expected HasLastResort=true; last-resort key should never be consumed")
	}
}

func TestHandleGetPreKeys_OneTimeConsumedNotLastResort(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store one-time KEM keys and a last-resort key.
	oneTimeKeys := []*keys.KEMSignedPreKey{
		{KeyID: 10, PublicKey: []byte("kem-pub-1"), Signature: []byte("kem-sig-1")},
	}
	setReq := &keys.SetKeysRequest{KEMPreKeys: oneTimeKeys}
	if err := s.keys.StoreKeys(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, setReq); err != nil {
		t.Fatalf("failed to store KEM pre-keys: %v", err)
	}
	lrKey := &keys.KEMSignedPreKey{KeyID: 99, PublicKey: []byte("lr-pub-32bytesPADDING"), Signature: []byte("lr-sig"), IsLastResort: true}
	if err := s.keys.StoreKEMLastResortPreKey(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, lrKey); err != nil {
		t.Fatalf("failed to store last-resort pre-key: %v", err)
	}

	// First fetch: should return one-time key (not last-resort).
	req1 := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/1", nil)
	req1.SetBasicAuth(testAccountUUID, testAuthToken)
	rr1 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr1, req1)

	var resp1 PreKeyResponseEntity
	if err := json.Unmarshal(rr1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp1.Devices) == 0 || resp1.Devices[0].PqPreKey == nil {
		t.Fatal("expected PqPreKey in first response")
	}
	if resp1.Devices[0].PqPreKey.KeyId == 99 {
		t.Error("expected one-time key (not last-resort) on first fetch")
	}

	// Second fetch: one-time exhausted, should fall back to last-resort.
	req2 := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/1", nil)
	req2.SetBasicAuth(testAccountUUID, testAuthToken)
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)

	var resp2 PreKeyResponseEntity
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp2.Devices) == 0 || resp2.Devices[0].PqPreKey == nil {
		t.Fatal("expected PqPreKey (last-resort) in second response")
	}
	if resp2.Devices[0].PqPreKey.KeyId != 99 {
		t.Errorf("expected last-resort KeyId 99 on second fetch, got %d", resp2.Devices[0].PqPreKey.KeyId)
	}
}

// --------------------------------------------------------------------------
// handleCheckKeys
// --------------------------------------------------------------------------

func TestHandleCheckKeys_NoMismatches(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"identityKeys":[{"uuid":"` + testAccountUUID + `","identityKey":"` + testIdentityKeyB64 + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v2/keys/check", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp KeyCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.IdentityKeyFingerprints) != 0 {
		t.Errorf("expected no mismatches, got %d", len(resp.IdentityKeyFingerprints))
	}
}

func TestHandleCheckKeys_WithMismatch(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	wrongKey := base64.StdEncoding.EncodeToString([]byte("wrong-identity-key-32bytes-xxxx"))
	body := `{"identityKeys":[{"uuid":"` + testAccountUUID + `","identityKey":"` + wrongKey + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v2/keys/check", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp KeyCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.IdentityKeyFingerprints) != 1 {
		t.Fatalf("expected 1 mismatch, got %d", len(resp.IdentityKeyFingerprints))
	}
	if resp.IdentityKeyFingerprints[0].UUID != testAccountUUID {
		t.Errorf("expected UUID %s, got %s", testAccountUUID, resp.IdentityKeyFingerprints[0].UUID)
	}
}

func TestHandleCheckKeys_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v2/keys/check", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCheckKeys_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v2/keys/check", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleCheckKeys_UnknownUUID(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"identityKeys":[{"uuid":"unknown-uuid","identityKey":"` + testIdentityKeyB64 + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v2/keys/check", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp KeyCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.IdentityKeyFingerprints) != 0 {
		t.Errorf("expected no mismatches for unknown UUID, got %d", len(resp.IdentityKeyFingerprints))
	}
}

// --------------------------------------------------------------------------
// convertSetKeysRequest
// --------------------------------------------------------------------------

func TestConvertSetKeysRequest_Empty(t *testing.T) {
	req := &SetKeysRequestEntity{}
	result, err := convertSetKeysRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.PreKeys) != 0 {
		t.Errorf("expected 0 pre-keys, got %d", len(result.PreKeys))
	}
}

func TestConvertSetKeysRequest_InvalidPreKeyBase64(t *testing.T) {
	req := &SetKeysRequestEntity{
		PreKeys: []PreKeyEntity{{KeyId: 1, PublicKey: "!!!"}},
	}
	_, err := convertSetKeysRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestConvertSetKeysRequest_InvalidSignedPreKeyPubBase64(t *testing.T) {
	req := &SetKeysRequestEntity{
		SignedPreKey: &SignedPreKeyEntity{KeyId: 1, PublicKey: "!!!", Signature: testSignedPreKeySigB64},
	}
	_, err := convertSetKeysRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestConvertSetKeysRequest_InvalidSignedPreKeySigBase64(t *testing.T) {
	req := &SetKeysRequestEntity{
		SignedPreKey: &SignedPreKeyEntity{KeyId: 1, PublicKey: testSignedPreKeyPubB64, Signature: "!!!"},
	}
	_, err := convertSetKeysRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestConvertSetKeysRequest_InvalidPqPreKeyPubBase64(t *testing.T) {
	req := &SetKeysRequestEntity{
		PqPreKeys: []KEMSignedPreKeyEntity{{KeyId: 1, PublicKey: "!!!", Signature: testSignedPreKeySigB64}},
	}
	_, err := convertSetKeysRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestConvertSetKeysRequest_InvalidPqPreKeySigBase64(t *testing.T) {
	req := &SetKeysRequestEntity{
		PqPreKeys: []KEMSignedPreKeyEntity{{KeyId: 1, PublicKey: testSignedPreKeyPubB64, Signature: "!!!"}},
	}
	_, err := convertSetKeysRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestConvertSetKeysRequest_InvalidPqLastResortPubBase64(t *testing.T) {
	req := &SetKeysRequestEntity{
		PqLastResortPreKey: &KEMSignedPreKeyEntity{KeyId: 1, PublicKey: "!!!", Signature: testSignedPreKeySigB64},
	}
	_, err := convertSetKeysRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestConvertSetKeysRequest_InvalidPqLastResortSigBase64(t *testing.T) {
	req := &SetKeysRequestEntity{
		PqLastResortPreKey: &KEMSignedPreKeyEntity{KeyId: 1, PublicKey: testSignedPreKeyPubB64, Signature: "!!!"},
	}
	_, err := convertSetKeysRequest(req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// --------------------------------------------------------------------------
// identityQueryParamError (Error method coverage)
// --------------------------------------------------------------------------

func TestIdentityQueryParamError_Error(t *testing.T) {
	e := &identityQueryParamError{}
	got := e.Error()
	if got != "identity must be aci or pni" {
		t.Errorf("unexpected error string: %q", got)
	}
}

func TestHandleGetPreKeyCount_InvalidIdentityParam(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys?identity=invalid", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid identity param, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUploadKeys_InvalidIdentityParam(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"preKeys":[],"signedPreKey":{"keyId":1,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"}}`
	req := httptest.NewRequest(http.MethodPut, "/v2/keys?identity=bogus", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid identity param, got %d: %s", rr.Code, rr.Body.String())
	}
}
