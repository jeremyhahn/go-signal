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
	"github.com/jeremyhahn/go-signal/pkg/messages"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// --------------------------------------------------------------------------
// Additional coverage: store error paths, missing branches, key types
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// handleSendProvisioningMessage with WS sessions
// --------------------------------------------------------------------------

func TestHandleSendProvisioningMessage_WithWSSessions(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	wsMgr := signalws.NewSessionManager(testLogger())
	s.wsSessions = wsMgr

	body := `{"body":"provisioning-message-body"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/provisioning/dest-uuid-123", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Should succeed even when no session is found (silently skips delivery).
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetPreKeys with EC and KEM pre-keys populated
// --------------------------------------------------------------------------

func TestHandleGetPreKeys_WithECPreKeys(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store EC pre-keys.
	ecKeys := []*keys.PreKey{
		{KeyID: 100, PublicKey: []byte("ec-prekey-pub-32bytes-xxxxxxxxx")},
	}
	setReq := &keys.SetKeysRequest{PreKeys: ecKeys}
	if err := s.keys.StoreKeys(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, setReq); err != nil {
		t.Fatalf("failed to store EC pre-keys: %v", err)
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
		t.Fatal("expected at least 1 device")
	}
	if resp.Devices[0].PreKey == nil {
		t.Error("expected PreKey to be populated")
	}
}

func TestHandleGetPreKeys_WithKEMPreKeys(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store KEM pre-keys.
	kemKeys := []*keys.KEMSignedPreKey{
		{KeyID: 200, PublicKey: []byte("kem-prekey-pub-32bytes-xxxxxxxx"), Signature: []byte("kem-prekey-sig-64bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")},
	}
	if err := s.keys.StoreKEMPreKeys(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, kemKeys); err != nil {
		t.Fatalf("failed to store KEM pre-keys: %v", err)
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
		t.Fatal("expected at least 1 device")
	}
	if resp.Devices[0].PqPreKey == nil {
		t.Error("expected PqPreKey to be populated")
	}
}

func TestHandleGetPreKeys_WithAllKeyTypes(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store both EC and KEM pre-keys.
	ecKeys := []*keys.PreKey{
		{KeyID: 100, PublicKey: []byte("ec-prekey-pub-32bytes-xxxxxxxxx")},
	}
	kemKeys := []*keys.KEMSignedPreKey{
		{KeyID: 200, PublicKey: []byte("kem-prekey-pub-32bytes-xxxxxxxx"), Signature: []byte("kem-prekey-sig-64bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")},
	}
	setReq := &keys.SetKeysRequest{PreKeys: ecKeys, KEMPreKeys: kemKeys}
	if err := s.keys.StoreKeys(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, setReq); err != nil {
		t.Fatalf("failed to store keys: %v", err)
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
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.Devices) == 0 {
		t.Fatal("expected at least 1 device")
	}
	if resp.Devices[0].PreKey == nil {
		t.Error("expected PreKey to be populated")
	}
	if resp.Devices[0].PqPreKey == nil {
		t.Error("expected PqPreKey to be populated")
	}
	if resp.Devices[0].SignedPreKey == nil {
		t.Error("expected SignedPreKey to be populated")
	}
}

// --------------------------------------------------------------------------
// handleGetPreKeyCount - store error path
// --------------------------------------------------------------------------

func TestHandleGetPreKeyCount_WithPQKeys(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Store KEM pre-keys to get a non-zero pqCount.
	kemKeys := []*keys.KEMSignedPreKey{
		{KeyID: 1, PublicKey: []byte("kem-pub"), Signature: []byte("kem-sig")},
		{KeyID: 2, PublicKey: []byte("kem-pub2"), Signature: []byte("kem-sig2")},
	}
	if err := s.keys.StoreKEMPreKeys(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, kemKeys); err != nil {
		t.Fatalf("failed to store KEM pre-keys: %v", err)
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
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.PqCount != 2 {
		t.Errorf("expected PQ count 2, got %d", resp.PqCount)
	}
}

// --------------------------------------------------------------------------
// handleUploadKeys - store error path (StoreKeys fails)
// --------------------------------------------------------------------------

func TestHandleUploadKeys_WithSignedPreKey(t *testing.T) {
	s, _, km := newTestServerWithRealKeys(t)

	// Generate a new signed pre-key signed with the ACI identity key.
	newSPKKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	spkPub := newSPKKP.PublicKey().Serialize()
	spkSigArr, err := ecc.CalculateSignature(km.ACIKeyPair.PrivateKey(), spkPub)
	if err != nil {
		t.Fatalf("failed to sign SPK: %v", err)
	}

	body := `{
		"signedPreKey": {"keyId": 200, "publicKey": "` + base64.StdEncoding.EncodeToString(spkPub) + `", "signature": "` + base64.StdEncoding.EncodeToString(spkSigArr[:]) + `"}
	}`

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleSetAccountAttributes - more branches
// --------------------------------------------------------------------------

func TestHandleSetAccountAttributes_WithUAK(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	uak := base64.StdEncoding.EncodeToString([]byte("valid-uak-16bytes!"))
	body := `{"unidentifiedAccessKey":"` + uak + `","fetchesMessages":true,"registrationId":0}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/attributes/", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSetAccountAttributes_WithRegistrationId(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"fetchesMessages":true,"registrationId":99999}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/attributes/", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleDeleteAccount - account already deleted (error path)
// --------------------------------------------------------------------------

func TestHandleDeleteAccount_DeleteTwice(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// First delete succeeds.
	req1 := httptest.NewRequest(http.MethodDelete, "/v1/accounts/me", nil)
	req1.SetBasicAuth(testAccountUUID, testAuthToken)
	rr1 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusNoContent {
		t.Fatalf("first delete: expected 204, got %d", rr1.Code)
	}

	// Second delete - the account no longer exists, so auth will fail.
	req2 := httptest.NewRequest(http.MethodDelete, "/v1/accounts/me", nil)
	req2.SetBasicAuth(testAccountUUID, testAuthToken)
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("second delete: expected 401, got %d", rr2.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeleteAccount - direct call with account in context to hit store error
// --------------------------------------------------------------------------

func TestHandleDeleteAccount_StoreError(t *testing.T) {
	s := newTestServer(t)

	// Create a fake account context with a UUID that doesn't exist in the store.
	fakeAcct := &accounts.Account{UUID: "nonexistent-uuid-delete"}
	ctx := contextWithAccount(context.Background(), fakeAcct)
	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/me", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleDeleteAccount(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleUnregisterGcm - direct call with account to hit Update error path
// --------------------------------------------------------------------------

func TestHandleUnregisterGcm_StoreUpdateError(t *testing.T) {
	s := newTestServer(t)

	// Create account in context but NOT in store, so Update will fail.
	acct := testAccount()
	acct.UUID = "nonexistent-uuid-gcm"
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/gcm/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleUnregisterGcm(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUnregisterGcm_NoPrimaryDevice(t *testing.T) {
	s := newTestServer(t)

	// Create account with no devices.
	acct := &accounts.Account{UUID: "no-devices-uuid"}
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/gcm/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleUnregisterGcm(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleUnregisterApn - direct call to hit Update error and no-primary paths
// --------------------------------------------------------------------------

func TestHandleUnregisterApn_StoreUpdateError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-apn"
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/apn/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleUnregisterApn(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUnregisterApn_NoPrimaryDevice(t *testing.T) {
	s := newTestServer(t)

	acct := &accounts.Account{UUID: "no-devices-uuid-apn"}
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/apn/", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleUnregisterApn(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleRegisterGcm - store error path
// --------------------------------------------------------------------------

func TestHandleRegisterGcm_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-gcm-reg"
	ctx := contextWithAccount(context.Background(), acct)
	body := `{"gcmRegistrationId":"token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/gcm/", strings.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleRegisterGcm(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleRegisterApn - store error path
// --------------------------------------------------------------------------

func TestHandleRegisterApn_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-apn-reg"
	ctx := contextWithAccount(context.Background(), acct)
	body := `{"apnRegistrationId":"token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/apn/", strings.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleRegisterApn(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleSetAccountAttributes - SetDeviceAttributes store error
// --------------------------------------------------------------------------

func TestHandleSetAccountAttributes_SetDeviceAttributesError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-attrs"
	ctx := contextWithAccount(context.Background(), acct)
	body := `{"fetchesMessages":true}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/attributes/", strings.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleSetAccountAttributes(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleSetRegistrationLock - store error path
// --------------------------------------------------------------------------

func TestHandleSetRegistrationLock_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-reglock"
	ctx := contextWithAccount(context.Background(), acct)
	body := `{"registrationLock":"some-pin"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/registration_lock", strings.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleSetRegistrationLock(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleRemoveRegistrationLock - store error path
// --------------------------------------------------------------------------

func TestHandleRemoveRegistrationLock_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-clearreglock"
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/registration_lock", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleRemoveRegistrationLock(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleSetPhoneNumberDiscoverability - store error path
// --------------------------------------------------------------------------

func TestHandleSetPhoneNumberDiscoverability_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-discover"
	ctx := contextWithAccount(context.Background(), acct)
	body := `{"discoverableByPhoneNumber":true}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/phone_number_discoverability", strings.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleSetPhoneNumberDiscoverability(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetDataReport - store error path
// --------------------------------------------------------------------------

func TestHandleGetDataReport_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-report"
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodGet, "/v2/accounts/data_report", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleGetDataReport(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetMessages - empty inbox path
// --------------------------------------------------------------------------

func TestHandleGetMessages_EmptyInbox(t *testing.T) {
	// The in-memory message store returns an empty list for an account with
	// no pending messages, producing a 200 with an empty messages array.
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify the response body is valid JSON with an empty messages array.
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected valid JSON response, got: %s", rr.Body.String())
	}
	msgs, ok := body["messages"]
	if !ok {
		t.Fatal("expected 'messages' key in response body")
	}
	msgSlice, ok := msgs.([]interface{})
	if !ok {
		t.Fatalf("expected 'messages' to be an array, got %T", msgs)
	}
	if len(msgSlice) != 0 {
		t.Errorf("expected empty messages array for account with no messages, got %d messages", len(msgSlice))
	}
}

// --------------------------------------------------------------------------
// handleDeleteMessage - store error path
// --------------------------------------------------------------------------

func TestHandleDeleteMessage_NonExistentGuid(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Delete a GUID that doesn't exist - in-memory store returns nil for this,
	// so it should succeed (204). Use a valid UUID format for the path parameter.
	req := httptest.NewRequest(http.MethodDelete, "/v1/messages/uuid/99999999-9999-9999-9999-999999999999", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSendMessage - message insert error (store error)
// --------------------------------------------------------------------------

func TestHandleSendMessage_NeedsSync(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Add a second device to trigger needsSync.
	acct, _ := s.accounts.Get(context.Background(), testAccountUUID)
	acct.Devices = append(acct.Devices, accounts.Device{
		ID:             2,
		Name:           "Second Device",
		AuthToken:      "second-token",
		RegistrationID: 99999,
	})
	if err := s.accounts.Update(context.Background(), acct); err != nil {
		t.Fatalf("failed to update account: %v", err)
	}

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp SendMessageResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if !resp.NeedsSync {
		t.Error("expected NeedsSync true for multi-device account")
	}
}

// --------------------------------------------------------------------------
// handleGetStickerPackForm - zero count (InvalidStickerCountError)
// --------------------------------------------------------------------------

func TestHandleGetStickerPackForm_ZeroCount(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/sticker/pack/form/0", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetStickerPackForm_TooManyStickers(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/sticker/pack/form/999", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleSetDeviceCapabilities - store error path
// --------------------------------------------------------------------------

func TestHandleSetDeviceCapabilities_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-caps"
	ctx := contextWithAccount(context.Background(), acct)
	body := `{"capabilities":{"storage":true}}`
	req := httptest.NewRequest(http.MethodPut, "/v1/devices/capabilities", strings.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleSetDeviceCapabilities(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleRemoveDevice - store error path
// --------------------------------------------------------------------------

func TestHandleRemoveDevice_StoreError(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	acct.UUID = "nonexistent-uuid-rmdev"
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodDelete, "/v1/devices/99", nil).WithContext(ctx)
	req.SetPathValue("device_id", "99")
	rr := httptest.NewRecorder()
	s.handleRemoveDevice(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetDeliveryCertificate - NoPrimaryDevice branch
// --------------------------------------------------------------------------

func TestHandleGetDeliveryCertificate_NoPrimaryDevice(t *testing.T) {
	s := newTestServer(t)

	// Account with no devices.
	acct := &accounts.Account{
		UUID:        testAccountUUID,
		Number:      testAccountNumber,
		IdentityKey: testIdentityKey,
	}
	ctx := contextWithAccount(context.Background(), acct)
	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/delivery", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleGetDeliveryCertificate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetGroupCredentials - missing end param only
// --------------------------------------------------------------------------

func TestHandleGetGroupCredentials_MissingEndParam(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/auth/group?redemptionStartSeconds=100", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleChallengeResponse - store error path
// --------------------------------------------------------------------------

func TestHandleChallengeResponse_ChallengeVerificationFails(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"type":"captcha","token":"invalid-token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/challenge", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// NewServer with WSSessions
// --------------------------------------------------------------------------

func TestNewServer_WithWSSessions(t *testing.T) {
	logger := testLogger()
	wsMgr := signalws.NewSessionManager(logger)

	accountStore := &memAccountStore{
		accounts: make(map[string]*accounts.Account),
		byNumber: make(map[string]string),
	}
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	keyStore := &memPreKeyStore{
		signedPreKeys: make(map[string]*keys.SignedPreKey),
		ecPreKeys:     make(map[string][]*keys.PreKey),
		kemPreKeys:    make(map[string][]*keys.KEMSignedPreKey),
	}
	keysMgr := keys.NewKeysManager(keyStore)
	msgStore := &memMessageStore{messages: make(map[string][]*messages.Envelope)}
	msgsMgr := messages.NewMessagesManager(msgStore)

	s := NewServer(ServerConfig{
		Host:       "127.0.0.1",
		Port:       0,
		Logger:     logger,
		Accounts:   accountsMgr,
		Keys:       keysMgr,
		Messages:   msgsMgr,
		WSSessions: wsMgr,
	})

	if s.wsHandler == nil {
		t.Error("expected wsHandler to be initialized when WSSessions provided")
	}
	if s.wsSessions == nil {
		t.Error("expected wsSessions to be set")
	}
}

// --------------------------------------------------------------------------
// handleWebSocket / handleWebSocketProvisioning with wsHandler set
// --------------------------------------------------------------------------

func TestHandleWebSocket_WithHandler(t *testing.T) {
	logger := testLogger()
	wsMgr := signalws.NewSessionManager(logger)

	accountStore := &memAccountStore{
		accounts: make(map[string]*accounts.Account),
		byNumber: make(map[string]string),
	}
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	keyStore := &memPreKeyStore{
		signedPreKeys: make(map[string]*keys.SignedPreKey),
		ecPreKeys:     make(map[string][]*keys.PreKey),
		kemPreKeys:    make(map[string][]*keys.KEMSignedPreKey),
	}
	keysMgr := keys.NewKeysManager(keyStore)
	msgStore := &memMessageStore{messages: make(map[string][]*messages.Envelope)}
	msgsMgr := messages.NewMessagesManager(msgStore)

	s := NewServer(ServerConfig{
		Host:       "127.0.0.1",
		Port:       0,
		Logger:     logger,
		Accounts:   accountsMgr,
		Keys:       keysMgr,
		Messages:   msgsMgr,
		WSSessions: wsMgr,
	})

	// The WS handler should be set. Making a request without a proper
	// WebSocket upgrade will fail at the upgrade step, but the wsHandler
	// branch is exercised.
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Should not return 503 since wsHandler is set.
	if rr.Code == http.StatusServiceUnavailable {
		t.Error("expected wsHandler to be invoked, not 503")
	}
}

// --------------------------------------------------------------------------
// handleRegistration - storeRegistrationPreKeys error paths
// --------------------------------------------------------------------------

func TestHandleRegistration_InvalidAciPqLastResortPubBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15558887777"
	sessionID := createVerifiedSession(t, s, transport, number)

	// Use real ACI identity key and signed pre-keys so we get past signature
	// validation, then fail on the PQ last-resort key's invalid base64.
	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"!!!invalid!!!","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// The PQ key's invalid base64 is caught by validateRegistrationKeys which
	// returns 400 Bad Request (changed from the prior 500 which was in storeRegistrationPreKeys).
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidAciPqLastResortSigBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15558887776"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"!!!invalid!!!"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleRegistration - capabilities with no storage
// --------------------------------------------------------------------------

func TestHandleRegistration_NoStorageCapability(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15558887775"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111, "capabilities": {"transfer": true}},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

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
	if resp.StorageCapable {
		t.Error("expected StorageCapable to be false")
	}
}

// --------------------------------------------------------------------------
// handleRegistration - with UAK
// --------------------------------------------------------------------------

func TestHandleRegistration_WithUAK(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15558887774"
	sessionID := createVerifiedSession(t, s, transport, number)

	uakB64 := base64.StdEncoding.EncodeToString([]byte("unidentified-key!"))
	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111, "unidentifiedAccessKey": "` + uakB64 + `"},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetPreKeys - all-device wildcard path with pre-key error
// --------------------------------------------------------------------------

func TestHandleGetPreKeys_AllDevices_NoPreKeysAvailable(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Add a second device without storing any keys for it.
	acct, _ := s.accounts.Get(context.Background(), testAccountUUID)
	acct.Devices = append(acct.Devices, accounts.Device{
		ID:             2,
		Name:           "Second",
		AuthToken:      "second-token",
		RegistrationID: 99999,
	})
	if err := s.accounts.Update(context.Background(), acct); err != nil {
		t.Fatalf("failed to update account: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/*", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Primary device has a signed pre-key, so should still return results.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleUploadKeys - StoreKeys error path
// --------------------------------------------------------------------------

func TestHandleUploadKeys_ValidPqLastResortPreKey(t *testing.T) {
	s, _, km := newTestServerWithRealKeys(t)

	// Generate a KEM public key and sign it with the ACI identity key.
	kemPub := make([]byte, 32)
	for i := range kemPub {
		kemPub[i] = byte(i + 200)
	}
	sigArr, err := ecc.CalculateSignature(km.ACIKeyPair.PrivateKey(), kemPub)
	if err != nil {
		t.Fatalf("failed to sign KEM key: %v", err)
	}

	body := `{
		"pqLastResortPreKey": {"keyId": 400, "publicKey": "` + base64.StdEncoding.EncodeToString(kemPub) + `", "signature": "` + base64.StdEncoding.EncodeToString(sigArr[:]) + `"}
	}`

	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// validateRegistrationKeys - PNI signed pre-key and PNI PQ base64 error paths
// --------------------------------------------------------------------------

func TestHandleRegistration_InvalidPniSignedPreKeyPubBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15559990001"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"!!!invalid!!!","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid pniSignedPreKey publicKey, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidPniSignedPreKeySigBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15559990002"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"!!!invalid!!!"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid pniSignedPreKey signature, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidPniPqLastResortPubBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15559990003"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"!!!invalid!!!","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid pniPqLastResortPreKey publicKey, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegistration_InvalidPniPqLastResortSigBase64(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)
	const number = "+15559990004"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"!!!invalid!!!"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid pniPqLastResortPreKey signature, got %d: %s", rr.Code, rr.Body.String())
	}
}
