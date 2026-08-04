package rest

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --------------------------------------------------------------------------
// handleCDNUploadPut - success path (covers 50% -> 100%)
// --------------------------------------------------------------------------

func TestHandleCDNUploadPut_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := "binary-upload-data-content"
	req := httptest.NewRequest(http.MethodPut, "/cdn3/upload/some-key", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleCDNUpload_MethodNotAllowed(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodDelete, "/cdn3/upload/some-key", nil)
	rr := httptest.NewRecorder()
	s.handleCDNUpload(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// --------------------------------------------------------------------------
// handleChangeNumber - additional branches
// --------------------------------------------------------------------------

func TestHandleChangeNumber_InvalidPniIdentityKeyEncoding(t *testing.T) {
	s, sessionID := changeNumberServer(t, "+15559998888")

	body := `{"number":"+15559998888","sessionId":"` + sessionID + `","pniIdentityKey":"!!!invalid!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleChangeNumber_NilAccountDirect(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	s.handleChangeNumber(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestHandleChangeNumber_NoPrimaryDevice(t *testing.T) {
	s := newTestServer(t)

	// A non-primary (linked) device must not be allowed to change the number.
	acct := &accounts.Account{UUID: "linked-device-uuid"}
	ctx := contextWithAccount(context.Background(), acct)
	ctx = contextWithDevice(ctx, 2)
	req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleChangeNumber(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// --------------------------------------------------------------------------
// handleSetProfile - invalid encoding branches (covers 80% -> higher)
// --------------------------------------------------------------------------

func TestHandleSetProfile_InvalidAboutEncoding(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"version":"v1","name":"` + base64.StdEncoding.EncodeToString([]byte("Test Name")) + `","about":"!!!invalid!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSetProfile_InvalidAboutEmojiEncoding(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	validB64 := base64.StdEncoding.EncodeToString([]byte("test"))
	body := `{"version":"v1","name":"` + validB64 + `","about":"` + validB64 + `","aboutEmoji":"!!!invalid!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSetProfile_InvalidPaymentAddressEncoding(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	validB64 := base64.StdEncoding.EncodeToString([]byte("test"))
	body := `{"version":"v1","name":"` + validB64 + `","about":"` + validB64 + `","aboutEmoji":"` + validB64 + `","paymentAddress":"!!!invalid!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleSetProfile_InvalidCommitmentEncoding(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	validB64 := base64.StdEncoding.EncodeToString([]byte("test"))
	body := `{"version":"v1","name":"` + validB64 + `","about":"` + validB64 + `","aboutEmoji":"` + validB64 + `","paymentAddress":"` + validB64 + `","commitment":"!!!invalid!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleSendMultiRecipientMessage - invalid payload encoding
// --------------------------------------------------------------------------

func TestHandleSendMultiRecipientMessage_InvalidPayloadEncoding(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"commonPayload":"!!!invalid!!!","recipients":[],"timestamp":1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleSendMessage - invalid content encoding
// --------------------------------------------------------------------------

func TestHandleSendMessage_InvalidContentEncoding(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"!!!invalid!!!","timestamp":1}],"timestamp":1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleGetPreKeys - invalid device ID
// --------------------------------------------------------------------------

func TestHandleGetPreKeys_InvalidDeviceID(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/keys/"+testAccountUUID+"/abc", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleReserveUsernameHash - invalid base64 in hashes
// --------------------------------------------------------------------------

func TestHandleReserveUsernameHash_InvalidBase64InHashes(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"usernameHashes":["!!!invalid!!!"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleSetUsernameLink - empty encrypted value
// --------------------------------------------------------------------------

func TestHandleSetUsernameLink_EmptyEncryptedValue(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"usernameLinkEncryptedValue":""}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleUploadKeys - invalid preKey public key encoding
// --------------------------------------------------------------------------

func TestHandleUploadKeys_InvalidPreKeyPublicKeyEncoding(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"preKeys":[{"keyId":1,"publicKey":"!!!invalid!!!"}]}`
	req := httptest.NewRequest(http.MethodPut, "/v2/keys", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleRegistration - various invalid encoding branches
// --------------------------------------------------------------------------

func TestHandleRegistration_ReRegistration(t *testing.T) {
	// newTestServerWithAccount creates a pre-existing account for testAccountNumber.
	// We need a verification transport to create a verified session.
	s, transport := newTestServerWithVerification(t)
	km := getTestKeyMaterial(t)

	// Pre-populate the server with the test account (as newTestServerWithAccount does).
	acct := testAccount()
	require.NoError(t, s.accounts.Create(context.Background(), acct))

	sessionID := createVerifiedSession(t, s, transport, testAccountNumber)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 222},
		"aciIdentityKey": "` + km.ACIIdentityKeyB64 + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + km.ACISignedPreKeyPubB64 + `","signature":"` + km.ACISignedPreKeySigB64 + `"},
		"pniSignedPreKey": {"keyId":2,"publicKey":"` + km.PNISignedPreKeyPubB64 + `","signature":"` + km.PNISignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + km.ACIPqPubB64 + `","signature":"` + km.ACIPqSigB64 + `"},
		"pniPqLastResortPreKey": {"keyId":4,"publicKey":"` + km.PNIPqPubB64 + `","signature":"` + km.PNIPqSigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(testAccountNumber, "newpassword123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleRegistration_InvalidIdentityKey(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15558880001"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "!!!invalid!!!",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRegistration_InvalidPniIdentityKey(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15558880002"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "!!!invalid!!!",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRegistration_InvalidAciSignedPreKeyPublicKey(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15558880003"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"!!!invalid!!!","signature":"` + testSignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRegistration_InvalidAciSignedPreKeySignature(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15558880004"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"!!!invalid!!!"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleRegistration_InvalidUAKEncoding(t *testing.T) {
	s, transport := newTestServerWithVerification(t)
	const number = "+15558880005"
	sessionID := createVerifiedSession(t, s, transport, number)

	body := `{
		"sessionId": "` + sessionID + `",
		"accountAttributes": {"fetchesMessages": true, "registrationId": 111, "unidentifiedAccessKey": "!!!invalid!!!"},
		"aciIdentityKey": "` + testIdentityKeyB64 + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"aciSignedPreKey": {"keyId":1,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"},
		"aciPqLastResortPreKey": {"keyId":3,"publicKey":"` + testSignedPreKeyPubB64 + `","signature":"` + testSignedPreKeySigB64 + `"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/registration", strings.NewReader(body))
	req.SetBasicAuth(number, "password123")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleGetStickerPackForm - invalid count param
// --------------------------------------------------------------------------

func TestHandleGetStickerPackForm_InvalidCountParam(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/sticker/pack/form/abc", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// fingerprintEqual - edge cases
// --------------------------------------------------------------------------

func TestFingerprintEqual_EmptySlices(t *testing.T) {
	assert.False(t, fingerprintEqual([]byte{}, []byte{}))
	assert.False(t, fingerprintEqual(nil, nil))
	assert.False(t, fingerprintEqual([]byte{1}, []byte{}))
	assert.False(t, fingerprintEqual([]byte{}, []byte{1}))
}

// TestFingerprintEqual_StoredShorter verifies that length-mismatched
// fingerprints are always rejected, regardless of which is shorter. This
// closes the prefix-match bug where different-length slices could match.
func TestFingerprintEqual_StoredShorter(t *testing.T) {
	// Neither direction of length mismatch should ever return true.
	assert.False(t, fingerprintEqual([]byte{1, 2, 3}, []byte{1, 2}),
		"submitted longer than stored: must reject")
	assert.False(t, fingerprintEqual([]byte{1, 2}, []byte{1, 2, 3}),
		"stored longer than submitted: must reject")
	assert.False(t, fingerprintEqual([]byte{1, 3, 3}, []byte{1, 2}),
		"non-matching lengths: must reject")
}

// --------------------------------------------------------------------------
// Server.Serve - nil listener
// --------------------------------------------------------------------------

func TestServer_Serve_NilListener(t *testing.T) {
	s := newTestServer(t)

	err := s.Serve()
	require.Error(t, err)

	var listenErr *ListenError
	assert.ErrorAs(t, err, &listenErr)
}

// --------------------------------------------------------------------------
// Server.Start - listen error
// --------------------------------------------------------------------------

func TestServer_Start_ListenError(t *testing.T) {
	s := NewServer(ServerConfig{
		Host:   "127.0.0.1",
		Port:   0,
		Logger: testLogger(),
	})

	require.NoError(t, s.Listen())
	addr := s.Addr()
	assert.NotEmpty(t, addr)

	s2 := NewServer(ServerConfig{
		Host:   "127.0.0.1",
		Port:   0,
		Logger: testLogger(),
	})
	s2.httpServer.Addr = addr

	err := s2.Start()
	require.Error(t, err)

	_ = s.listener.Close()
}

// --------------------------------------------------------------------------
// writeError - success path
// --------------------------------------------------------------------------

func TestWriteError_Success(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, http.StatusBadRequest, "test error message")

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "test error message")
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
}

// --------------------------------------------------------------------------
// writeJSON - marshal failure
// --------------------------------------------------------------------------

func TestWriteJSON_MarshalFailure(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusOK, make(chan int))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "internal server error")
}
