package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// --------------------------------------------------------------------------
// helpers specific to device-validation tests
// --------------------------------------------------------------------------

const (
	testDeviceUUID   = "22222222-2222-2222-2222-222222222222"
	testDeviceNumber = "+15559876543"
	testDeviceToken  = "device-auth-token-secondary"
)

// testAccountMultiDevice creates an account with two enabled devices and
// stores it in the server's account store. Device 1 (primary) has
// registrationID 12345; device 2 has registrationID 99999.
func testAccountMultiDevice(t *testing.T, s *Server) *accounts.Account {
	t.Helper()

	acct := &accounts.Account{
		UUID:                   testDeviceUUID,
		Number:                 testDeviceNumber,
		IdentityKey:            testIdentityKey,
		PhoneNumberIdentityKey: testPniIdentityKey,
		UnidentifiedAccessKey:  []byte("unidentified-access-key-16bytes"),
		Devices: []accounts.Device{
			{
				ID:             accounts.PrimaryDeviceID,
				Name:           "Primary",
				AuthToken:      testDeviceToken,
				RegistrationID: 12345,
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: testSignedPreKeyPub,
					Signature: testSignedPreKeySig,
				},
				FetchesMessages: true,
				CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				LastSeen:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			{
				ID:             2,
				Name:           "Secondary",
				AuthToken:      "secondary-token",
				RegistrationID: 99999,
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     2,
					PublicKey: testSignedPreKeyPub,
					Signature: testSignedPreKeySig,
				},
				FetchesMessages: true,
				CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				LastSeen:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Version:   1,
	}

	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create multi-device account: %v", err)
	}

	got, err := s.accounts.Get(context.Background(), testDeviceUUID)
	if err != nil {
		t.Fatalf("failed to get multi-device account: %v", err)
	}
	return got
}

// --------------------------------------------------------------------------
// handleSendMessage – device-set validation (409)
// --------------------------------------------------------------------------

func TestHandleSendMessage_AllDevicesAddressed_Success(t *testing.T) {
	s, senderAcct := newTestServerWithAccount(t)
	_ = senderAcct
	testAccountMultiDevice(t, s)

	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{
		"messages": [
			{"type": 1, "destinationDeviceId": 1, "content": "` + content + `", "timestamp": 1},
			{"type": 1, "destinationDeviceId": 2, "content": "` + content + `", "timestamp": 1}
		],
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testDeviceUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_MissingDevice_Returns409(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	testAccountMultiDevice(t, s)

	// Sender only addresses device 1, but device 2 also exists → 409.
	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{
		"messages": [{"type": 1, "destinationDeviceId": 1, "content": "` + content + `", "timestamp": 1}],
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testDeviceUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp MismatchedDevicesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal 409 response: %v", err)
	}
	if len(resp.MissingDevices) != 1 {
		t.Errorf("expected 1 missingDevice, got %v", resp.MissingDevices)
	}
	if resp.MissingDevices[0] != 2 {
		t.Errorf("expected missingDevice=2, got %d", resp.MissingDevices[0])
	}
	if len(resp.ExtraDevices) != 0 {
		t.Errorf("expected no extraDevices, got %v", resp.ExtraDevices)
	}
}

func TestHandleSendMessage_ExtraDevice_Returns409(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	// Destination account has only device 1.
	// Sender addresses device 1 and a non-existent device 99.
	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{
		"messages": [
			{"type": 1, "destinationDeviceId": 1, "content": "` + content + `", "timestamp": 1},
			{"type": 1, "destinationDeviceId": 99, "content": "` + content + `", "timestamp": 1}
		],
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp MismatchedDevicesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal 409 response: %v", err)
	}
	if len(resp.ExtraDevices) != 1 || resp.ExtraDevices[0] != 99 {
		t.Errorf("expected extraDevices=[99], got %v", resp.ExtraDevices)
	}
}

func TestHandleSendMessage_BothMissingAndExtra_Returns409(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	testAccountMultiDevice(t, s)

	// Destination has devices 1 and 2.
	// Sender addresses 1 and 99 (extra); misses 2 (missing).
	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{
		"messages": [
			{"type": 1, "destinationDeviceId": 1, "content": "` + content + `", "timestamp": 1},
			{"type": 1, "destinationDeviceId": 99, "content": "` + content + `", "timestamp": 1}
		],
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testDeviceUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp MismatchedDevicesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal 409 response: %v", err)
	}
	if len(resp.MissingDevices) == 0 {
		t.Error("expected at least one missingDevice")
	}
	if len(resp.ExtraDevices) == 0 {
		t.Error("expected at least one extraDevice")
	}
}

// --------------------------------------------------------------------------
// handleSendMessage – registration-ID validation (410)
// --------------------------------------------------------------------------

func TestHandleSendMessage_StaleRegistrationID_Returns410(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Device 1 on testAccountUUID has registrationID 12345.
	// Sender supplies an outdated registrationId of 999 → 410.
	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{
		"messages": [{"type": 1, "destinationDeviceId": 1, "registrationId": 999, "content": "` + content + `", "timestamp": 1}],
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp StaleDevicesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal 410 response: %v", err)
	}
	if len(resp.StaleDevices) != 1 || resp.StaleDevices[0] != 1 {
		t.Errorf("expected staleDevices=[1], got %v", resp.StaleDevices)
	}
}

func TestHandleSendMessage_CorrectRegistrationID_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Device 1 on testAccountUUID has registrationID 12345 (set in testAccount()).
	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{
		"messages": [{"type": 1, "destinationDeviceId": 1, "registrationId": 12345, "content": "` + content + `", "timestamp": 1}],
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_NoRegistrationID_NoStaleCheck(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// No registrationId supplied → stale-device check is skipped.
	content := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{
		"messages": [{"type": 1, "destinationDeviceId": 1, "content": "` + content + `", "timestamp": 1}],
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// MismatchedDevicesResponse / StaleDevicesResponse JSON serialisation
// --------------------------------------------------------------------------

func TestMismatchedDevicesResponse_JSONSerialisation(t *testing.T) {
	resp := MismatchedDevicesResponse{
		MissingDevices: []uint64{2, 3},
		ExtraDevices:   []uint64{99},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded MismatchedDevicesResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.MissingDevices) != 2 {
		t.Errorf("expected 2 missingDevices, got %d", len(decoded.MissingDevices))
	}
	if len(decoded.ExtraDevices) != 1 {
		t.Errorf("expected 1 extraDevice, got %d", len(decoded.ExtraDevices))
	}
}

func TestMismatchedDevicesResponse_EmptySlicesNotNull(t *testing.T) {
	resp := MismatchedDevicesResponse{
		MissingDevices: []uint64{},
		ExtraDevices:   []uint64{},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	// Ensure we get [] not null in JSON.
	s := string(data)
	if strings.Contains(s, "null") {
		t.Errorf("unexpected null in JSON output: %s", s)
	}
}

func TestStaleDevicesResponse_JSONSerialisation(t *testing.T) {
	resp := StaleDevicesResponse{StaleDevices: []uint64{1, 2}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded StaleDevicesResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.StaleDevices) != 2 {
		t.Errorf("expected 2 stale devices, got %d", len(decoded.StaleDevices))
	}
}

func TestStaleDevicesResponse_EmptySliceNotNull(t *testing.T) {
	resp := StaleDevicesResponse{StaleDevices: []uint64{}}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	s := string(data)
	if strings.Contains(s, "null") {
		t.Errorf("unexpected null in JSON output: %s", s)
	}
}

// --------------------------------------------------------------------------
// nilToEmpty helper
// --------------------------------------------------------------------------

func TestNilToEmpty_NilSlice(t *testing.T) {
	result := nilToEmpty(nil)
	if result == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

func TestNilToEmpty_NonNilSlice(t *testing.T) {
	input := []uint64{1, 2, 3}
	result := nilToEmpty(input)
	if len(result) != 3 {
		t.Errorf("expected 3 elements, got %d", len(result))
	}
}

// --------------------------------------------------------------------------
// handleSendMultiRecipientMessage – device-set validation (409)
// --------------------------------------------------------------------------

func TestHandleSendMultiRecipientMessage_MissingDevice_Returns409(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	testAccountMultiDevice(t, s)

	// Destination has devices 1 and 2; sender only addresses device 1.
	payload := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{
		"recipients": [{"uuid": "` + testDeviceUUID + `", "deviceIds": [1], "registrationIds": [12345]}],
		"commonPayload": "` + payload + `",
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp MismatchedDevicesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(resp.MissingDevices) == 0 {
		t.Error("expected at least one missing device")
	}
}

func TestHandleSendMultiRecipientMessage_AllDevicesAddressed_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	testAccountMultiDevice(t, s)

	// Sender addresses both device 1 and 2 with correct registration IDs.
	payload := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{
		"recipients": [{"uuid": "` + testDeviceUUID + `", "deviceIds": [1, 2], "registrationIds": [12345, 99999]}],
		"commonPayload": "` + payload + `",
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMultiRecipientMessage_StaleRegistrationID_Returns410(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	testAccountMultiDevice(t, s)

	// Device 1 registrationID is 12345; device 2 is 99999.
	// Sender supplies stale registrationId 777 for device 2 → 410.
	payload := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{
		"recipients": [{"uuid": "` + testDeviceUUID + `", "deviceIds": [1, 2], "registrationIds": [12345, 777]}],
		"commonPayload": "` + payload + `",
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp StaleDevicesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(resp.StaleDevices) == 0 {
		t.Error("expected at least one stale device")
	}
}

func TestHandleSendMultiRecipientMessage_MixedRecipientsFirstValidSecondNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// A valid UUID format that does not exist in the account store.
	unknownUUID := "00000000-0000-0000-0000-000000000099"

	// First recipient (testAccountUUID) exists with one device; second does not.
	payload := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{
		"recipients": [
			{"uuid": "` + testAccountUUID + `", "deviceIds": [1], "registrationIds": [12345]},
			{"uuid": "` + unknownUUID + `", "deviceIds": [1], "registrationIds": [1]}
		],
		"commonPayload": "` + payload + `",
		"timestamp": 1
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp MultiRecipientMessageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(resp.UUIDs404) != 1 || resp.UUIDs404[0] != unknownUUID {
		t.Errorf("expected uuids404=[%s], got %v", unknownUUID, resp.UUIDs404)
	}
}

// --------------------------------------------------------------------------
// buildDeviceMessages helper
// --------------------------------------------------------------------------

func TestBuildDeviceMessages_EqualLengthSlices(t *testing.T) {
	deviceIDs := []uint64{1, 2, 3}
	regIDs := []uint32{111, 222, 333}

	result := buildDeviceMessages(deviceIDs, regIDs)
	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
	for i := range result {
		if result[i].DestinationDeviceID != deviceIDs[i] {
			t.Errorf("[%d] expected deviceID %d, got %d", i, deviceIDs[i], result[i].DestinationDeviceID)
		}
		if result[i].RegistrationID != regIDs[i] {
			t.Errorf("[%d] expected regID %d, got %d", i, regIDs[i], result[i].RegistrationID)
		}
	}
}

func TestBuildDeviceMessages_FewerRegIDsThanDeviceIDs(t *testing.T) {
	deviceIDs := []uint64{1, 2, 3}
	regIDs := []uint32{111}

	result := buildDeviceMessages(deviceIDs, regIDs)
	if len(result) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result))
	}
	if result[0].RegistrationID != 111 {
		t.Errorf("expected first regID 111, got %d", result[0].RegistrationID)
	}
	// Entries beyond regIDs length must have RegistrationID 0 (skipped in validation).
	if result[1].RegistrationID != 0 || result[2].RegistrationID != 0 {
		t.Errorf("expected trailing regIDs to be 0, got %d and %d",
			result[1].RegistrationID, result[2].RegistrationID)
	}
}

func TestBuildDeviceMessages_EmptySlices(t *testing.T) {
	result := buildDeviceMessages([]uint64{}, []uint32{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d elements", len(result))
	}
}
