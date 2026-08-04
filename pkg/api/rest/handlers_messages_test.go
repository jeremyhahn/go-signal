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

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/spam"
)

// --------------------------------------------------------------------------
// handleSendMessage
// --------------------------------------------------------------------------

func TestHandleSendMessage_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello world"))
	body := `{
		"messages": [{"type": 1, "destinationDeviceId": 1, "content": "` + contentB64 + `", "timestamp": 1000}],
		"timestamp": 1000,
		"online": false,
		"urgent": true
	}`

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
	// Single-device account: needsSync should be false.
	if resp.NeedsSync {
		t.Error("expected NeedsSync false for single-device account")
	}
}

func TestHandleSendMessage_DestinationNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	// Use a valid UUID format that doesn't correspond to any registered account.
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/99999999-9999-9999-9999-999999999999", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleSendMessage_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSendMessage_InvalidContentBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"!!!not-base64!!!","timestamp":1}],"timestamp":1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/some-uuid", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleSendMessage_DefaultDeviceID(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	// DeviceID 0 should default to primary device.
	body := `{"messages":[{"type":1,"destinationDeviceId":0,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetMessages
// --------------------------------------------------------------------------

func TestHandleGetMessages_Empty(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp OutgoingMessageEntityList
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.Messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(resp.Messages))
	}
	if resp.More {
		t.Error("expected More false")
	}
}

func TestHandleGetMessages_WithMessages(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	env := &messages.Envelope{
		Type:              1,
		SourceUUID:        "sender-uuid",
		SourceDevice:      1,
		DestinationUUID:   testAccountUUID,
		DestinationDevice: accounts.PrimaryDeviceID,
		Timestamp:         12345,
		Content:           []byte("encrypted content"),
		Urgent:            true,
	}
	if err := s.messages.Insert(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, env); err != nil {
		t.Fatalf("failed to insert message: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp OutgoingMessageEntityList
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(resp.Messages))
	}
	if resp.Messages[0].Type != 1 {
		t.Errorf("expected type 1, got %d", resp.Messages[0].Type)
	}
	if resp.Messages[0].Source != "sender-uuid" {
		t.Errorf("expected source sender-uuid, got %s", resp.Messages[0].Source)
	}
}

func TestHandleGetMessages_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeleteMessage
// --------------------------------------------------------------------------

func TestHandleDeleteMessage_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	env := &messages.Envelope{
		Type:    1,
		Content: []byte("test"),
	}
	if err := s.messages.Insert(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, env); err != nil {
		t.Fatalf("failed to insert: %v", err)
	}

	// Get the message to find its GUID.
	msgs, _ := s.messages.GetMessagesForDevice(context.Background(), testAccountUUID, accounts.PrimaryDeviceID)
	if len(msgs) == 0 {
		t.Fatal("expected at least one message")
	}

	req := httptest.NewRequest(http.MethodDelete, "/v1/messages/uuid/"+msgs[0].ServerGUID, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeleteMessage_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/messages/uuid/some-guid", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSendMultiRecipientMessage
// --------------------------------------------------------------------------

func TestHandleSendMultiRecipientMessage_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	payloadB64 := base64.StdEncoding.EncodeToString([]byte("sealed content"))
	body := `{
		"recipients": [{"uuid": "` + testAccountUUID + `", "deviceIds": [1], "registrationIds": [12345]}],
		"commonPayload": "` + payloadB64 + `",
		"timestamp": 999
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
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.UUIDs404) != 0 {
		t.Errorf("expected no 404 UUIDs, got %v", resp.UUIDs404)
	}
}

func TestHandleSendMultiRecipientMessage_RecipientNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// A valid UUID that does not exist in the account store.
	unknownUUID := "00000000-0000-0000-0000-000000000099"
	payloadB64 := base64.StdEncoding.EncodeToString([]byte("sealed"))
	body := `{
		"recipients": [{"uuid": "` + unknownUUID + `", "deviceIds": [1], "registrationIds": [1]}],
		"commonPayload": "` + payloadB64 + `",
		"timestamp": 999
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
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.UUIDs404) != 1 {
		t.Errorf("expected 1 missing UUID, got %d", len(resp.UUIDs404))
	}
}

func TestHandleSendMultiRecipientMessage_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSendMultiRecipientMessage_InvalidPayloadBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"recipients":[],"commonPayload":"!!!not-base64!!!","timestamp":1}`
	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMultiRecipientMessage_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleReportSpam
// --------------------------------------------------------------------------

func TestHandleReportSpam_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages/report/99999999-9999-9999-9999-999999999999/88888888-8888-8888-8888-888888888888", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleReportSpam_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages/report/src/guid", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// Spam checker integration tests
// --------------------------------------------------------------------------

// newTestServerWithSpamChecker creates a test server wired with the provided
// SpamChecker so spam integration tests can control the checker behaviour.
func newTestServerWithSpamChecker(t *testing.T, checker spam.SpamChecker) *Server {
	t.Helper()
	s, _ := newTestServerWithVerification(t)
	s.spamChecker = checker
	return s
}

// blockingChecker is a SpamChecker that unconditionally returns SpamCheckBlock.
type blockingChecker struct{}

func (b *blockingChecker) Check(_ context.Context, _ *spam.CheckContext) (spam.SpamCheckResult, error) {
	return spam.SpamCheckBlock, nil
}

// challengingChecker is a SpamChecker that unconditionally returns SpamCheckChallenge.
type challengingChecker struct{}

func (c *challengingChecker) Check(_ context.Context, _ *spam.CheckContext) (spam.SpamCheckResult, error) {
	return spam.SpamCheckChallenge, nil
}

// erroringChecker is a SpamChecker that unconditionally returns an error.
type erroringChecker struct{}

func (e *erroringChecker) Check(_ context.Context, _ *spam.CheckContext) (spam.SpamCheckResult, error) {
	return spam.SpamCheckAllow, errSpamCheckerFailed
}

var errSpamCheckerFailed = errors.New("internal checker failure")

func TestHandleSendMessage_SpamBlock_Returns403(t *testing.T) {
	s := newTestServerWithSpamChecker(t, &blockingChecker{})

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 when spam checker blocks, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_SpamChallenge_Returns428(t *testing.T) {
	s := newTestServerWithSpamChecker(t, &challengingChecker{})

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusPreconditionRequired {
		t.Errorf("expected 428 when spam checker challenges, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_SpamAllow_Succeeds(t *testing.T) {
	s := newTestServerWithSpamChecker(t, &spam.NoOpChecker{})

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when spam checker allows, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_SpamCheckerError_Returns500(t *testing.T) {
	s := newTestServerWithSpamChecker(t, &erroringChecker{})

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when spam checker errors (fail-closed), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendMessage_DefaultNoOpChecker_Succeeds(t *testing.T) {
	// Verify that a server with nil SpamChecker in config defaults to NoOp
	// and does not block messages.
	s, _ := newTestServerWithAccount(t)

	contentB64 := base64.StdEncoding.EncodeToString([]byte("hello"))
	body := `{"messages":[{"type":1,"destinationDeviceId":1,"content":"` + contentB64 + `","timestamp":1}],"timestamp":1}`

	req := httptest.NewRequest(http.MethodPut, "/v1/messages/"+testAccountUUID, strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with default no-op checker, got %d: %s", rr.Code, rr.Body.String())
	}
}
