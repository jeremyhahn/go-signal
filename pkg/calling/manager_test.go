package calling

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// mockTurnProvider is a test double for TurnCredentialProvider.
type mockTurnProvider struct {
	token *TurnToken
	err   error
}

func (m *mockTurnProvider) RetrieveCredentials(ctx context.Context) (*TurnToken, error) {
	return m.token, m.err
}

// mockSurveyPublisher is a test double for SurveyPublisher.
type mockSurveyPublisher struct {
	published []*CallQualitySurveyMessage
	err       error
}

func (m *mockSurveyPublisher) Publish(ctx context.Context, survey *CallQualitySurveyMessage) error {
	m.published = append(m.published, survey)
	return m.err
}

func testCallingManager(tp TurnCredentialProvider, sp SurveyPublisher) *CallingManager {
	return NewCallingManager(CallingConfig{
		TurnProvider:    tp,
		SurveyPublisher: sp,
		Logger:          testLogger(),
	})
}

func testCallingManagerWithZK(tp TurnCredentialProvider, sp SurveyPublisher) *CallingManager {
	var randomness zkgroup.RandomnessBytes
	for i := range randomness {
		randomness[i] = 0x42
	}
	params := zkgroup.GenerateGenericServerSecretParams(randomness)
	return NewCallingManager(CallingConfig{
		TurnProvider:        tp,
		GenericServerSecret: params,
		SurveyPublisher:     sp,
		Logger:              testLogger(),
	})
}

func TestNewCallingManager_NotNil(t *testing.T) {
	m := testCallingManager(&mockTurnProvider{}, &mockSurveyPublisher{})
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewCallingManager_StoresFields(t *testing.T) {
	tp := &mockTurnProvider{}
	sp := &mockSurveyPublisher{}
	m := NewCallingManager(CallingConfig{
		TurnProvider:    tp,
		SurveyPublisher: sp,
		Logger:          testLogger(),
	})
	if m.turnProvider != tp {
		t.Error("turnProvider not stored correctly")
	}
	if m.surveyPublisher != sp {
		t.Error("surveyPublisher not stored correctly")
	}
	if m.logger == nil {
		t.Error("logger not stored correctly")
	}
}

func TestGetCallingRelays_Success(t *testing.T) {
	token := &TurnToken{
		Username:    "user",
		Password:    "pass",
		TTLSeconds:  3600,
		URLs:        []string{"turn:example.com"},
		URLsWithIPs: []string{"turn:1.2.3.4:3478"},
		Hostname:    "example.com",
	}
	m := testCallingManager(&mockTurnProvider{token: token}, &mockSurveyPublisher{})

	resp, err := m.GetCallingRelays(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Relays) != 1 {
		t.Fatalf("got %d relays, want 1", len(resp.Relays))
	}
	if resp.Relays[0].Username != "user" {
		t.Errorf("got username %q, want %q", resp.Relays[0].Username, "user")
	}
	if resp.Relays[0].Password != "pass" {
		t.Errorf("got password %q, want %q", resp.Relays[0].Password, "pass")
	}
}

func TestGetCallingRelays_ProviderError(t *testing.T) {
	providerErr := errors.New("provider failed")
	m := testCallingManager(&mockTurnProvider{err: providerErr}, &mockSurveyPublisher{})

	_, err := m.GetCallingRelays(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if err != providerErr {
		t.Errorf("got error %v, want %v", err, providerErr)
	}
}

func TestCreateCallLinkAuth_NilZKConfig(t *testing.T) {
	m := testCallingManager(&mockTurnProvider{}, &mockSurveyPublisher{})

	_, err := m.CreateCallLinkAuth(context.Background(), "11111111-1111-1111-1111-111111111111", nil)
	if err == nil {
		t.Fatal("expected error without ZK config")
	}
	var target *InvalidCredentialRequestError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidCredentialRequestError, got %T", err)
	}
}

func TestCreateCallLinkAuth_InvalidUUID(t *testing.T) {
	m := testCallingManagerWithZK(&mockTurnProvider{}, &mockSurveyPublisher{})

	_, err := m.CreateCallLinkAuth(context.Background(), "not-a-uuid", nil)
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
	var target *InvalidCredentialRequestError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidCredentialRequestError, got %T", err)
	}
}

func TestCreateCallLinkAuth_WithZKConfig(t *testing.T) {
	m := testCallingManagerWithZK(&mockTurnProvider{}, &mockSurveyPublisher{})

	// Pass empty/nil request bytes - the deserialization will fail but that's
	// expected for this test path. We're testing the full flow works with ZK.
	resp, err := m.CreateCallLinkAuth(context.Background(), "11111111-1111-1111-1111-111111111111", nil)
	if err != nil {
		// Deserialization of nil bytes will fail, which is expected.
		var target *InvalidCredentialRequestError
		if !errors.As(err, &target) {
			t.Fatalf("expected *InvalidCredentialRequestError, got %T: %v", err, err)
		}
		return
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestCreateCallLinkAuth_ValidSerializedRequest(t *testing.T) {
	m := testCallingManagerWithZK(&mockTurnProvider{}, &mockSurveyPublisher{})

	// Create a valid CreateCallLinkCredentialRequest using the zkgroup API.
	var requestRandomness zkgroup.RandomnessBytes
	for i := range requestRandomness {
		requestRandomness[i] = byte(i)
	}
	roomID := []byte("test-room-id-123")
	reqCtx, err := zkgroup.NewCreateCallLinkCredentialRequestContext(roomID, requestRandomness)
	if err != nil {
		t.Fatalf("failed to create request context: %v", err)
	}

	// Get the serialized request that a client would send.
	request := reqCtx.GetRequest()

	// Serialize the request the same way a client would.
	serialized := zkgroup.SerializeCreateCallLinkCredentialRequest(request)

	resp, err := m.CreateCallLinkAuth(context.Background(), "11111111-1111-1111-1111-111111111111", serialized)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Credential) == 0 {
		t.Error("expected non-empty credential")
	}
	if resp.RedemptionTime == 0 {
		t.Error("expected non-zero redemption time")
	}
}

func TestCreateCallLinkAuth_ShortSerializedBytes(t *testing.T) {
	m := testCallingManagerWithZK(&mockTurnProvider{}, &mockSurveyPublisher{})

	// Valid zkgroup deserialization (leading 0 byte) but too short for
	// CreateCallLinkCredentialRequest (needs 96+ bytes after deserialization).
	shortBytes := make([]byte, 33)
	shortBytes[0] = 0 // valid reserved byte

	_, err := m.CreateCallLinkAuth(context.Background(), "11111111-1111-1111-1111-111111111111", shortBytes)
	if err == nil {
		t.Fatal("expected error for short request data")
	}
	var target *InvalidCredentialRequestError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidCredentialRequestError, got %T", err)
	}
}

func TestCreateCallLinkAuth_InvalidReservedByte(t *testing.T) {
	m := testCallingManagerWithZK(&mockTurnProvider{}, &mockSurveyPublisher{})

	// Pass bytes with invalid reserved byte (non-zero first byte).
	invalidBytes := []byte{0x01, 0x02, 0x03}
	_, err := m.CreateCallLinkAuth(context.Background(), "11111111-1111-1111-1111-111111111111", invalidBytes)
	if err == nil {
		t.Fatal("expected error for invalid reserved byte")
	}
	var target *InvalidCredentialRequestError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidCredentialRequestError, got %T", err)
	}
}

func TestCreateCallLinkAuth_EmptyUUID(t *testing.T) {
	m := testCallingManagerWithZK(&mockTurnProvider{}, &mockSurveyPublisher{})

	_, err := m.CreateCallLinkAuth(context.Background(), "", nil)
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
	var target *InvalidCredentialRequestError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidCredentialRequestError, got %T", err)
	}
}

func TestCreateCallLinkAuth_NilZKConfigMessage(t *testing.T) {
	m := testCallingManager(&mockTurnProvider{}, &mockSurveyPublisher{})

	_, err := m.CreateCallLinkAuth(context.Background(), "11111111-1111-1111-1111-111111111111", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var target *InvalidCredentialRequestError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidCredentialRequestError, got %T", err)
	}
	if target.Message != "calling zkgroup not configured" {
		t.Errorf("got message %q, want %q", target.Message, "calling zkgroup not configured")
	}
}

func TestGetCallingRelays_WrapsTokenInResponse(t *testing.T) {
	token := &TurnToken{
		Username: "u",
		Password: "p",
		URLs:     []string{"turn:a.com", "turn:b.com"},
	}
	m := testCallingManager(&mockTurnProvider{token: token}, &mockSurveyPublisher{})

	resp, err := m.GetCallingRelays(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Relays) != 1 {
		t.Fatalf("got %d relays, want 1", len(resp.Relays))
	}
	if len(resp.Relays[0].URLs) != 2 {
		t.Errorf("got %d URLs, want 2", len(resp.Relays[0].URLs))
	}
}

func TestSubmitCallQualitySurvey_CopiesAllFields(t *testing.T) {
	sp := &mockSurveyPublisher{}
	m := testCallingManager(&mockTurnProvider{}, sp)

	req := &CallQualitySurveyRequest{
		UserSatisfied:   true,
		StartTimestamp:  5000,
		EndTimestamp:    6000,
		CallType:        "VIDEO_CALL",
		Success:         false,
		CallEndReason:   "NETWORK_ERROR",
		QualityIssues:   []string{"pixelated"},
		AdditionalNotes: "bad quality",
		DebugLogURL:     "https://debug.example.com/abc",
	}

	err := m.SubmitCallQualitySurvey(context.Background(), req, "192.168.1.1", "Signal-iOS/5.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := sp.published[0]
	if !msg.UserSatisfied {
		t.Error("expected UserSatisfied true")
	}
	if msg.StartTimestamp != 5000 {
		t.Errorf("got StartTimestamp %d, want 5000", msg.StartTimestamp)
	}
	if msg.EndTimestamp != 6000 {
		t.Errorf("got EndTimestamp %d, want 6000", msg.EndTimestamp)
	}
	if msg.CallType != "VIDEO_CALL" {
		t.Errorf("got CallType %q, want %q", msg.CallType, "VIDEO_CALL")
	}
	if msg.Success {
		t.Error("expected Success false")
	}
	if msg.CallEndReason != "NETWORK_ERROR" {
		t.Errorf("got CallEndReason %q, want %q", msg.CallEndReason, "NETWORK_ERROR")
	}
	if len(msg.QualityIssues) != 1 || msg.QualityIssues[0] != "pixelated" {
		t.Errorf("got QualityIssues %v, want [pixelated]", msg.QualityIssues)
	}
	if msg.AdditionalNotes != "bad quality" {
		t.Errorf("got AdditionalNotes %q, want %q", msg.AdditionalNotes, "bad quality")
	}
	if msg.DebugLogURL != "https://debug.example.com/abc" {
		t.Errorf("got DebugLogURL %q, want %q", msg.DebugLogURL, "https://debug.example.com/abc")
	}
	if msg.ResponseID == "" {
		t.Error("expected non-empty ResponseID")
	}
	if msg.SubmissionTime == 0 {
		t.Error("expected non-zero SubmissionTime")
	}
}

func TestSubmitCallQualitySurvey_Success(t *testing.T) {
	sp := &mockSurveyPublisher{}
	m := testCallingManager(&mockTurnProvider{}, sp)

	req := &CallQualitySurveyRequest{
		UserSatisfied:  true,
		StartTimestamp: 1000,
		EndTimestamp:   2000,
		CallType:       "AUDIO_CALL",
		Success:        true,
		CallEndReason:  "CALLER_HUNG_UP",
	}

	err := m.SubmitCallQualitySurvey(context.Background(), req, "127.0.0.1", "Signal-Android/5.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sp.published) != 1 {
		t.Fatalf("expected 1 published survey, got %d", len(sp.published))
	}
	if sp.published[0].CallType != "AUDIO_CALL" {
		t.Errorf("got callType %q, want %q", sp.published[0].CallType, "AUDIO_CALL")
	}
	if sp.published[0].RemoteAddr != "127.0.0.1" {
		t.Errorf("got remoteAddr %q, want %q", sp.published[0].RemoteAddr, "127.0.0.1")
	}
}

func TestSubmitCallQualitySurvey_ValidationError(t *testing.T) {
	m := testCallingManager(&mockTurnProvider{}, &mockSurveyPublisher{})

	tests := []struct {
		name  string
		req   *CallQualitySurveyRequest
		field string
	}{
		{"missing start timestamp", &CallQualitySurveyRequest{EndTimestamp: 1, CallType: "A", CallEndReason: "B"}, "startTimestamp"},
		{"missing end timestamp", &CallQualitySurveyRequest{StartTimestamp: 1, CallType: "A", CallEndReason: "B"}, "endTimestamp"},
		{"missing call type", &CallQualitySurveyRequest{StartTimestamp: 1, EndTimestamp: 2, CallEndReason: "B"}, "callType"},
		{"missing call end reason", &CallQualitySurveyRequest{StartTimestamp: 1, EndTimestamp: 2, CallType: "A"}, "callEndReason"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.SubmitCallQualitySurvey(context.Background(), tt.req, "", "")
			if err == nil {
				t.Fatal("expected validation error")
			}
			var target *SurveyValidationError
			if !errors.As(err, &target) {
				t.Fatalf("expected *SurveyValidationError, got %T", err)
			}
			if target.Field != tt.field {
				t.Errorf("got field %q, want %q", target.Field, tt.field)
			}
		})
	}
}

func TestSubmitCallQualitySurvey_PublishError(t *testing.T) {
	publishErr := errors.New("publish failed")
	sp := &mockSurveyPublisher{err: publishErr}
	m := testCallingManager(&mockTurnProvider{}, sp)

	req := &CallQualitySurveyRequest{
		StartTimestamp: 1000,
		EndTimestamp:   2000,
		CallType:       "AUDIO_CALL",
		CallEndReason:  "CALLER_HUNG_UP",
	}

	err := m.SubmitCallQualitySurvey(context.Background(), req, "", "")
	if err == nil {
		t.Fatal("expected error")
	}
	var target *SurveyPublishError
	if !errors.As(err, &target) {
		t.Fatalf("expected *SurveyPublishError, got %T", err)
	}
}

func TestValidateSurvey_AllFieldsPresent(t *testing.T) {
	req := &CallQualitySurveyRequest{
		StartTimestamp: 1000,
		EndTimestamp:   2000,
		CallType:       "AUDIO_CALL",
		CallEndReason:  "CALLER_HUNG_UP",
	}
	if err := validateSurvey(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSurvey_EmptyRequest(t *testing.T) {
	req := &CallQualitySurveyRequest{}
	err := validateSurvey(req)
	if err == nil {
		t.Fatal("expected error for empty request")
	}
}

// destroyableMockTurnProvider is a mock that records Destroy calls.
type destroyableMockTurnProvider struct {
	mockTurnProvider
	destroyed bool
}

func (d *destroyableMockTurnProvider) Destroy() {
	d.destroyed = true
}

func TestCallingManager_Destroy(t *testing.T) {
	dp := &destroyableMockTurnProvider{}
	m := testCallingManager(dp, &mockSurveyPublisher{})

	m.Destroy()

	if !dp.destroyed {
		t.Fatal("expected Destroy to be called on turn provider")
	}
}

func TestCallingManager_Destroy_Idempotent(t *testing.T) {
	dp := &destroyableMockTurnProvider{}
	m := testCallingManager(dp, &mockSurveyPublisher{})

	m.Destroy()
	m.Destroy() // Should not panic.

	if !dp.destroyed {
		t.Fatal("expected Destroy to be called on turn provider")
	}
}

func TestCallingManager_Destroy_NonDestroyableProvider(t *testing.T) {
	// mockTurnProvider does NOT implement Destroy, so this tests
	// that CallingManager.Destroy does not panic when the provider
	// lacks a Destroy method.
	m := testCallingManager(&mockTurnProvider{}, &mockSurveyPublisher{})
	m.Destroy() // Should not panic.
}
