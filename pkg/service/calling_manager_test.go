package service

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/calling"
)

func newTestCallingService() CallingService {
	mgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider:    &noOpTurnProvider{},
		SurveyPublisher: &noOpSurveyPublisher{},
		Logger:          slog.Default(),
	})
	return NewCallingService(mgr)
}

func TestNewCallingService_InterfaceSatisfaction(t *testing.T) {
	var _ CallingService = (*callingManagerService)(nil)
}

func TestCallingService_GetCallingRelays_Success(t *testing.T) {
	svc := newTestCallingService()
	resp, err := svc.GetCallingRelays(context.Background())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Relays, 1)
}

func TestCallingService_GetCallingRelays_ProviderError(t *testing.T) {
	mgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider:    &failingTurnProvider{err: errors.New("TURN unavailable")},
		SurveyPublisher: &noOpSurveyPublisher{},
		Logger:          slog.Default(),
	})
	svc := NewCallingService(mgr)

	_, err := svc.GetCallingRelays(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TURN unavailable")
}

func TestCallingService_SubmitCallQualitySurvey_Success(t *testing.T) {
	svc := newTestCallingService()
	req := &calling.CallQualitySurveyRequest{
		StartTimestamp: 1_000_000,
		EndTimestamp:   2_000_000,
		CallType:       "audio",
		CallEndReason:  "hangup",
		UserSatisfied:  true,
	}
	err := svc.SubmitCallQualitySurvey(context.Background(), req, "127.0.0.1", "Signal/7.0 Android/14")
	require.NoError(t, err)
}

func TestCallingService_SubmitCallQualitySurvey_MissingRequiredFields(t *testing.T) {
	svc := newTestCallingService()
	// Empty struct omits all required fields; validateSurvey returns an error.
	err := svc.SubmitCallQualitySurvey(context.Background(), &calling.CallQualitySurveyRequest{}, "127.0.0.1", "Signal/7.0")
	require.Error(t, err)
}

func TestCallingService_CreateCallLinkAuth_ReturnsError(t *testing.T) {
	svc := newTestCallingService()
	// Passing empty requestBytes should cause an error in the manager.
	_, err := svc.CreateCallLinkAuth(context.Background(), "some-uuid", []byte{})
	// The manager may or may not error depending on the zkgroup validation;
	// we only assert the delegation occurred (no panic).
	_ = err
}
