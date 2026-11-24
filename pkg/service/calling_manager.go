package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/calling"
)

// CallingService provides TURN relay and call-link credentials; CallSignalingService relays WebRTC signaling.
type CallingService interface {
	// GetCallingRelays retrieves TURN credentials for call setup.
	GetCallingRelays(ctx context.Context) (*calling.GetCallingRelaysResponse, error)

	// CreateCallLinkAuth issues a CreateCallLink credential using zkgroup.
	CreateCallLinkAuth(
		ctx context.Context,
		accountUUID string,
		requestBytes []byte,
	) (*calling.CreateCallLinkCredentialResponse, error)

	// SubmitCallQualitySurvey validates and publishes a call quality survey.
	SubmitCallQualitySurvey(
		ctx context.Context,
		request *calling.CallQualitySurveyRequest,
		remoteAddr string,
		userAgent string,
	) error
}

// callingManagerService is the default CallingService backed by a CallingManager.
type callingManagerService struct {
	manager *calling.CallingManager
}

// NewCallingService returns a CallingService that delegates to the given
// CallingManager. The manager must not be nil.
func NewCallingService(manager *calling.CallingManager) CallingService {
	return &callingManagerService{manager: manager}
}

func (s *callingManagerService) GetCallingRelays(ctx context.Context) (*calling.GetCallingRelaysResponse, error) {
	return s.manager.GetCallingRelays(ctx)
}

func (s *callingManagerService) CreateCallLinkAuth(
	ctx context.Context,
	accountUUID string,
	requestBytes []byte,
) (*calling.CreateCallLinkCredentialResponse, error) {
	return s.manager.CreateCallLinkAuth(ctx, accountUUID, requestBytes)
}

func (s *callingManagerService) SubmitCallQualitySurvey(
	ctx context.Context,
	request *calling.CallQualitySurveyRequest,
	remoteAddr string,
	userAgent string,
) error {
	return s.manager.SubmitCallQualitySurvey(ctx, request, remoteAddr, userAgent)
}

// Compile-time assertion: CallingManager must satisfy CallingService.
var _ CallingService = (*calling.CallingManager)(nil)
