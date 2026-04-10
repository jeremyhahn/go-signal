package calling

import (
	"context"
	"crypto/rand"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
)

// CallingManager manages TURN relay credentials, call link credential issuance,
// and call quality survey submission. It delegates to pluggable providers for
// TURN credentials and survey publishing.
type CallingManager struct {
	turnProvider        TurnCredentialProvider
	genericServerSecret *zkgroup.GenericServerSecretParams
	surveyPublisher     SurveyPublisher
	logger              *slog.Logger
}

// CallingConfig holds the configuration required to create a CallingManager.
type CallingConfig struct {
	TurnProvider        TurnCredentialProvider
	GenericServerSecret *zkgroup.GenericServerSecretParams
	SurveyPublisher     SurveyPublisher
	Logger              *slog.Logger
}

// NewCallingManager creates a new CallingManager with the given configuration.
func NewCallingManager(cfg CallingConfig) *CallingManager {
	return &CallingManager{
		turnProvider:        cfg.TurnProvider,
		genericServerSecret: cfg.GenericServerSecret,
		surveyPublisher:     cfg.SurveyPublisher,
		logger:              cfg.Logger,
	}
}

// Destroy releases resources held by the CallingManager. If the configured
// TurnCredentialProvider implements a Destroy method, it is called to wipe
// protected key material from memory. The genericServerSecret reference is
// also cleared so the ZKGroup secret can be garbage collected.
func (m *CallingManager) Destroy() {
	type destroyer interface {
		Destroy()
	}
	if d, ok := m.turnProvider.(destroyer); ok {
		d.Destroy()
	}
	m.genericServerSecret = nil
}

// GetCallingRelays retrieves TURN credentials from the configured provider and
// returns them wrapped in a GetCallingRelaysResponse.
func (m *CallingManager) GetCallingRelays(ctx context.Context) (*GetCallingRelaysResponse, error) {
	token, err := m.turnProvider.RetrieveCredentials(ctx)
	if err != nil {
		m.logger.ErrorContext(ctx, "failed to retrieve TURN credentials", slog.String("error", err.Error()))
		return nil, err
	}
	return &GetCallingRelaysResponse{Relays: []TurnToken{*token}}, nil
}

// CreateCallLinkAuth issues a CreateCallLink credential using zkgroup,
// matching Java's CallLinkController.getCreateAuth(). The client sends a
// serialized CreateCallLinkCredentialRequest which contains a blinded room ID
// and blinding public key. The server issues a blinded credential response.
func (m *CallingManager) CreateCallLinkAuth(
	ctx context.Context,
	accountUUID string,
	requestBytes []byte,
) (*CreateCallLinkCredentialResponse, error) {

	if m.genericServerSecret == nil {
		return nil, &InvalidCredentialRequestError{Message: "calling zkgroup not configured"}
	}

	// Parse the account UUID into a 16-byte array for zkgroup.
	parsed, err := uuid.Parse(accountUUID)
	if err != nil {
		return nil, &InvalidCredentialRequestError{Message: "invalid account UUID: " + err.Error()}
	}

	var uuidBytes [16]byte
	copy(uuidBytes[:], parsed[:])
	userID := zkgroup.NewACI(uuidBytes)

	// Deserialize the client's CreateCallLinkCredentialRequest.
	// Java: new CreateCallLinkCredentialRequest(request.createCallLinkCredentialRequest())
	requestData, err := zkgroup.Deserialize(requestBytes)
	if err != nil {
		return nil, &InvalidCredentialRequestError{Message: "failed to deserialize credential request: " + err.Error()}
	}

	// Reconstruct the zkgroup CreateCallLinkCredentialRequest from the
	// deserialized data. The request contains a BlindedRoomID and a
	// BlindingPublicKey serialized by the client.
	callLinkRequest, err := zkgroup.DeserializeCreateCallLinkCredentialRequest(requestData)
	if err != nil {
		return nil, &InvalidCredentialRequestError{Message: "invalid call link credential request: " + err.Error()}
	}

	// Calculate today's day-aligned timestamp for the credential.
	// Java: Instant.now().truncatedTo(ChronoUnit.DAYS)
	now := time.Now().UTC()
	todaySeconds := uint64(now.Unix())
	dayAligned := (todaySeconds / zkgroup.SecondsPerDay) * zkgroup.SecondsPerDay
	timestamp := zkgroup.NewTimestamp(dayAligned)

	// Generate randomness for credential issuance.
	var randomness zkgroup.RandomnessBytes
	if _, err := rand.Read(randomness[:]); err != nil {
		return nil, &InvalidCredentialRequestError{Message: "failed to generate randomness: " + err.Error()}
	}

	// Issue the blinded credential using the client's request.
	// Java: createCallLinkCredentialRequest.issueCredential(aci, timestamp, genericServerSecretParams)
	response, err := callLinkRequest.Issue(userID, timestamp, m.genericServerSecret, randomness)
	if err != nil {
		m.logger.ErrorContext(ctx, "failed to issue create call link credential", slog.String("error", err.Error()))
		return nil, &InvalidCredentialRequestError{Message: "credential issuance failed: " + err.Error()}
	}

	// Serialize the response for the client.
	// Java: .serialize()
	credential := zkgroup.Serialize(zkgroup.EncodeCreateCallLinkCredentialResponse(response))

	m.logger.DebugContext(ctx, "issued create call link credential",
		slog.String("accountUUID", accountUUID),
		slog.Uint64("redemptionTime", dayAligned),
	)

	return &CreateCallLinkCredentialResponse{
		Credential:     credential,
		RedemptionTime: int64(dayAligned),
	}, nil
}

// SubmitCallQualitySurvey validates and publishes a call quality survey.
func (m *CallingManager) SubmitCallQualitySurvey(
	ctx context.Context,
	request *CallQualitySurveyRequest,
	remoteAddr string,
	userAgent string,
) error {
	if err := validateSurvey(request); err != nil {
		return err
	}

	msg := &CallQualitySurveyMessage{
		ResponseID:      uuid.NewString(),
		SubmissionTime:  time.Now().UnixMilli(),
		UserSatisfied:   request.UserSatisfied,
		StartTimestamp:  request.StartTimestamp,
		EndTimestamp:    request.EndTimestamp,
		CallType:        request.CallType,
		Success:         request.Success,
		CallEndReason:   request.CallEndReason,
		QualityIssues:   request.QualityIssues,
		AdditionalNotes: request.AdditionalNotes,
		DebugLogURL:     request.DebugLogURL,
		RemoteAddr:      remoteAddr,
	}

	if err := m.surveyPublisher.Publish(ctx, msg); err != nil {
		m.logger.ErrorContext(ctx, "failed to publish call quality survey", slog.String("error", err.Error()))
		return &SurveyPublishError{Cause: err}
	}

	return nil
}

// validateSurvey checks required fields in a call quality survey request.
func validateSurvey(req *CallQualitySurveyRequest) error {
	if req.StartTimestamp == 0 {
		return &SurveyValidationError{Field: "startTimestamp"}
	}
	if req.EndTimestamp == 0 {
		return &SurveyValidationError{Field: "endTimestamp"}
	}
	if req.CallType == "" {
		return &SurveyValidationError{Field: "callType"}
	}
	if req.CallEndReason == "" {
		return &SurveyValidationError{Field: "callEndReason"}
	}
	return nil
}
