// Package grpcclient implements registration.Client by talking to a
// remote registration-service binary over gRPC. The wire surface is
// regpb.RegistrationServiceClient; this adapter translates between the
// proto types and the chat-server-side
// *verification.VerificationSession + verification.* error contract so
// callers can stay transport-agnostic.
package grpcclient

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"

	regpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/registrationservice"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// Config configures the gRPC client. Either Conn or Endpoint must be
// set: Conn lets callers wire their own dial options (mTLS,
// interceptors); Endpoint opens a default insecure-credentials channel
// using grpc.NewClient. The latter is intended for development and
// integration tests only.
type Config struct {
	// Conn is a pre-built grpc.ClientConn. When supplied, Endpoint and
	// DialOptions are ignored. Ownership stays with the caller; Close
	// is a no-op when Conn was supplied.
	Conn *grpc.ClientConn
	// Endpoint is the host:port to dial when Conn is nil.
	Endpoint string
	// DialOptions are forwarded to grpc.NewClient when Endpoint is used.
	DialOptions []grpc.DialOption
	// Timeout caps each RPC. Zero means no timeout (the caller's ctx
	// governs).
	Timeout time.Duration
}

// Client implements registration.Client via gRPC.
type Client struct {
	cc      *grpc.ClientConn
	owned   bool
	stub    regpb.RegistrationServiceClient
	timeout time.Duration
}

// New constructs a Client. Either Config.Conn or Config.Endpoint is
// required; passing both is an error.
func New(cfg Config) (*Client, error) {
	if (cfg.Conn != nil) == (cfg.Endpoint != "") {
		return nil, errors.New("grpcclient: exactly one of Conn or Endpoint is required")
	}
	var (
		cc    *grpc.ClientConn
		owned bool
		err   error
	)
	if cfg.Conn != nil {
		cc = cfg.Conn
	} else {
		cc, err = grpc.NewClient(cfg.Endpoint, cfg.DialOptions...)
		if err != nil {
			return nil, err
		}
		owned = true
	}
	return &Client{
		cc:      cc,
		owned:   owned,
		stub:    regpb.NewRegistrationServiceClient(cc),
		timeout: cfg.Timeout,
	}, nil
}

var _ registration.Client = (*Client)(nil)

// Close shuts down the underlying gRPC channel iff the Client owns it.
func (c *Client) Close() error {
	if c.owned && c.cc != nil {
		return c.cc.Close()
	}
	return nil
}

// CreateSession calls RegistrationService.CreateSession and decodes the
// response envelope.
func (c *Client) CreateSession(ctx context.Context, number string) (*verification.VerificationSession, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	e164 := parseE164(number)
	resp, err := c.stub.CreateSession(ctx, &regpb.CreateRegistrationSessionRequest{E164: e164})
	if err != nil {
		return nil, err
	}
	if errPb := resp.GetError(); errPb != nil {
		return nil, decodeCreateError(errPb, number)
	}
	return decodeSessionMetadata(resp.GetSessionMetadata(), number)
}

// GetSession calls RegistrationService.GetSessionMetadata.
func (c *Client) GetSession(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	idBytes, err := encodeSessionID(sessionID)
	if err != nil {
		return nil, &verification.SessionNotFoundError{SessionID: sessionID}
	}
	resp, err := c.stub.GetSessionMetadata(ctx, &regpb.GetRegistrationSessionMetadataRequest{SessionId: idBytes})
	if err != nil {
		return nil, err
	}
	if errPb := resp.GetError(); errPb != nil {
		return nil, decodeGetError(errPb, sessionID)
	}
	return decodeSessionMetadata(resp.GetSessionMetadata(), "")
}

// SendCode calls RegistrationService.SendVerificationCode.
func (c *Client) SendCode(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	idBytes, err := encodeSessionID(sessionID)
	if err != nil {
		return nil, &verification.SessionNotFoundError{SessionID: sessionID}
	}
	resp, err := c.stub.SendVerificationCode(ctx, &regpb.SendVerificationCodeRequest{
		SessionId: idBytes,
		Transport: regpb.MessageTransport_MESSAGE_TRANSPORT_SMS,
	})
	if err != nil {
		return nil, err
	}
	if errPb := resp.GetError(); errPb != nil {
		return nil, decodeSendError(errPb, sessionID)
	}
	return decodeSessionMetadata(resp.GetSessionMetadata(), "")
}

// SubmitCode calls RegistrationService.CheckVerificationCode.
func (c *Client) SubmitCode(ctx context.Context, sessionID, code string) (*verification.VerificationSession, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	idBytes, err := encodeSessionID(sessionID)
	if err != nil {
		return nil, &verification.SessionNotFoundError{SessionID: sessionID}
	}
	resp, err := c.stub.CheckVerificationCode(ctx, &regpb.CheckVerificationCodeRequest{
		SessionId:        idBytes,
		VerificationCode: code,
	})
	if err != nil {
		return nil, err
	}
	if errPb := resp.GetError(); errPb != nil {
		return nil, decodeCheckError(errPb, sessionID, resp.GetSessionMetadata())
	}
	return decodeSessionMetadata(resp.GetSessionMetadata(), "")
}

func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

// --- proto decode helpers -----------------------------------------------

func decodeSessionMetadata(md *regpb.RegistrationSessionMetadata, fallbackNumber string) (*verification.VerificationSession, error) {
	if md == nil {
		return nil, errors.New("grpcclient: empty session metadata")
	}
	id, err := uuid.FromBytes(md.GetSessionId())
	if err != nil {
		return nil, err
	}
	number := encodeE164(md.GetE164())
	if number == "" {
		number = fallbackNumber
	}
	now := time.Now()
	session := &verification.VerificationSession{
		ID:                   id.String(),
		Number:               number,
		Verified:             md.GetVerified(),
		AllowedToRequestCode: md.GetMayRequestSms(),
		ExpiresAt:            addSeconds(now, md.GetExpirationSeconds()),
		NextCodeRequestAt:    addSeconds(now, md.GetNextSmsSeconds()),
	}
	return session, nil
}

func decodeCreateError(e *regpb.CreateRegistrationSessionError, _ string) error {
	switch e.GetErrorType() {
	case regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_RATE_LIMITED:
		// Map to SessionLimitExceededError so the REST handler returns
		// 429 — that is the closest match for the chat-server-facing
		// contract; the underlying RPC error type is a server-wide
		// throttle rather than a per-session one.
		return &verification.SessionLimitExceededError{}
	case regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_ILLEGAL_PHONE_NUMBER:
		return errors.New("registration-service: illegal phone number")
	default:
		return errors.New("registration-service: create session failed")
	}
}

func decodeGetError(e *regpb.GetRegistrationSessionMetadataError, sessionID string) error {
	switch e.GetErrorType() {
	case regpb.GetRegistrationSessionMetadataErrorType_GET_REGISTRATION_SESSION_METADATA_ERROR_TYPE_NOT_FOUND:
		return &verification.SessionNotFoundError{SessionID: sessionID}
	default:
		return errors.New("registration-service: get session failed")
	}
}

func decodeSendError(e *regpb.SendVerificationCodeError, sessionID string) error {
	switch e.GetErrorType() {
	case regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND:
		return &verification.SessionNotFoundError{SessionID: sessionID}
	case regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED:
		return &verification.RequestCodeRateLimitedError{
			SessionID:  sessionID,
			RetryAfter: time.Duration(e.GetRetryAfterSeconds()) * time.Second,
		}
	case regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SENDER_REJECTED:
		return &verification.TransportError{
			Transport:   "registration-service",
			Destination: sessionID,
			Cause:       errors.New("sender rejected"),
		}
	case regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_ALREADY_VERIFIED:
		return errors.New("registration-service: session already verified")
	case regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_TRANSPORT_NOT_ALLOWED:
		return errors.New("registration-service: transport not allowed")
	case regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SUSPECTED_FRAUD:
		return errors.New("registration-service: suspected fraud")
	default:
		return errors.New("registration-service: send code failed")
	}
}

func decodeCheckError(e *regpb.CheckVerificationCodeError, sessionID string, md *regpb.RegistrationSessionMetadata) error {
	switch e.GetErrorType() {
	case regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND:
		return &verification.SessionNotFoundError{SessionID: sessionID}
	case regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_NO_CODE_SENT:
		return &verification.CodeExpiredError{SessionID: sessionID}
	case regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_ATTEMPT_EXPIRED:
		return &verification.CodeExpiredError{SessionID: sessionID}
	case regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED:
		// Java collapses bad-guess and attempts-cap onto the same wire
		// code. Distinguish by may_check_code in the metadata: when the
		// server has clamped further checks the caller wants
		// MaxAttemptsExceededError; otherwise it was a bad guess.
		if md != nil && !md.GetMayCheckCode() {
			return &verification.MaxAttemptsExceededError{SessionID: sessionID}
		}
		return &verification.InvalidCodeError{SessionID: sessionID}
	default:
		return errors.New("registration-service: check code failed")
	}
}

func encodeSessionID(s string) ([]byte, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, err
	}
	return id.MarshalBinary()
}

func encodeE164(n uint64) string {
	if n == 0 {
		return ""
	}
	return "+" + strconv.FormatUint(n, 10)
}

func parseE164(s string) uint64 {
	if !strings.HasPrefix(s, "+") {
		return 0
	}
	n, err := strconv.ParseUint(s[1:], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func addSeconds(t time.Time, secs uint64) time.Time {
	if secs == 0 {
		return time.Time{}
	}
	return t.Add(time.Duration(secs) * time.Second)
}
