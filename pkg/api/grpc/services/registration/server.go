// Package registration hosts the gRPC server-side implementation of
// the RegistrationService.proto contract. It is the wire surface the
// standalone cmd/registration-service binary exposes; it delegates to
// the underlying *core.Service for all session lifecycle and transport
// orchestration.
//
// Wire mapping notes:
//
//   - Proto session_id is `bytes`. Our session.ID is a UUID string. We
//     marshal via uuid.Parse(...).MarshalBinary() and unmarshal via
//     uuid.FromBytes — a 1:1 round-trip.
//   - Proto e164 is uint64 — the E.164 number with the leading "+"
//     stripped. We format back to "+%d" for the storage-side string.
//   - The proto's `accept_language`, `client_type`, `sender_name`, and
//     `mcc`/`mnc`/`rate_limit_collation_key` fields are accepted for
//     wire-compatibility but currently ignored by the server: the
//     underlying *core.Service does not yet plumb them through (Phase
//     4.1 baseline). Production deployments using Twilio routing will
//     want to surface these to the transport once a future revision
//     extends the transport interface.
package registration

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	regpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/registrationservice"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// Server implements regpb.RegistrationServiceServer by delegating to
// *core.Service. One Server is shared across all RPCs.
type Server struct {
	regpb.UnimplementedRegistrationServiceServer
	svc *core.Service
}

// NewServer constructs a Server backed by svc.
func NewServer(svc *core.Service) *Server {
	if svc == nil {
		panic("registration: Service is required")
	}
	return &Server{svc: svc}
}

// CreateSession implements regpb.RegistrationServiceServer.
func (s *Server) CreateSession(ctx context.Context, req *regpb.CreateRegistrationSessionRequest) (*regpb.CreateRegistrationSessionResponse, error) {
	number := encodeE164(req.GetE164())
	if number == "" {
		return &regpb.CreateRegistrationSessionResponse{
			Response: &regpb.CreateRegistrationSessionResponse_Error{
				Error: &regpb.CreateRegistrationSessionError{
					ErrorType: regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_ILLEGAL_PHONE_NUMBER,
				},
			},
		}, nil
	}

	session, err := s.svc.CreateSession(ctx, number)
	if err != nil {
		var limitExceeded *verification.SessionLimitExceededError
		if errors.As(err, &limitExceeded) {
			return &regpb.CreateRegistrationSessionResponse{
				Response: &regpb.CreateRegistrationSessionResponse_Error{
					Error: &regpb.CreateRegistrationSessionError{
						ErrorType:         regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_RATE_LIMITED,
						MayRetry:          true,
						RetryAfterSeconds: 0,
					},
				},
			}, nil
		}
		return nil, status.Error(codes.Internal, "create session failed")
	}

	return &regpb.CreateRegistrationSessionResponse{
		Response: &regpb.CreateRegistrationSessionResponse_SessionMetadata{
			SessionMetadata: sessionMetadata(session),
		},
	}, nil
}

// GetSessionMetadata implements regpb.RegistrationServiceServer.
func (s *Server) GetSessionMetadata(ctx context.Context, req *regpb.GetRegistrationSessionMetadataRequest) (*regpb.GetRegistrationSessionMetadataResponse, error) {
	sessionID, ok := decodeSessionID(req.GetSessionId())
	if !ok {
		return notFoundMetadataResponse(), nil
	}
	session, err := s.svc.GetSession(ctx, sessionID)
	if err != nil {
		var notFound *verification.SessionNotFoundError
		var expired *verification.SessionExpiredError
		if errors.As(err, &notFound) || errors.As(err, &expired) {
			return notFoundMetadataResponse(), nil
		}
		return nil, status.Error(codes.Internal, "get session failed")
	}
	return &regpb.GetRegistrationSessionMetadataResponse{
		Response: &regpb.GetRegistrationSessionMetadataResponse_SessionMetadata{
			SessionMetadata: sessionMetadata(session),
		},
	}, nil
}

// SendVerificationCode implements regpb.RegistrationServiceServer.
func (s *Server) SendVerificationCode(ctx context.Context, req *regpb.SendVerificationCodeRequest) (*regpb.SendVerificationCodeResponse, error) {
	sessionID, ok := decodeSessionID(req.GetSessionId())
	if !ok {
		return &regpb.SendVerificationCodeResponse{
			Error: &regpb.SendVerificationCodeError{
				ErrorType: regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
			},
		}, nil
	}
	session, err := s.svc.SendCode(ctx, sessionID)
	if err != nil {
		return sendVerificationCodeErrorResponse(ctx, s.svc, sessionID, err), nil
	}
	return &regpb.SendVerificationCodeResponse{
		SessionMetadata: sessionMetadata(session),
	}, nil
}

// CheckVerificationCode implements regpb.RegistrationServiceServer.
func (s *Server) CheckVerificationCode(ctx context.Context, req *regpb.CheckVerificationCodeRequest) (*regpb.CheckVerificationCodeResponse, error) {
	sessionID, ok := decodeSessionID(req.GetSessionId())
	if !ok {
		return &regpb.CheckVerificationCodeResponse{
			Error: &regpb.CheckVerificationCodeError{
				ErrorType: regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
			},
		}, nil
	}
	session, err := s.svc.SubmitCode(ctx, sessionID, req.GetVerificationCode())
	if err != nil {
		return checkVerificationCodeErrorResponse(ctx, s.svc, sessionID, err), nil
	}
	return &regpb.CheckVerificationCodeResponse{
		SessionMetadata: sessionMetadata(session),
	}, nil
}

// --- Wire mapping helpers ------------------------------------------------

// sessionMetadata projects a *verification.VerificationSession onto the
// proto RegistrationSessionMetadata shape. CaptchaRequired is NOT
// surfaced — captcha lives on the chat-server side. session.Attempts
// is folded into may_check_code so callers can decide whether another
// submit is allowed.
func sessionMetadata(s *verification.VerificationSession) *regpb.RegistrationSessionMetadata {
	now := time.Now()
	idBytes, _ := encodeSessionID(s.ID)
	return &regpb.RegistrationSessionMetadata{
		SessionId:            idBytes,
		Verified:             s.Verified,
		E164:                 parseE164(s.Number),
		MayRequestSms:        canRequestCode(s),
		NextSmsSeconds:       waitSeconds(now, s.NextCodeRequestAt),
		MayRequestVoiceCall:  canRequestCode(s),
		NextVoiceCallSeconds: waitSeconds(now, s.NextCodeRequestAt),
		MayCheckCode:         s.Code != "" && s.Attempts < attemptCap(s),
		NextCodeCheckSeconds: 0,
		ExpirationSeconds:    waitSeconds(now, s.ExpiresAt),
	}
}

func canRequestCode(s *verification.VerificationSession) bool {
	if s.Verified {
		return false
	}
	if s.NextCodeRequestAt.IsZero() {
		return true
	}
	return !time.Now().Before(s.NextCodeRequestAt)
}

// attemptCap is the per-session max-attempts ceiling. The server config
// owns the real cap; for the metadata projection we use a generous
// default that matches core.Config defaults (3). Callers can still
// distinguish "cap reached" from the SubmitCode error returned later.
func attemptCap(_ *verification.VerificationSession) int {
	return 3
}

func waitSeconds(now, t time.Time) uint64 {
	if t.IsZero() || !now.Before(t) {
		return 0
	}
	d := t.Sub(now)
	// Round up to the next second so a 999ms wait reports as 1, not 0.
	secs := int64(d / time.Second)
	if d%time.Second != 0 {
		secs++
	}
	if secs < 0 {
		return 0
	}
	// #nosec G115 -- secs is bounded non-negative above.
	return uint64(secs)
}

// encodeSessionID converts a UUID string to its 16-byte big-endian form.
func encodeSessionID(s string) ([]byte, bool) {
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, false
	}
	b, err := id.MarshalBinary()
	if err != nil {
		return nil, false
	}
	return b, true
}

// decodeSessionID converts a 16-byte big-endian UUID back to its
// canonical string form.
func decodeSessionID(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	if len(b) == 36 {
		// Tolerant of clients that pass the string form encoded as
		// bytes; validate by parsing.
		if _, err := uuid.Parse(string(b)); err == nil {
			return string(b), true
		}
		return "", false
	}
	id, err := uuid.FromBytes(b)
	if err != nil {
		return "", false
	}
	return id.String(), true
}

// encodeE164 converts the proto's uint64 form (e.g. 15551234567) into a
// canonical "+15551234567" string. A zero value returns "" so callers
// can treat the input as illegal.
func encodeE164(n uint64) string {
	if n == 0 {
		return ""
	}
	return "+" + strconv.FormatUint(n, 10)
}

// parseE164 converts a "+15551234567"-shaped string back to the
// proto's uint64 form. Returns 0 on any parse failure — the proto's
// metadata then surfaces 0 to the client which mirrors Java for
// non-canonical numbers.
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

func notFoundMetadataResponse() *regpb.GetRegistrationSessionMetadataResponse {
	return &regpb.GetRegistrationSessionMetadataResponse{
		Response: &regpb.GetRegistrationSessionMetadataResponse_Error{
			Error: &regpb.GetRegistrationSessionMetadataError{
				ErrorType: regpb.GetRegistrationSessionMetadataErrorType_GET_REGISTRATION_SESSION_METADATA_ERROR_TYPE_NOT_FOUND,
			},
		},
	}
}

// sendVerificationCodeErrorResponse maps a SendCode error onto the proto
// envelope. When the underlying state is available we attach the
// session metadata so the client can compute next-attempt timing.
func sendVerificationCodeErrorResponse(ctx context.Context, svc *core.Service, sessionID string, err error) *regpb.SendVerificationCodeResponse {
	resp := &regpb.SendVerificationCodeResponse{Error: &regpb.SendVerificationCodeError{}}
	var (
		notFound       *verification.SessionNotFoundError
		expired        *verification.SessionExpiredError
		rateLimited    *verification.RequestCodeRateLimitedError
		transportError *verification.TransportError
	)
	switch {
	case errors.As(err, &notFound):
		resp.Error.ErrorType = regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND
	case errors.As(err, &expired):
		resp.Error.ErrorType = regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND
	case errors.As(err, &rateLimited):
		resp.Error.ErrorType = regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED
		resp.Error.MayRetry = true
		retrySecs := int64(rateLimited.RetryAfter / time.Second)
		if rateLimited.RetryAfter%time.Second != 0 {
			retrySecs++
		}
		if retrySecs < 0 {
			retrySecs = 0
		}
		// #nosec G115 -- retrySecs is bounded non-negative above.
		resp.Error.RetryAfterSeconds = uint64(retrySecs)
	case errors.As(err, &transportError):
		resp.Error.ErrorType = regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SENDER_REJECTED
		resp.Error.MayRetry = true
	default:
		resp.Error.ErrorType = regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_UNSPECIFIED
	}
	if session, getErr := svc.GetSession(ctx, sessionID); getErr == nil {
		resp.SessionMetadata = sessionMetadata(session)
	}
	return resp
}

// checkVerificationCodeErrorResponse maps a SubmitCode error onto the
// proto envelope. Session metadata is attached when available so the
// caller can compute next-attempt cooldowns from a single response.
func checkVerificationCodeErrorResponse(ctx context.Context, svc *core.Service, sessionID string, err error) *regpb.CheckVerificationCodeResponse {
	resp := &regpb.CheckVerificationCodeResponse{Error: &regpb.CheckVerificationCodeError{}}
	var (
		notFound    *verification.SessionNotFoundError
		expired     *verification.SessionExpiredError
		codeExpired *verification.CodeExpiredError
		maxAttempts *verification.MaxAttemptsExceededError
		invalidCode *verification.InvalidCodeError
	)
	switch {
	case errors.As(err, &notFound):
		resp.Error.ErrorType = regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND
	case errors.As(err, &expired):
		resp.Error.ErrorType = regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND
	case errors.As(err, &codeExpired):
		resp.Error.ErrorType = regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_ATTEMPT_EXPIRED
	case errors.As(err, &maxAttempts):
		resp.Error.ErrorType = regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED
	case errors.As(err, &invalidCode):
		// Java mirror: a bad guess is a "rate limited" attempt (the
		// attempts counter advanced). The metadata reports may_check
		// _code, so the client can re-try until that flips false.
		resp.Error.ErrorType = regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED
		resp.Error.MayRetry = true
	default:
		resp.Error.ErrorType = regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_UNSPECIFIED
	}
	if session, getErr := svc.GetSession(ctx, sessionID); getErr == nil {
		resp.SessionMetadata = sessionMetadata(session)
	}
	return resp
}
