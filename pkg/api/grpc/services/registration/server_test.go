package registration

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	regpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/registrationservice"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// stubTransport is a no-op transport whose code-dispatch never fails;
// the core test suite covers transport failure paths directly.
type stubTransport struct{ codes []string }

func (s *stubTransport) SendCode(_ context.Context, _, code string, _ ...verification.SendOption) error {
	s.codes = append(s.codes, code)
	return nil
}
func (s *stubTransport) Name() string { return "stub" }

func newGRPCStub(t *testing.T, coreSvc *core.Service) regpb.RegistrationServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	regpb.RegisterRegistrationServiceServer(gs, NewServer(coreSvc))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
		return nil
	}
	t.Cleanup(func() { _ = conn.Close() })
	return regpb.NewRegistrationServiceClient(conn)
}

func TestGRPCCreateSession_HappyPath(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	resp, err := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551112222})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	md := resp.GetSessionMetadata()
	if md == nil {
		t.Fatal("expected SessionMetadata; got error response")
	}
	if md.GetE164() != 15551112222 {
		t.Errorf("E164 round-trip = %d", md.GetE164())
	}
	if len(md.GetSessionId()) != 16 {
		t.Errorf("session_id length = %d, want 16", len(md.GetSessionId()))
	}
}

func TestGRPCCreateSession_IllegalPhoneNumber(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)
	resp, err := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 0})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_ILLEGAL_PHONE_NUMBER {
		t.Errorf("expected ILLEGAL_PHONE_NUMBER, got %v", resp)
	}
}

func TestGRPCGetSessionMetadata_NotFound(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)
	id := uuid.New()
	idBytes, _ := id.MarshalBinary()
	resp, err := client.GetSessionMetadata(context.Background(), &regpb.GetRegistrationSessionMetadataRequest{SessionId: idBytes})
	if err != nil {
		t.Fatalf("GetSessionMetadata: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.GetRegistrationSessionMetadataErrorType_GET_REGISTRATION_SESSION_METADATA_ERROR_TYPE_NOT_FOUND {
		t.Errorf("expected NOT_FOUND, got %v", resp)
	}
}

func TestGRPCSendCheckRoundTrip(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{FixedCode: "424242"})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	resp, err := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sid := resp.GetSessionMetadata().GetSessionId()

	sendResp, err := client.SendVerificationCode(context.Background(), &regpb.SendVerificationCodeRequest{SessionId: sid, Transport: regpb.MessageTransport_MESSAGE_TRANSPORT_SMS})
	if err != nil {
		t.Fatalf("SendVerificationCode: %v", err)
	}
	if sendResp.GetError() != nil {
		t.Fatalf("send error: %v", sendResp.GetError())
	}

	checkResp, err := client.CheckVerificationCode(context.Background(), &regpb.CheckVerificationCodeRequest{SessionId: sid, VerificationCode: "424242"})
	if err != nil {
		t.Fatalf("CheckVerificationCode: %v", err)
	}
	if checkResp.GetError() != nil {
		t.Fatalf("check error: %v", checkResp.GetError())
	}
	if !checkResp.GetSessionMetadata().GetVerified() {
		t.Error("verified must be true after a matching code submission")
	}
}

func TestGRPCSendVerificationCode_RateLimit(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{
		RequestCodeCooldowns: []time.Duration{0, time.Hour},
	})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)
	resp, _ := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551})
	sid := resp.GetSessionMetadata().GetSessionId()
	if _, err := client.SendVerificationCode(context.Background(), &regpb.SendVerificationCodeRequest{SessionId: sid}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	second, err := client.SendVerificationCode(context.Background(), &regpb.SendVerificationCodeRequest{SessionId: sid})
	if err != nil {
		t.Fatalf("second send: %v", err)
	}
	if second.GetError() == nil ||
		second.GetError().GetErrorType() != regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED {
		t.Errorf("expected RATE_LIMITED, got %v", second)
	}
	if second.GetError().GetRetryAfterSeconds() == 0 {
		t.Error("RetryAfterSeconds should be > 0 on rate-limit")
	}
}

func TestSessionIDRoundTrip_StringFormFromClient(t *testing.T) {
	id := uuid.New()
	got, ok := decodeSessionID([]byte(id.String()))
	if !ok || got != id.String() {
		t.Errorf("decodeSessionID(string form) = %q, %v", got, ok)
	}
}

func TestSessionIDRoundTrip_BinaryForm(t *testing.T) {
	id := uuid.New()
	b, _ := id.MarshalBinary()
	got, ok := decodeSessionID(b)
	if !ok || got != id.String() {
		t.Errorf("decodeSessionID(binary form) = %q, %v", got, ok)
	}
}

func TestSessionIDRoundTrip_BadInputs(t *testing.T) {
	if _, ok := decodeSessionID(nil); ok {
		t.Error("nil should not parse")
	}
	if _, ok := decodeSessionID([]byte("not-a-uuid")); ok {
		t.Error("short garbage should not parse")
	}
	if _, ok := decodeSessionID([]byte("not-a-uuid-but-thirty-six-chars-abc!")); ok {
		t.Error("36-byte garbage should not parse")
	}
	if _, ok := encodeSessionID("not-a-uuid"); ok {
		t.Error("non-uuid input must not encode")
	}
}

func TestParseE164(t *testing.T) {
	if got := parseE164("+15551"); got != 15551 {
		t.Errorf("parseE164(+15551) = %d", got)
	}
	if got := parseE164("15551"); got != 0 {
		t.Errorf("parseE164 missing +: got %d, want 0", got)
	}
	if got := parseE164("+abc"); got != 0 {
		t.Errorf("parseE164 non-numeric: got %d", got)
	}
}

func TestEncodeE164(t *testing.T) {
	if got := encodeE164(15551112222); got != "+15551112222" {
		t.Errorf("encodeE164 = %q", got)
	}
	if got := encodeE164(0); got != "" {
		t.Errorf("encodeE164(0) = %q", got)
	}
}

// integration sanity: SendCode for an unknown session id returns the
// proto error envelope, not a Go err.
func TestGRPCSendCode_UnknownSession(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)
	id := uuid.New()
	b, _ := id.MarshalBinary()
	resp, err := client.SendVerificationCode(context.Background(), &regpb.SendVerificationCodeRequest{SessionId: b})
	if err != nil {
		t.Fatalf("SendVerificationCode: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND {
		t.Errorf("expected SESSION_NOT_FOUND, got %v", resp)
	}
}

// Sanity check: errors.As round-trip still picks up *verification errors
// when callers use the core directly (the grpc layer translates them to
// proto envelopes; the grpcclient adapter reverses the translation —
// covered separately in its own tests).
func TestCoreSurface_TypedErrors(t *testing.T) {
	svc := core.NewService(verification.NewMemoryVerificationSessionStore(), &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	_, err := svc.SendCode(context.Background(), "no-such-session")
	var nf *verification.SessionNotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *SessionNotFoundError, got %v", err)
	}
}

func TestNewServer_PanicsWithNilSvc(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with nil service")
		}
	}()
	NewServer(nil)
}

func TestGRPCCreateSession_LimitExceeded(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{MaxSessions: 1})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	// Fill the single-session quota.
	_, err := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551112222})
	if err != nil {
		t.Fatalf("first CreateSession: %v", err)
	}
	resp, err := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551112223})
	if err != nil {
		t.Fatalf("second CreateSession: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_RATE_LIMITED {
		t.Errorf("expected RATE_LIMITED when MaxSessions exceeded, got %v", resp)
	}
}

func TestGRPCGetSessionMetadata_InternalError(t *testing.T) {
	// Use the string-bytes form to hit the 36-byte garbage path in decodeSessionID.
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)
	// 36-byte garbage that is NOT a valid UUID string → decodeSessionID returns false.
	badID := []byte("zz000000-0000-0000-0000-000000000000")
	resp, err := client.GetSessionMetadata(context.Background(), &regpb.GetRegistrationSessionMetadataRequest{SessionId: badID})
	if err != nil {
		t.Fatalf("GetSessionMetadata: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.GetRegistrationSessionMetadataErrorType_GET_REGISTRATION_SESSION_METADATA_ERROR_TYPE_NOT_FOUND {
		t.Errorf("expected NOT_FOUND for invalid session ID, got %v", resp)
	}
}

func TestGRPCCheckVerificationCode_InvalidSessionID(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	// nil bytes → decodeSessionID returns false → proto error envelope
	resp, err := client.CheckVerificationCode(context.Background(),
		&regpb.CheckVerificationCodeRequest{SessionId: nil, VerificationCode: "123456"})
	if err != nil {
		t.Fatalf("CheckVerificationCode: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND {
		t.Errorf("expected SESSION_NOT_FOUND for nil session ID, got %v", resp)
	}
}

func TestGRPCCheckVerificationCode_CodeExpired(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	// Create session but DO NOT send code → Code is empty → CodeExpiredError.
	cr, _ := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551})
	sid := cr.GetSessionMetadata().GetSessionId()
	resp, err := client.CheckVerificationCode(context.Background(),
		&regpb.CheckVerificationCodeRequest{SessionId: sid, VerificationCode: "000000"})
	if err != nil {
		t.Fatalf("CheckVerificationCode: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_ATTEMPT_EXPIRED {
		t.Errorf("expected ATTEMPT_EXPIRED when code not sent, got %v", resp.GetError())
	}
}

func TestGRPCCheckVerificationCode_InvalidCode(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{FixedCode: "111111"})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	cr, _ := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551})
	sid := cr.GetSessionMetadata().GetSessionId()
	_, _ = client.SendVerificationCode(context.Background(), &regpb.SendVerificationCodeRequest{SessionId: sid})

	resp, err := client.CheckVerificationCode(context.Background(),
		&regpb.CheckVerificationCodeRequest{SessionId: sid, VerificationCode: "999999"})
	if err != nil {
		t.Fatalf("CheckVerificationCode: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED {
		t.Errorf("expected RATE_LIMITED for wrong code, got %v", resp.GetError())
	}
	if !resp.GetError().GetMayRetry() {
		t.Error("may_retry should be true for a bad-guess rate limit")
	}
}

func TestGRPCCheckVerificationCode_MaxAttemptsExceeded(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{FixedCode: "222222", MaxAttempts: 1})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	cr, _ := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551})
	sid := cr.GetSessionMetadata().GetSessionId()
	_, _ = client.SendVerificationCode(context.Background(), &regpb.SendVerificationCodeRequest{SessionId: sid})

	// First wrong code burns the only attempt.
	_, _ = client.CheckVerificationCode(context.Background(),
		&regpb.CheckVerificationCodeRequest{SessionId: sid, VerificationCode: "000000"})

	// Second attempt → MaxAttemptsExceeded.
	resp, err := client.CheckVerificationCode(context.Background(),
		&regpb.CheckVerificationCodeRequest{SessionId: sid, VerificationCode: "000000"})
	if err != nil {
		t.Fatalf("CheckVerificationCode: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED {
		t.Errorf("expected RATE_LIMITED for max attempts, got %v", resp.GetError())
	}
}

// failingTransport always errors on SendCode.
type failingTransport struct{ reason string }

func (f *failingTransport) SendCode(_ context.Context, _, _ string, _ ...verification.SendOption) error {
	return errors.New(f.reason)
}
func (f *failingTransport) Name() string { return "failing" }

func TestGRPCSendCode_TransportError(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &failingTransport{reason: "provider down"}, core.Config{FixedCode: "000000"})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)

	cr, _ := client.CreateSession(context.Background(), &regpb.CreateRegistrationSessionRequest{E164: 15551})
	sid := cr.GetSessionMetadata().GetSessionId()

	resp, err := client.SendVerificationCode(context.Background(), &regpb.SendVerificationCodeRequest{SessionId: sid})
	if err != nil {
		t.Fatalf("SendVerificationCode: %v", err)
	}
	if resp.GetError() == nil ||
		resp.GetError().GetErrorType() != regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SENDER_REJECTED {
		t.Errorf("expected SENDER_REJECTED for transport failure, got %v", resp.GetError())
	}
}

func TestWaitSeconds_ZeroPastTime(t *testing.T) {
	now := time.Now()
	// Time in the past → 0.
	if got := waitSeconds(now, now.Add(-time.Second)); got != 0 {
		t.Errorf("past time: got %d, want 0", got)
	}
	// Zero time → 0.
	if got := waitSeconds(now, time.Time{}); got != 0 {
		t.Errorf("zero time: got %d, want 0", got)
	}
	// Future time → > 0.
	if got := waitSeconds(now, now.Add(500*time.Millisecond)); got == 0 {
		t.Error("future time with < 1s should round up to at least 1")
	}
}

// TestCheckVerificationCodeErrorResponse_DirectCoverage exercises the
// internal error-mapping function via direct calls so all branches get
// counted even when the service doesn't produce those errors through
// the normal integration surface.
func TestCheckVerificationCodeErrorResponse_DirectCoverage(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	ctx := context.Background()
	const sid = "00000000-0000-0000-0000-000000000001"

	cases := []struct {
		name string
		err  error
		want regpb.CheckVerificationCodeErrorType
	}{
		{
			"session_not_found",
			&verification.SessionNotFoundError{SessionID: sid},
			regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
		},
		{
			"session_expired",
			&verification.SessionExpiredError{SessionID: sid},
			regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
		},
		{
			"code_expired",
			&verification.CodeExpiredError{SessionID: sid},
			regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_ATTEMPT_EXPIRED,
		},
		{
			"max_attempts",
			&verification.MaxAttemptsExceededError{SessionID: sid},
			regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED,
		},
		{
			"invalid_code",
			&verification.InvalidCodeError{SessionID: sid},
			regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED,
		},
		{
			"default",
			errors.New("some internal error"),
			regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_UNSPECIFIED,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := checkVerificationCodeErrorResponse(ctx, svc, sid, tc.err)
			if resp.GetError() == nil {
				t.Fatal("expected error in response")
			}
			if resp.GetError().GetErrorType() != tc.want {
				t.Errorf("got %v, want %v", resp.GetError().GetErrorType(), tc.want)
			}
		})
	}
}

func TestSendVerificationCodeErrorResponse_DirectCoverage(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{})
	t.Cleanup(svc.Shutdown)
	ctx := context.Background()
	const sid = "00000000-0000-0000-0000-000000000002"

	cases := []struct {
		name string
		err  error
		want regpb.SendVerificationCodeErrorType
	}{
		{
			"session_not_found",
			&verification.SessionNotFoundError{SessionID: sid},
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
		},
		{
			"session_expired",
			&verification.SessionExpiredError{SessionID: sid},
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
		},
		{
			"rate_limited",
			&verification.RequestCodeRateLimitedError{SessionID: sid, RetryAfter: time.Hour},
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED,
		},
		{
			"session_already_verified",
			&verification.SessionAlreadyVerifiedError{SessionID: sid},
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_ALREADY_VERIFIED,
		},
		{
			"transport_error",
			&verification.TransportError{Transport: "sms", Destination: sid, Cause: errors.New("fail")},
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SENDER_REJECTED,
		},
		{
			"default",
			errors.New("some internal error"),
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_UNSPECIFIED,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendVerificationCodeErrorResponse(ctx, svc, sid, tc.err)
			if resp.GetError() == nil {
				t.Fatal("expected error in response")
			}
			if resp.GetError().GetErrorType() != tc.want {
				t.Errorf("got %v, want %v", resp.GetError().GetErrorType(), tc.want)
			}
		})
	}
}

// TestGRPCSendVerificationCode_AlreadyVerified drives the whole gRPC path: a
// verified session must reach the client as SESSION_ALREADY_VERIFIED, not as
// UNSPECIFIED. A split deployment routes REST through this boundary, so an
// unmapped error here becomes a 500 where the in-process path returns 409.
//
// The cooldown is left armed deliberately: without the verified check
// ordering, this session would be reported as RATE_LIMITED instead.
func TestGRPCSendVerificationCode_AlreadyVerified(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{
		FixedCode:            "123456",
		RequestCodeCooldowns: []time.Duration{0, time.Hour},
	})
	t.Cleanup(svc.Shutdown)
	client := newGRPCStub(t, svc)
	ctx := context.Background()

	created, err := client.CreateSession(ctx, &regpb.CreateRegistrationSessionRequest{E164: 15552})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sid := created.GetSessionMetadata().GetSessionId()

	if _, err := client.SendVerificationCode(ctx, &regpb.SendVerificationCodeRequest{SessionId: sid}); err != nil {
		t.Fatalf("SendVerificationCode: %v", err)
	}
	checked, err := client.CheckVerificationCode(ctx, &regpb.CheckVerificationCodeRequest{
		SessionId:        sid,
		VerificationCode: "123456",
	})
	if err != nil {
		t.Fatalf("CheckVerificationCode: %v", err)
	}
	if !checked.GetSessionMetadata().GetVerified() {
		t.Fatalf("session should be verified: %v", checked)
	}

	resp, err := client.SendVerificationCode(ctx, &regpb.SendVerificationCodeRequest{SessionId: sid})
	if err != nil {
		t.Fatalf("SendVerificationCode after verify: %v", err)
	}
	got := resp.GetError().GetErrorType()
	if got != regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_ALREADY_VERIFIED {
		t.Errorf("error type = %v, want SESSION_ALREADY_VERIFIED", got)
	}
}
