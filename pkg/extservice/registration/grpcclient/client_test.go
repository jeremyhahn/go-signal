package grpcclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	regpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/registrationservice"
	regsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/registration"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

type stubTransport struct{ last string }

func (s *stubTransport) SendCode(_ context.Context, _, code string, _ ...verification.SendOption) error {
	s.last = code
	return nil
}
func (s *stubTransport) Name() string { return "stub" }

func newTestClient(t *testing.T) (*Client, *core.Service) {
	t.Helper()
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{FixedCode: "424242"})
	t.Cleanup(svc.Shutdown)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	regpb.RegisterRegistrationServiceServer(gs, regsvc.NewServer(svc))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c, err := New(Config{Conn: conn})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, svc
}

func TestClient_HappyPath_CreateSendCheck(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()

	sess, err := c.CreateSession(ctx, "+15551112222")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Error("session ID is empty")
	}
	if sess.Number != "+15551112222" {
		t.Errorf("Number = %q", sess.Number)
	}

	sent, err := c.SendCode(ctx, sess.ID)
	if err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if sent.ID != sess.ID {
		t.Errorf("ID mismatch after SendCode")
	}

	verified, err := c.SubmitCode(ctx, sess.ID, "424242")
	if err != nil {
		t.Fatalf("SubmitCode: %v", err)
	}
	if !verified.Verified {
		t.Error("Verified should be true after matching code")
	}
}

func TestClient_GetSession_NotFound(t *testing.T) {
	c, _ := newTestClient(t)
	_, err := c.GetSession(context.Background(), "00000000-0000-0000-0000-000000000000")
	var nf *verification.SessionNotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *SessionNotFoundError, got %v", err)
	}
}

func TestClient_GetSession_InvalidUUID(t *testing.T) {
	c, _ := newTestClient(t)
	_, err := c.GetSession(context.Background(), "not-a-uuid")
	var nf *verification.SessionNotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *SessionNotFoundError, got %v", err)
	}
}

func TestClient_SendCode_RateLimitedDecodesTypedError(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, &stubTransport{}, core.Config{
		RequestCodeCooldowns: []time.Duration{0, time.Hour},
	})
	t.Cleanup(svc.Shutdown)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	regpb.RegisterRegistrationServiceServer(gs, regsvc.NewServer(svc))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, _ := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	c, _ := New(Config{Conn: conn})
	t.Cleanup(func() { _ = c.Close() })

	sess, err := c.CreateSession(context.Background(), "+15551")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := c.SendCode(context.Background(), sess.ID); err != nil {
		t.Fatalf("first SendCode: %v", err)
	}
	_, err = c.SendCode(context.Background(), sess.ID)
	var rateLimited *verification.RequestCodeRateLimitedError
	if !errors.As(err, &rateLimited) {
		t.Errorf("expected *RequestCodeRateLimitedError, got %v", err)
	}
	if rateLimited.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, expected > 0", rateLimited.RetryAfter)
	}
}

func TestClient_SubmitCode_InvalidCodeDecodes(t *testing.T) {
	c, _ := newTestClient(t)
	sess, err := c.CreateSession(context.Background(), "+15551")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := c.SendCode(context.Background(), sess.ID); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	_, err = c.SubmitCode(context.Background(), sess.ID, "wrong-code")
	var bad *verification.InvalidCodeError
	if !errors.As(err, &bad) {
		t.Errorf("expected *InvalidCodeError, got %v", err)
	}
}

func TestNew_RejectsBothOrNeither(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected error when neither Conn nor Endpoint is set")
	}
	if _, err := New(Config{Endpoint: "x", Conn: &grpc.ClientConn{}}); err == nil {
		t.Error("expected error when both Conn and Endpoint are set")
	}
}

func TestParseE164Helpers(t *testing.T) {
	if encodeE164(0) != "" {
		t.Error("encodeE164(0) should be empty")
	}
	if encodeE164(15551) != "+15551" {
		t.Error("encodeE164(15551) mismatch")
	}
	if parseE164("nope") != 0 {
		t.Error("parseE164 garbage = 0")
	}
}

func TestNew_WithEndpoint(t *testing.T) {
	// grpc.NewClient is lazy — an unreachable endpoint still succeeds at
	// construction time. Insecure credentials are required by gRPC when
	// no TLS is configured.
	c, err := New(Config{
		Endpoint:    "localhost:19999",
		DialOptions: []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())},
	})
	if err != nil {
		t.Fatalf("New with Endpoint: %v", err)
	}
	if c.owned != true {
		t.Error("Endpoint-dialed client must own the connection")
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNew_BothConnAndEndpoint_Errors(t *testing.T) {
	conn, err := grpc.NewClient("localhost:19999", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, err = New(Config{Conn: conn, Endpoint: "localhost:19999"})
	if err == nil {
		t.Error("expected error when both Conn and Endpoint are set")
	}
}

func TestWithTimeout_SetsDeadline(t *testing.T) {
	c := &Client{timeout: 5 * time.Second}
	ctx, cancel := c.withTimeout(context.Background())
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok || dl.IsZero() {
		t.Error("expected a deadline when timeout > 0")
	}
}

func TestWithTimeout_NoTimeout_NoDeadline(t *testing.T) {
	c := &Client{timeout: 0}
	ctx, cancel := c.withTimeout(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Error("expected no deadline when timeout == 0")
	}
}

func TestDecodeSessionMetadata_Nil_ReturnsError(t *testing.T) {
	_, err := decodeSessionMetadata(nil, "")
	if err == nil {
		t.Error("expected error for nil metadata")
	}
}

func TestDecodeCreateError_AllCases(t *testing.T) {
	cases := []struct {
		errType regpb.CreateRegistrationSessionErrorType
		wantPtr bool // true == *verification.SessionLimitExceededError
	}{
		{regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_RATE_LIMITED, true},
		{regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_ILLEGAL_PHONE_NUMBER, false},
		{regpb.CreateRegistrationSessionErrorType_CREATE_REGISTRATION_SESSION_ERROR_TYPE_UNSPECIFIED, false},
	}
	for _, tc := range cases {
		err := decodeCreateError(&regpb.CreateRegistrationSessionError{ErrorType: tc.errType}, "+15551")
		if err == nil {
			t.Errorf("%v: expected an error", tc.errType)
			continue
		}
		var limit *verification.SessionLimitExceededError
		if got := errors.As(err, &limit); got != tc.wantPtr {
			t.Errorf("%v: SessionLimitExceededError? got=%v want=%v, err=%v", tc.errType, got, tc.wantPtr, err)
		}
	}
}

func TestDecodeGetError_DefaultCase(t *testing.T) {
	err := decodeGetError(&regpb.GetRegistrationSessionMetadataError{
		ErrorType: regpb.GetRegistrationSessionMetadataErrorType_GET_REGISTRATION_SESSION_METADATA_ERROR_TYPE_UNSPECIFIED,
	}, "sess-1")
	if err == nil {
		t.Error("expected error for default GET error type")
	}
	var nf *verification.SessionNotFoundError
	if errors.As(err, &nf) {
		t.Error("UNSPECIFIED should not decode as SessionNotFoundError")
	}
}

func TestDecodeSendError_AllCases(t *testing.T) {
	cases := []struct {
		errType regpb.SendVerificationCodeErrorType
		wantFn  func(error) bool
	}{
		{
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
			func(err error) bool {
				var nf *verification.SessionNotFoundError
				return errors.As(err, &nf)
			},
		},
		{
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED,
			func(err error) bool {
				var rl *verification.RequestCodeRateLimitedError
				return errors.As(err, &rl)
			},
		},
		{
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SENDER_REJECTED,
			func(err error) bool {
				var te *verification.TransportError
				return errors.As(err, &te)
			},
		},
		{
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SESSION_ALREADY_VERIFIED,
			func(err error) bool {
				// Typed, so the REST layer can map it to 409. `err != nil`
				// would pass on the untyped value that produced a 500.
				var av *verification.SessionAlreadyVerifiedError
				return errors.As(err, &av)
			},
		},
		{
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_TRANSPORT_NOT_ALLOWED,
			func(err error) bool { return err != nil },
		},
		{
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_SUSPECTED_FRAUD,
			func(err error) bool { return err != nil },
		},
		{
			regpb.SendVerificationCodeErrorType_SEND_VERIFICATION_CODE_ERROR_TYPE_UNSPECIFIED,
			func(err error) bool { return err != nil },
		},
	}
	for _, tc := range cases {
		e := &regpb.SendVerificationCodeError{
			ErrorType:         tc.errType,
			RetryAfterSeconds: 60,
		}
		err := decodeSendError(e, "sess-1")
		if !tc.wantFn(err) {
			t.Errorf("errType=%v: unexpected result: %v", tc.errType, err)
		}
	}
}

func TestDecodeCheckError_AllCases(t *testing.T) {
	cases := []struct {
		name    string
		errType regpb.CheckVerificationCodeErrorType
		md      *regpb.RegistrationSessionMetadata
		wantFn  func(error) bool
	}{
		{
			name:    "session_not_found",
			errType: regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_SESSION_NOT_FOUND,
			md:      nil,
			wantFn: func(err error) bool {
				var nf *verification.SessionNotFoundError
				return errors.As(err, &nf)
			},
		},
		{
			name:    "no_code_sent",
			errType: regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_NO_CODE_SENT,
			md:      nil,
			wantFn: func(err error) bool {
				var ce *verification.CodeExpiredError
				return errors.As(err, &ce)
			},
		},
		{
			name:    "attempt_expired",
			errType: regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_ATTEMPT_EXPIRED,
			md:      nil,
			wantFn: func(err error) bool {
				var ce *verification.CodeExpiredError
				return errors.As(err, &ce)
			},
		},
		{
			name:    "rate_limited_max_attempts",
			errType: regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED,
			md:      &regpb.RegistrationSessionMetadata{MayCheckCode: false},
			wantFn: func(err error) bool {
				var ma *verification.MaxAttemptsExceededError
				return errors.As(err, &ma)
			},
		},
		{
			name:    "rate_limited_invalid_code",
			errType: regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_RATE_LIMITED,
			md:      &regpb.RegistrationSessionMetadata{MayCheckCode: true},
			wantFn: func(err error) bool {
				var ic *verification.InvalidCodeError
				return errors.As(err, &ic)
			},
		},
		{
			name:    "default",
			errType: regpb.CheckVerificationCodeErrorType_CHECK_VERIFICATION_CODE_ERROR_TYPE_UNSPECIFIED,
			md:      nil,
			wantFn:  func(err error) bool { return err != nil },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &regpb.CheckVerificationCodeError{ErrorType: tc.errType}
			err := decodeCheckError(e, "sess-1", tc.md)
			if !tc.wantFn(err) {
				t.Errorf("unexpected result: %v", err)
			}
		})
	}
}

// failingTransport is a transport that always returns an error.
type failingTransport struct{ err error }

func (f *failingTransport) SendCode(_ context.Context, _, _ string, _ ...verification.SendOption) error {
	return f.err
}
func (f *failingTransport) Name() string { return "failing" }

func TestClient_SendCode_TransportError(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	tr := &failingTransport{err: errors.New("provider down")}
	svc := core.NewService(store, tr, core.Config{FixedCode: "000000"})
	t.Cleanup(svc.Shutdown)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	regpb.RegisterRegistrationServiceServer(gs, regsvc.NewServer(svc))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, _ := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	c, _ := New(Config{Conn: conn})
	t.Cleanup(func() { _ = c.Close() })

	sess, err := c.CreateSession(context.Background(), "+15559991111")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, err = c.SendCode(context.Background(), sess.ID)
	var te *verification.TransportError
	if !errors.As(err, &te) {
		t.Errorf("expected *TransportError after transport failure, got %v", err)
	}
}

func TestClient_SubmitCode_BeforeSendCodeExpired(t *testing.T) {
	c, _ := newTestClient(t)
	sess, err := c.CreateSession(context.Background(), "+15550000001")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// Submit without calling SendCode first → code is empty → CodeExpiredError.
	_, err = c.SubmitCode(context.Background(), sess.ID, "424242")
	var ce *verification.CodeExpiredError
	if !errors.As(err, &ce) {
		t.Errorf("expected *CodeExpiredError, got %v", err)
	}
}

func TestAddSeconds_ZeroReturnsZeroTime(t *testing.T) {
	if !addSeconds(time.Now(), 0).IsZero() {
		t.Error("addSeconds with 0 secs should return zero time")
	}
	if addSeconds(time.Now(), 5).IsZero() {
		t.Error("addSeconds with 5 secs should not return zero time")
	}
}

func TestParseE164_NoPlusPrefix_ReturnsZero(t *testing.T) {
	if got := parseE164("15551234567"); got != 0 {
		t.Errorf("parseE164 without +: got %d, want 0", got)
	}
}

func TestParseE164_BadDigitsAfterPlus_ReturnsZero(t *testing.T) {
	if got := parseE164("+notanumber"); got != 0 {
		t.Errorf("parseE164 with bad digits: got %d, want 0", got)
	}
}

func TestDecodeSessionMetadata_InvalidUUIDBytesReturnsError(t *testing.T) {
	md := &regpb.RegistrationSessionMetadata{
		SessionId: []byte("too-short"), // not 16 bytes → uuid.FromBytes fails
	}
	_, err := decodeSessionMetadata(md, "+15550001234")
	if err == nil {
		t.Error("expected error for invalid UUID session ID bytes")
	}
}

func TestDecodeSessionMetadata_ZeroE164_UsesNumber(t *testing.T) {
	id := [16]byte{1}
	md := &regpb.RegistrationSessionMetadata{
		SessionId: id[:],
		E164:      0, // encodeE164(0) == "" → fallback to number param
	}
	sess, err := decodeSessionMetadata(md, "+15550001234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.Number != "+15550001234" {
		t.Errorf("Number = %q, want +15550001234", sess.Number)
	}
}

func TestClient_CreateSession_CancelledContext_ReturnsError(t *testing.T) {
	c, _ := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.CreateSession(ctx, "+15550001234")
	if err == nil {
		t.Error("expected error with cancelled context in CreateSession")
	}
}

func TestClient_GetSession_CancelledContext_ReturnsError(t *testing.T) {
	c, _ := newTestClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.GetSession(ctx, "00000000-0000-0000-0000-000000000001")
	if err == nil {
		t.Error("expected error with cancelled context in GetSession")
	}
}

func TestClient_SendCode_CancelledContext_ReturnsError(t *testing.T) {
	c, svc := newTestClient(t)
	sess, err := c.CreateSession(context.Background(), "+15551234500")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = svc
	_, err = c.SendCode(ctx, sess.ID)
	if err == nil {
		t.Error("expected error with cancelled context in SendCode")
	}
}

func TestClient_SubmitCode_CancelledContext_ReturnsError(t *testing.T) {
	c, _ := newTestClient(t)
	sess, err := c.CreateSession(context.Background(), "+15551234501")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.SubmitCode(ctx, sess.ID, "424242")
	if err == nil {
		t.Error("expected error with cancelled context in SubmitCode")
	}
}
