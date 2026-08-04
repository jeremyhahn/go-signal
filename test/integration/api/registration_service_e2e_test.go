//go:build integration

package api

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
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/grpcclient"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/registration/sessionshim"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// recordingTransport captures the codes dispatched by the
// registration-service so the chat-server-side shim test can submit
// them as a real user would after receiving an SMS.
type recordingTransport struct {
	mu   chan recordingTransportEvent
	last string
}
type recordingTransportEvent struct {
	destination string
	code        string
}

func newRecordingTransport() *recordingTransport {
	return &recordingTransport{mu: make(chan recordingTransportEvent, 16)}
}

func (r *recordingTransport) SendCode(_ context.Context, destination, code string, _ ...verification.SendOption) error {
	r.last = code
	r.mu <- recordingTransportEvent{destination: destination, code: code}
	return nil
}
func (r *recordingTransport) Name() string { return "recording" }

// startRegistrationServiceForTest spins up an in-memory
// registration-service binary (gRPC over bufconn) and returns a
// gRPC-backed registration.Client pointed at it. The Service runs the
// real core implementation; only the transport is a test recorder.
//
// This is the cleanest end-to-end exercise of the Phase 4.1 wire:
//
//	signald (shim → grpcclient.Client) → registration-service (core.Service)
//
// over an actual gRPC channel.
func startRegistrationServiceForTest(t *testing.T) (
	*grpcclient.Client,
	*core.Service,
	*recordingTransport,
) {
	t.Helper()
	store := verification.NewMemoryVerificationSessionStore()
	transport := newRecordingTransport()
	svc := core.NewService(store, transport, core.Config{
		CodeLength:           6,
		MaxAttempts:          3,
		RequestCodeCooldowns: []time.Duration{0, time.Hour},
	})
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
		t.Fatalf("dial bufconn: %v", err)
	}
	c, err := grpcclient.New(grpcclient.Config{Conn: conn})
	if err != nil {
		t.Fatalf("grpcclient.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, svc, transport
}

// TestRegistrationServiceE2E_HappyPath exercises the production wire:
// signald-side shim → gRPC → registration-service core. Verification
// state must round-trip: Create returns metadata, SendCode dispatches a
// code via the recording transport, SubmitCode flips verified=true.
func TestRegistrationServiceE2E_HappyPath(t *testing.T) {
	client, _, transport := startRegistrationServiceForTest(t)
	shim := sessionshim.NewShim(sessionshim.Config{
		Client:                 client,
		CaptchaStore:           sessionshim.NewMemoryCaptchaStore(),
		CaptchaChecker:         nil,
		CaptchaEscalationAfter: -1,
	})
	ctx := context.Background()

	sess, err := shim.CreateSession(ctx, "+15558675309")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Error("session ID is empty after CreateSession")
	}
	if sess.Number != "+15558675309" {
		t.Errorf("Number = %q", sess.Number)
	}

	sent, err := shim.SendCode(ctx, sess.ID)
	if err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if sent.ID != sess.ID {
		t.Error("ID mismatch after SendCode")
	}

	// Recover the code the recording transport observed and submit it.
	var observed recordingTransportEvent
	select {
	case observed = <-transport.mu:
	case <-time.After(2 * time.Second):
		t.Fatal("transport did not receive a code dispatch")
	}
	if observed.destination != "+15558675309" {
		t.Errorf("transport destination = %q", observed.destination)
	}
	verified, err := shim.SubmitCode(ctx, sess.ID, observed.code)
	if err != nil {
		t.Fatalf("SubmitCode: %v", err)
	}
	if !verified.Verified {
		t.Error("Verified should be true after a correct code submission")
	}
}

// TestRegistrationServiceE2E_RateLimitedRoundTrip confirms the proto
// error envelope decodes back to *verification.RequestCodeRateLimitedError
// after the second SendCode within the cooldown window.
func TestRegistrationServiceE2E_RateLimitedRoundTrip(t *testing.T) {
	client, _, _ := startRegistrationServiceForTest(t)
	shim := sessionshim.NewShim(sessionshim.Config{
		Client:                 client,
		CaptchaStore:           sessionshim.NewMemoryCaptchaStore(),
		CaptchaEscalationAfter: -1,
	})
	ctx := context.Background()

	sess, err := shim.CreateSession(ctx, "+15551112222")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := shim.SendCode(ctx, sess.ID); err != nil {
		t.Fatalf("first SendCode: %v", err)
	}
	_, err = shim.SendCode(ctx, sess.ID)
	var rateLimited *verification.RequestCodeRateLimitedError
	if !errors.As(err, &rateLimited) {
		t.Errorf("expected *RequestCodeRateLimitedError, got %v", err)
	}
	if rateLimited.RetryAfter < time.Minute {
		t.Errorf("RetryAfter = %v, expected >= 1 minute", rateLimited.RetryAfter)
	}
}

// TestRegistrationServiceE2E_CaptchaEscalation locks the chat-server
// side gate after a single send when the shim is configured with
// CaptchaEscalationAfter=1. The registration-service is unaware of the
// captcha state — confirming the split mirrors the Java reference.
func TestRegistrationServiceE2E_CaptchaEscalation(t *testing.T) {
	client, _, _ := startRegistrationServiceForTest(t)
	shim := sessionshim.NewShim(sessionshim.Config{
		Client:                 client,
		CaptchaStore:           sessionshim.NewMemoryCaptchaStore(),
		CaptchaChecker:         &captcha.Checker{},
		CaptchaEscalationAfter: 1,
	})
	ctx := context.Background()

	sess, _ := shim.CreateSession(ctx, "+15551")
	first, err := shim.SendCode(ctx, sess.ID)
	if err != nil {
		t.Fatalf("first SendCode: %v", err)
	}
	if !first.CaptchaRequired {
		t.Error("CaptchaRequired should be true after the threshold send")
	}
	_, err = shim.SendCode(ctx, sess.ID)
	var captchaRequired *verification.CaptchaRequiredError
	if !errors.As(err, &captchaRequired) {
		t.Errorf("expected *CaptchaRequiredError on second SendCode, got %v", err)
	}
}
