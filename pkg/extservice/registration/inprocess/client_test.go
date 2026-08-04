package inprocess

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/extservice/registration"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

type stubTransport struct{}

func (stubTransport) SendCode(_ context.Context, _, _ string, _ ...verification.SendOption) error {
	return nil
}
func (stubTransport) Name() string { return "stub" }

func newClient(t *testing.T) (*Client, *core.Service) {
	t.Helper()
	store := verification.NewMemoryVerificationSessionStore()
	svc := core.NewService(store, stubTransport{}, core.Config{FixedCode: "123456"})
	t.Cleanup(svc.Shutdown)
	return New(svc), svc
}

func TestInprocessClient_ConformsToInterface(t *testing.T) {
	c, _ := newClient(t)
	var _ registration.Client = c
}

func TestInprocessClient_HappyPath(t *testing.T) {
	c, _ := newClient(t)
	ctx := context.Background()

	sess, err := c.CreateSession(ctx, "+15551")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := c.SendCode(ctx, sess.ID); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	verified, err := c.SubmitCode(ctx, sess.ID, "123456")
	if err != nil {
		t.Fatalf("SubmitCode: %v", err)
	}
	if !verified.Verified {
		t.Error("Verified should be true")
	}
	got, err := c.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("ID round-trip mismatch")
	}
}

func TestInprocessClient_GetSession_NotFound(t *testing.T) {
	c, _ := newClient(t)
	_, err := c.GetSession(context.Background(), "missing")
	var nf *verification.SessionNotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *SessionNotFoundError, got %v", err)
	}
}

func TestInprocessClient_CloseIsNoOp(t *testing.T) {
	c, _ := newClient(t)
	if err := c.Close(); err != nil {
		t.Errorf("Close should be a no-op; got %v", err)
	}
}
