package workers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

// removeExpiredFakeMessageService implements just enough of MessageService to
// drive RemoveExpiredMessagesWorker tests. Only RemoveExpired actually does
// work; the rest panic so a misrouted test fails loudly.
type removeExpiredFakeMessageService struct {
	service.MessageService // embed for unused methods
	removed                int64
	called                 bool
	err                    error
	gotBefore              time.Time
}

func (s *removeExpiredFakeMessageService) RemoveExpired(_ context.Context, before time.Time) (int64, error) {
	s.called = true
	s.gotBefore = before
	return s.removed, s.err
}

func TestRemoveExpiredMessagesWorker_Name(t *testing.T) {
	w := NewRemoveExpiredMessagesWorker(nil, 0)
	if w.Name() != "remove-expired-messages" {
		t.Errorf("Name() = %q; want remove-expired-messages", w.Name())
	}
}

func TestRemoveExpiredMessagesWorker_Schedule(t *testing.T) {
	w := NewRemoveExpiredMessagesWorker(nil, 0)
	if w.Schedule() != "@every 5m" {
		t.Errorf("Schedule() = %q", w.Schedule())
	}
}

func TestRemoveExpiredMessagesWorker_NilServiceNoOps(t *testing.T) {
	w := NewRemoveExpiredMessagesWorker(nil, time.Minute)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("expected nil error for nil service, got %v", err)
	}
}

func TestRemoveExpiredMessagesWorker_NilMessagesNoOps(t *testing.T) {
	w := NewRemoveExpiredMessagesWorker(&service.SignalService{}, time.Minute)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("expected nil error when Messages is nil, got %v", err)
	}
}

func TestRemoveExpiredMessagesWorker_InvokesServiceWithGraceCutoff(t *testing.T) {
	fake := &removeExpiredFakeMessageService{removed: 7}
	svc := &service.SignalService{Messages: fake}
	before := time.Now().UTC()
	w := NewRemoveExpiredMessagesWorker(svc, 30*time.Minute)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !fake.called {
		t.Fatal("expected RemoveExpired to be called")
	}
	after := time.Now().UTC()
	// The cutoff must be in [before-grace, after-grace] — bracketed by the
	// timestamps captured before/after Run.
	graceWindowStart := before.Add(-30 * time.Minute)
	graceWindowEnd := after.Add(-30 * time.Minute)
	if fake.gotBefore.Before(graceWindowStart) || fake.gotBefore.After(graceWindowEnd) {
		t.Errorf("cutoff = %v; expected within [%v, %v]", fake.gotBefore, graceWindowStart, graceWindowEnd)
	}
}

func TestRemoveExpiredMessagesWorker_PropagatesServiceError(t *testing.T) {
	sentinel := errors.New("sweep blew up")
	fake := &removeExpiredFakeMessageService{err: sentinel}
	svc := &service.SignalService{Messages: fake}
	w := NewRemoveExpiredMessagesWorker(svc, 0)
	if err := w.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel, got %v", err)
	}
}

// TestRemoveExpiredMessagesWorker_DefaultGraceIsZero documents that the
// default sweep matches Java Signal-Server: no grace, prune anything past
// its own expires_at the moment we observe it.
func TestRemoveExpiredMessagesWorker_DefaultGraceIsZero(t *testing.T) {
	w := NewRemoveExpiredMessagesWorker(nil, 0)
	if w.ExpiryGrace != DefaultMessageExpiryGrace {
		t.Errorf("ExpiryGrace = %v; want %v", w.ExpiryGrace, DefaultMessageExpiryGrace)
	}
	if DefaultMessageExpiryGrace != 0 {
		t.Errorf("DefaultMessageExpiryGrace = %v; want 0", DefaultMessageExpiryGrace)
	}
}

// Compile-time guard that the interface still binds — silences "imported and
// not used" for the messages package if the test set ever shrinks.
var _ = messages.EnvelopeTypeReceipt
