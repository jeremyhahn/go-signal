package memory

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/jobs"
)

func TestNewMemoryJobsStore(t *testing.T) {
	s := NewMemoryJobsStore()
	if s == nil {
		t.Fatal("expected non-nil store")
	}
	if s.rows == nil {
		t.Fatal("expected rows map to be initialised")
	}
	if s.claimedAt == nil {
		t.Fatal("expected claimedAt map to be initialised")
	}
}

func TestNewMemoryJobsStore_InterfaceSatisfaction(t *testing.T) {
	var _ jobs.Store = (*MemoryJobsStore)(nil)
}

// ─── Enqueue ─────────────────────────────────────────────────────────────────

func TestMemoryJobsStore_Enqueue_AssignsIDAndStatus(t *testing.T) {
	s := NewMemoryJobsStore()
	j := &jobs.Job{Type: "email", FireAt: time.Now().UTC()}

	if err := s.Enqueue(context.Background(), j); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if j.ID == "" {
		t.Error("Enqueue: expected non-empty ID to be assigned")
	}
	if j.Status != jobs.StatusPending {
		t.Errorf("Enqueue: expected StatusPending, got %v", j.Status)
	}
	if j.CreatedAt.IsZero() {
		t.Error("Enqueue: expected non-zero CreatedAt")
	}
}

func TestMemoryJobsStore_Enqueue_NilJobReturnsError(t *testing.T) {
	s := NewMemoryJobsStore()
	if err := s.Enqueue(context.Background(), nil); err == nil {
		t.Fatal("Enqueue nil: expected error")
	}
}

func TestMemoryJobsStore_Enqueue_PreservesExplicitID(t *testing.T) {
	s := NewMemoryJobsStore()
	j := &jobs.Job{ID: "explicit-id", Type: "noop", FireAt: time.Now().UTC()}

	if err := s.Enqueue(context.Background(), j); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if j.ID != "explicit-id" {
		t.Errorf("Enqueue: expected explicit-id, got %q", j.ID)
	}
}

// ─── ClaimDue ────────────────────────────────────────────────────────────────

func TestMemoryJobsStore_ClaimDue_ReturnsDueJobs(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	j := &jobs.Job{Type: "task", FireAt: now.Add(-time.Minute)}
	if err := s.Enqueue(ctx, j); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	claimed, err := s.ClaimDue(ctx, now, 10)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("ClaimDue: expected 1, got %d", len(claimed))
	}
	if claimed[0].Status != jobs.StatusRunning {
		t.Errorf("ClaimDue: expected StatusRunning, got %v", claimed[0].Status)
	}
}

func TestMemoryJobsStore_ClaimDue_TypeFilterExcludesOtherTypes(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.Enqueue(ctx, &jobs.Job{Type: "email", FireAt: now.Add(-time.Minute)})
	_ = s.Enqueue(ctx, &jobs.Job{Type: "sms", FireAt: now.Add(-time.Minute)})

	claimed, err := s.ClaimDue(ctx, now, 10, "email")
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("ClaimDue with type filter: expected 1, got %d", len(claimed))
	}
	if claimed[0].Type != "email" {
		t.Errorf("ClaimDue: expected email, got %q", claimed[0].Type)
	}
}

func TestMemoryJobsStore_ClaimDue_FutureJobsNotReturned(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.Enqueue(ctx, &jobs.Job{Type: "future", FireAt: now.Add(time.Hour)})

	claimed, err := s.ClaimDue(ctx, now, 10)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(claimed) != 0 {
		t.Errorf("ClaimDue: expected 0 future jobs, got %d", len(claimed))
	}
}

// ─── MarkDone ────────────────────────────────────────────────────────────────

func TestMemoryJobsStore_MarkDone_RemovesJob(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	j := &jobs.Job{Type: "task", FireAt: now.Add(-time.Second)}
	_ = s.Enqueue(ctx, j)
	claimed, _ := s.ClaimDue(ctx, now, 1)
	if len(claimed) == 0 {
		t.Fatal("expected a claimed job")
	}

	if err := s.MarkDone(ctx, claimed[0].ID); err != nil {
		t.Fatalf("MarkDone: %v", err)
	}

	_, err := s.Get(ctx, claimed[0].ID)
	if err == nil {
		t.Fatal("MarkDone: job still retrievable after Done")
	}
}

func TestMemoryJobsStore_MarkDone_IdempotentOnMissing(t *testing.T) {
	s := NewMemoryJobsStore()
	// MarkDone on a non-existent ID must not error — idempotent.
	if err := s.MarkDone(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("MarkDone idempotent: unexpected error: %v", err)
	}
}

// ─── MarkFailed ──────────────────────────────────────────────────────────────

func TestMemoryJobsStore_MarkFailed_RequeuesWithinBudget(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	j := &jobs.Job{Type: "retry", FireAt: now.Add(-time.Second)}
	_ = s.Enqueue(ctx, j)
	claimed, _ := s.ClaimDue(ctx, now, 1)

	if err := s.MarkFailed(ctx, claimed[0].ID, now, time.Minute, 5); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	got, err := s.Get(ctx, claimed[0].ID)
	if err != nil {
		t.Fatalf("Get after MarkFailed: %v", err)
	}
	if got.Status != jobs.StatusPending {
		t.Errorf("MarkFailed requeue: expected Pending, got %v", got.Status)
	}
}

func TestMemoryJobsStore_MarkFailed_MarksFailedWhenBudgetExhausted(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	j := &jobs.Job{Type: "exhaust", FireAt: now.Add(-time.Second)}
	_ = s.Enqueue(ctx, j)
	claimed, _ := s.ClaimDue(ctx, now, 1)
	jobID := claimed[0].ID

	// Exhaust attempts — maxAttempts=1 and the job already has Attempts=1 after claim.
	if err := s.MarkFailed(ctx, jobID, now, time.Second, 1); err != nil {
		t.Fatalf("MarkFailed exhaust: %v", err)
	}

	got, err := s.Get(ctx, jobID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != jobs.StatusFailed {
		t.Errorf("MarkFailed exhaust: expected Failed, got %v", got.Status)
	}
}

func TestMemoryJobsStore_MarkFailed_MissingJobReturnsError(t *testing.T) {
	s := NewMemoryJobsStore()
	err := s.MarkFailed(context.Background(), "missing", time.Now(), time.Second, 5)
	if err == nil {
		t.Fatal("MarkFailed missing: expected error")
	}
}

// ─── ResetToPending ──────────────────────────────────────────────────────────

func TestMemoryJobsStore_ResetToPending_TransitionsRunningJob(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	j := &jobs.Job{Type: "reset", FireAt: now.Add(-time.Second)}
	_ = s.Enqueue(ctx, j)
	claimed, _ := s.ClaimDue(ctx, now, 1)

	fireAt := now.Add(time.Minute)
	if err := s.ResetToPending(ctx, claimed[0].ID, fireAt); err != nil {
		t.Fatalf("ResetToPending: %v", err)
	}

	got, err := s.Get(ctx, claimed[0].ID)
	if err != nil {
		t.Fatalf("Get after ResetToPending: %v", err)
	}
	if got.Status != jobs.StatusPending {
		t.Errorf("ResetToPending: expected Pending, got %v", got.Status)
	}
}

func TestMemoryJobsStore_ResetToPending_IdempotentOnMissing(t *testing.T) {
	s := NewMemoryJobsStore()
	if err := s.ResetToPending(context.Background(), "ghost", time.Now()); err != nil {
		t.Fatalf("ResetToPending missing: unexpected error: %v", err)
	}
}

// ─── RecoverStale ────────────────────────────────────────────────────────────

func TestMemoryJobsStore_RecoverStale_RequeusStaleClaim(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	then := time.Now().UTC().Add(-time.Hour)

	j := &jobs.Job{Type: "stale", FireAt: then}
	_ = s.Enqueue(ctx, j)
	claimed, _ := s.ClaimDue(ctx, then, 1)
	if len(claimed) == 0 {
		t.Fatal("expected to claim a job")
	}

	// Recover anything claimed more than 30 minutes ago.
	recovered, err := s.RecoverStale(ctx, time.Now().UTC().Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("RecoverStale: %v", err)
	}
	if recovered != 1 {
		t.Errorf("RecoverStale: expected 1, got %d", recovered)
	}
}

func TestMemoryJobsStore_RecoverStale_SkipsFreshClaims(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()
	now := time.Now().UTC()

	j := &jobs.Job{Type: "fresh", FireAt: now.Add(-time.Second)}
	_ = s.Enqueue(ctx, j)
	_, _ = s.ClaimDue(ctx, now, 1)

	// Treat anything older than 1 hour as stale — fresh claim is safe.
	recovered, err := s.RecoverStale(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("RecoverStale: %v", err)
	}
	if recovered != 0 {
		t.Errorf("RecoverStale: expected 0, got %d", recovered)
	}
}

// ─── Get ─────────────────────────────────────────────────────────────────────

func TestMemoryJobsStore_Get_ReturnsJob(t *testing.T) {
	s := NewMemoryJobsStore()
	ctx := context.Background()

	j := &jobs.Job{ID: "get-id", Type: "probe", FireAt: time.Now().UTC()}
	_ = s.Enqueue(ctx, j)

	got, err := s.Get(ctx, "get-id")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "get-id" {
		t.Errorf("Get: expected get-id, got %q", got.ID)
	}
}

func TestMemoryJobsStore_Get_MissingReturnsError(t *testing.T) {
	s := NewMemoryJobsStore()
	_, err := s.Get(context.Background(), "no-such-id")
	if err == nil {
		t.Fatal("Get missing: expected error")
	}
}
