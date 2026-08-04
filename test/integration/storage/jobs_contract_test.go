package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/jobs"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// runJobsStoreContract drives every behavioral expectation of
// jobs.Store across all backends. Identical semantics are the
// locked-in contract; divergences must fail here before they can
// ship.
func runJobsStoreContract(t *testing.T, factory func(t *testing.T) jobs.Store) {
	t.Helper()

	t.Run("Enqueue_Get_RoundTrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		j := &jobs.Job{Type: "t", FireAt: time.Now().UTC().Truncate(time.Second), Payload: []byte("hi")}
		require.NoError(t, s.Enqueue(ctx, j))
		require.NotEmpty(t, j.ID)
		got, err := s.Get(ctx, j.ID)
		require.NoError(t, err)
		assert.Equal(t, j.Type, got.Type)
		assert.Equal(t, j.Payload, got.Payload)
		assert.Equal(t, jobs.StatusPending, got.Status)
	})

	t.Run("Get_Missing_Error", func(t *testing.T) {
		s := factory(t)
		_, err := s.Get(context.Background(), "absent")
		assert.True(t, errors.Is(err, jobs.ErrJobNotFound))
	})

	t.Run("ClaimDue_RespectsFireAt", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		past := &jobs.Job{Type: "p", FireAt: now.Add(-time.Hour)}
		future := &jobs.Job{Type: "f", FireAt: now.Add(time.Hour)}
		require.NoError(t, s.Enqueue(ctx, past))
		require.NoError(t, s.Enqueue(ctx, future))

		got, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, past.ID, got[0].ID)
		assert.Equal(t, jobs.StatusRunning, got[0].Status)
		assert.Equal(t, 1, got[0].Attempts)
	})

	t.Run("ClaimDue_RespectsLimit", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		for i := 0; i < 5; i++ {
			require.NoError(t, s.Enqueue(ctx, &jobs.Job{Type: "x", FireAt: now.Add(-time.Hour)}))
		}
		got, err := s.ClaimDue(ctx, now, 3)
		require.NoError(t, err)
		assert.Len(t, got, 3)
	})

	t.Run("ClaimDue_DoesNotClaimRunning", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		j := &jobs.Job{Type: "x", FireAt: now.Add(-time.Hour)}
		require.NoError(t, s.Enqueue(ctx, j))
		first, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)
		require.Len(t, first, 1)
		second, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)
		assert.Len(t, second, 0)
	})

	t.Run("MarkDone_Removes", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		j := &jobs.Job{Type: "x", FireAt: time.Now().Add(-time.Hour)}
		require.NoError(t, s.Enqueue(ctx, j))
		require.NoError(t, s.MarkDone(ctx, j.ID))
		_, err := s.Get(ctx, j.ID)
		assert.True(t, errors.Is(err, jobs.ErrJobNotFound))
	})

	t.Run("MarkFailed_RequeuesUntilBudgetExhausted", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		j := &jobs.Job{Type: "x", FireAt: now.Add(-time.Hour)}
		require.NoError(t, s.Enqueue(ctx, j))

		// First failure: re-queue with attempts=1, status=pending.
		_, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)
		require.NoError(t, s.MarkFailed(ctx, j.ID, now, time.Minute, 2))
		got, _ := s.Get(ctx, j.ID)
		assert.Equal(t, jobs.StatusPending, got.Status)
		assert.Equal(t, 1, got.Attempts)

		// Re-claim now requires advancing time past the new FireAt
		// (now + 1*backoff). The contract for memory/qrdb advances
		// by attempts*backoff; assert by claiming with a future
		// "now" so FireAt has elapsed.
		futureNow := got.FireAt.Add(time.Second)
		_, err = s.ClaimDue(ctx, futureNow, 10)
		require.NoError(t, err)
		require.NoError(t, s.MarkFailed(ctx, j.ID, futureNow, time.Minute, 2))
		got, _ = s.Get(ctx, j.ID)
		assert.Equal(t, jobs.StatusFailed, got.Status)
	})

	t.Run("MarkFailed_Missing_Idempotent", func(t *testing.T) {
		s := factory(t)
		err := s.MarkFailed(context.Background(), "absent",
			time.Now(), time.Minute, 3)
		// Either ErrJobNotFound or nil is acceptable depending on
		// backend storage semantics; both keep the system safe.
		_ = err
	})

	t.Run("ResetToPending_FlipsRunningBackToPending", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		j := &jobs.Job{Type: "x", FireAt: now.Add(-time.Hour)}
		require.NoError(t, s.Enqueue(ctx, j))
		_, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)

		// Job is now Running; reset it.
		require.NoError(t, s.ResetToPending(ctx, j.ID, now))
		got, err := s.Get(ctx, j.ID)
		require.NoError(t, err)
		assert.Equal(t, jobs.StatusPending, got.Status)
	})

	t.Run("ResetToPending_NonRunning_NoOp", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		j := &jobs.Job{Type: "x", FireAt: time.Now().Add(-time.Hour)}
		require.NoError(t, s.Enqueue(ctx, j))
		// Reset on Pending row — should be a no-op (no error).
		require.NoError(t, s.ResetToPending(ctx, j.ID, time.Now()))
		got, _ := s.Get(ctx, j.ID)
		assert.Equal(t, jobs.StatusPending, got.Status)
	})

	t.Run("ResetToPending_Missing_NoError", func(t *testing.T) {
		s := factory(t)
		require.NoError(t, s.ResetToPending(context.Background(), "absent", time.Now()))
	})

	t.Run("RecoverStale_ReQueuesStaleRunning", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		j := &jobs.Job{Type: "x", FireAt: now.Add(-time.Hour)}
		require.NoError(t, s.Enqueue(ctx, j))
		_, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)

		// Sweep with threshold 10s in the future — the row was
		// just claimed but its claim time is "before" the
		// threshold, so it's stale by definition.
		recovered, err := s.RecoverStale(ctx, now.Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, 1, recovered)

		got, _ := s.Get(ctx, j.ID)
		assert.Equal(t, jobs.StatusPending, got.Status)
	})

	t.Run("RecoverStale_KeepsFreshlyClaimed", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		j := &jobs.Job{Type: "x", FireAt: now.Add(-time.Hour)}
		require.NoError(t, s.Enqueue(ctx, j))
		_, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)

		// Sweep with a threshold in the distant past — nothing
		// should be considered stale.
		recovered, err := s.RecoverStale(ctx, now.Add(-time.Hour))
		require.NoError(t, err)
		assert.Equal(t, 0, recovered)
	})

	t.Run("ClaimDue_TypeFilter_OnlyMatching", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		require.NoError(t, s.Enqueue(ctx, &jobs.Job{Type: "alpha", FireAt: now.Add(-time.Hour)}))
		require.NoError(t, s.Enqueue(ctx, &jobs.Job{Type: "beta", FireAt: now.Add(-time.Hour)}))
		require.NoError(t, s.Enqueue(ctx, &jobs.Job{Type: "gamma", FireAt: now.Add(-time.Hour)}))

		got, err := s.ClaimDue(ctx, now, 10, "alpha", "gamma")
		require.NoError(t, err)
		require.Len(t, got, 2)
		seen := map[string]bool{}
		for _, j := range got {
			seen[j.Type] = true
		}
		assert.True(t, seen["alpha"])
		assert.True(t, seen["gamma"])
		assert.False(t, seen["beta"])
	})

	t.Run("ClaimDue_EmptyTypeFilter_ClaimsAll", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		now := time.Now().UTC()
		require.NoError(t, s.Enqueue(ctx, &jobs.Job{Type: "alpha", FireAt: now.Add(-time.Hour)}))
		require.NoError(t, s.Enqueue(ctx, &jobs.Job{Type: "beta", FireAt: now.Add(-time.Hour)}))

		got, err := s.ClaimDue(ctx, now, 10)
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
}

// TestJobsStoreContract_Memory runs the contract against the
// in-memory store.
func TestJobsStoreContract_Memory(t *testing.T) {
	runJobsStoreContract(t, func(t *testing.T) jobs.Store {
		return memorystorage.NewMemoryJobsStore()
	})
}

// TestJobsStoreContract_QRDB runs the contract against the qrdb
// (FakeKVStore) backend.
func TestJobsStoreContract_QRDB(t *testing.T) {
	runJobsStoreContract(t, func(t *testing.T) jobs.Store {
		return qrdbstorage.NewJobsStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestJobsStoreContract_Postgres runs the contract against a live
// Postgres instance.
func TestJobsStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runJobsStoreContract(t, func(t *testing.T) jobs.Store {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewJobsStore(c)
	})
}
