package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// newTestVerificationSession returns a valid VerificationSession.
func newTestVerificationSession() *verification.VerificationSession {
	return &verification.VerificationSession{
		ID:                   uuid.NewString(),
		Number:               "+15555550100",
		Verified:             false,
		Attempts:             0,
		AllowedToRequestCode: true,
		CreatedAt:            time.Now().UTC().Truncate(time.Second),
		ExpiresAt:            time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second),
	}
}

// runVerificationSessionStoreContract drives every behavioral expectation of
// verification.VerificationSessionStore across all backends.
func runVerificationSessionStoreContract(t *testing.T, factory func(t *testing.T) verification.VerificationSessionStore) {
	t.Helper()

	t.Run("Create_Get_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess := newTestVerificationSession()

		require.NoError(t, s.Create(ctx, sess))

		got, err := s.Get(ctx, sess.ID)
		require.NoError(t, err)
		assert.Equal(t, sess.ID, got.ID)
		assert.Equal(t, sess.Number, got.Number)
		assert.Equal(t, sess.AllowedToRequestCode, got.AllowedToRequestCode)
	})

	t.Run("Create_DuplicateID_RejectsWithError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess := newTestVerificationSession()

		require.NoError(t, s.Create(ctx, sess))

		// All backends must reject a duplicate-ID Create with an error.
		err := s.Create(ctx, sess)
		require.Error(t, err, "second Create with same ID must return an error")

		// The original session must remain readable and unchanged.
		got, err := s.Get(ctx, sess.ID)
		require.NoError(t, err)
		assert.Equal(t, sess.ID, got.ID)
	})

	t.Run("Get_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.Get(ctx, uuid.NewString())
		require.Error(t, err)
		var target *verification.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Update_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess := newTestVerificationSession()
		require.NoError(t, s.Create(ctx, sess))

		sess.Verified = true
		sess.Attempts = 2
		require.NoError(t, s.Update(ctx, sess))

		got, err := s.Get(ctx, sess.ID)
		require.NoError(t, err)
		assert.True(t, got.Verified)
		assert.Equal(t, 2, got.Attempts)
	})

	t.Run("Update_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		ghost := newTestVerificationSession()

		err := s.Update(ctx, ghost)
		require.Error(t, err)
		var target *verification.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Delete_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess := newTestVerificationSession()
		require.NoError(t, s.Create(ctx, sess))

		require.NoError(t, s.Delete(ctx, sess.ID))

		_, err := s.Get(ctx, sess.ID)
		require.Error(t, err)
		var target *verification.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Delete_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		err := s.Delete(ctx, uuid.NewString())
		require.Error(t, err)
		var target *verification.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Count_Empty_Zero", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		n, err := s.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("Count_AfterCreate", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		require.NoError(t, s.Create(ctx, newTestVerificationSession()))
		require.NoError(t, s.Create(ctx, newTestVerificationSession()))

		n, err := s.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, n)
	})

	t.Run("DeleteExpired_RemovesExpiredSessions", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		// Fresh session (not expired).
		fresh := newTestVerificationSession()
		require.NoError(t, s.Create(ctx, fresh))

		// Already-expired session.
		expired := newTestVerificationSession()
		expired.ExpiresAt = time.Now().Add(-1 * time.Hour)
		require.NoError(t, s.Create(ctx, expired))

		require.NoError(t, s.DeleteExpired(ctx))

		// Fresh session must still exist.
		_, err := s.Get(ctx, fresh.ID)
		require.NoError(t, err)

		// Expired session must be gone.
		_, err = s.Get(ctx, expired.ID)
		require.Error(t, err)
		var target *verification.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteExpired_NoExpired_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		require.NoError(t, s.DeleteExpired(ctx))
	})
}

// TestVerificationSessionStoreContract_Memory runs the verification contract
// against the in-memory backend.
func TestVerificationSessionStoreContract_Memory(t *testing.T) {
	runVerificationSessionStoreContract(t, func(t *testing.T) verification.VerificationSessionStore {
		return verification.NewMemoryVerificationSessionStore()
	})
}

// TestVerificationSessionStoreContract_QRDB runs the verification contract
// against the qrdb (FakeKVStore) backend.
func TestVerificationSessionStoreContract_QRDB(t *testing.T) {
	runVerificationSessionStoreContract(t, func(t *testing.T) verification.VerificationSessionStore {
		return qrdbstorage.NewVerificationSessionStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestVerificationSessionStoreContract_Postgres runs the verification contract
// against a live Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestVerificationSessionStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runVerificationSessionStoreContract(t, func(t *testing.T) verification.VerificationSessionStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewVerificationSessionStore(c.Pool())
	})
}
