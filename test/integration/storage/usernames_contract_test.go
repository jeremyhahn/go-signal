package storage_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// newUsernameHash returns a deterministic 32-byte hash for testing.
func newUsernameHash(seed byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed + byte(i)
	}
	return h
}

// runUsernameStoreContract drives every behavioral expectation of
// usernames.UsernameStore across all backends.
func runUsernameStoreContract(t *testing.T, factory func(t *testing.T) usernames.UsernameStore) {
	t.Helper()

	t.Run("ReserveHash_ConfirmHash_LookupByHash_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		hash := newUsernameHash(1)

		selectedHash, token, err := s.ReserveHash(ctx, uid, [][]byte{hash})
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Equal(t, hash, selectedHash)

		require.NoError(t, s.ConfirmHash(ctx, uid, selectedHash, token))

		foundUID, err := s.LookupByHash(ctx, hash)
		require.NoError(t, err)
		assert.Equal(t, uid, foundUID)
	})

	t.Run("ReserveHash_AllConflict_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid1 := uuid.NewString()
		uid2 := uuid.NewString()
		hash := newUsernameHash(2)

		// uid1 reserves and confirms the hash.
		_, token1, err := s.ReserveHash(ctx, uid1, [][]byte{hash})
		require.NoError(t, err)
		require.NoError(t, s.ConfirmHash(ctx, uid1, hash, token1))

		// uid2 attempts to reserve the same hash — all candidates conflict.
		_, _, err = s.ReserveHash(ctx, uid2, [][]byte{hash})
		require.Error(t, err)
		var target *usernames.UsernameHashConflictError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("ConfirmHash_InvalidToken_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		hash := newUsernameHash(3)

		_, _, err := s.ReserveHash(ctx, uid, [][]byte{hash})
		require.NoError(t, err)

		err = s.ConfirmHash(ctx, uid, hash, "bad-token")
		require.Error(t, err)
		var target *usernames.InvalidReservationTokenError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("ConfirmHash_NoReservation_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		hash := newUsernameHash(4)

		err := s.ConfirmHash(ctx, uid, hash, "no-reservation")
		require.Error(t, err)
		var target *usernames.InvalidReservationTokenError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("LookupByHash_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.LookupByHash(ctx, newUsernameHash(5))
		require.Error(t, err)
		var target *usernames.UsernameNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteHash_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		hash := newUsernameHash(6)

		_, token, err := s.ReserveHash(ctx, uid, [][]byte{hash})
		require.NoError(t, err)
		require.NoError(t, s.ConfirmHash(ctx, uid, hash, token))

		require.NoError(t, s.DeleteHash(ctx, uid))

		_, err = s.LookupByHash(ctx, hash)
		require.Error(t, err)
		var target *usernames.UsernameNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteHash_NotFound_Idempotent", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		// All backends must be idempotent: deleting a hash for a UUID with no
		// confirmed hash returns nil.
		require.NoError(t, s.DeleteHash(ctx, uuid.NewString()))
	})

	t.Run("SetLink_GetLink_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		handle := uuid.NewString()

		link := &usernames.UsernameLink{
			UUID:               uid,
			UsernameLinkHandle: handle,
			EncryptedUsername:  []byte("encrypted-username"),
		}
		require.NoError(t, s.SetLink(ctx, link))

		got, err := s.GetLink(ctx, handle)
		require.NoError(t, err)
		assert.Equal(t, uid, got.UUID)
		assert.Equal(t, handle, got.UsernameLinkHandle)
		assert.Equal(t, []byte("encrypted-username"), got.EncryptedUsername)
	})

	t.Run("GetLink_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetLink(ctx, uuid.NewString())
		require.Error(t, err)
		var target *usernames.UsernameLinkNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("SetLink_Replaces_OldLink", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		handle1 := uuid.NewString()
		handle2 := uuid.NewString()

		require.NoError(t, s.SetLink(ctx, &usernames.UsernameLink{
			UUID:               uid,
			UsernameLinkHandle: handle1,
			EncryptedUsername:  []byte("old"),
		}))

		require.NoError(t, s.SetLink(ctx, &usernames.UsernameLink{
			UUID:               uid,
			UsernameLinkHandle: handle2,
			EncryptedUsername:  []byte("new"),
		}))

		// New handle must be reachable.
		got, err := s.GetLink(ctx, handle2)
		require.NoError(t, err)
		assert.Equal(t, uid, got.UUID)

		// Old handle must be gone.
		_, err = s.GetLink(ctx, handle1)
		require.Error(t, err)
	})

	t.Run("DeleteLink_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		handle := uuid.NewString()

		require.NoError(t, s.SetLink(ctx, &usernames.UsernameLink{
			UUID:               uid,
			UsernameLinkHandle: handle,
			EncryptedUsername:  []byte("data"),
		}))

		require.NoError(t, s.DeleteLink(ctx, uid))

		_, err := s.GetLink(ctx, handle)
		require.Error(t, err)
		var target *usernames.UsernameLinkNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteLink_NotFound_Idempotent", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		// All backends must be idempotent: deleting a link for a UUID with no
		// link returns nil.
		require.NoError(t, s.DeleteLink(ctx, uuid.NewString()))
	})

	t.Run("FirstAvailableHash_Selected", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid1 := uuid.NewString()
		uid2 := uuid.NewString()

		// uid1 takes hash A.
		hashA := newUsernameHash(10)
		hashB := newUsernameHash(11)
		_, tokenA, err := s.ReserveHash(ctx, uid1, [][]byte{hashA})
		require.NoError(t, err)
		require.NoError(t, s.ConfirmHash(ctx, uid1, hashA, tokenA))

		// uid2 provides [A, B]; A is taken so B must be selected.
		selected, token2, err := s.ReserveHash(ctx, uid2, [][]byte{hashA, hashB})
		require.NoError(t, err)
		assert.Equal(t, hashB, selected)
		require.NoError(t, s.ConfirmHash(ctx, uid2, hashB, token2))
	})

	t.Run("DeleteExpiredReservations_MissingTreatedAsZero", func(t *testing.T) {
		s := factory(t)
		n, err := s.DeleteExpiredReservations(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("DeleteExpiredReservations_KeepsActiveReservations", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		hash := newUsernameHash(40)
		_, _, err := s.ReserveHash(ctx, uid, [][]byte{hash})
		require.NoError(t, err)
		n, err := s.DeleteExpiredReservations(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})
}

// TestUsernameStoreContract_Memory runs the username contract against the
// in-memory backend.
func TestUsernameStoreContract_Memory(t *testing.T) {
	runUsernameStoreContract(t, func(t *testing.T) usernames.UsernameStore {
		return memorystorage.NewMemoryUsernameStore()
	})
}

// TestUsernameStoreContract_QRDB runs the username contract against the qrdb
// (FakeKVStore) backend.
func TestUsernameStoreContract_QRDB(t *testing.T) {
	runUsernameStoreContract(t, func(t *testing.T) usernames.UsernameStore {
		return qrdbstorage.NewUsernameStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestUsernameStoreContract_Postgres runs the username contract against a
// live Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestUsernameStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runUsernameStoreContract(t, func(t *testing.T) usernames.UsernameStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewUsernameStore(c)
	})
}
