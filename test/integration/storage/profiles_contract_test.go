package storage_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/profiles"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestProfile returns a minimal profile for testing.
func newTestProfile(accountUUID, version string) *profiles.Profile {
	return &profiles.Profile{
		UUID:       accountUUID,
		Version:    version,
		Name:       []byte("encrypted-name"),
		About:      []byte("encrypted-about"),
		AboutEmoji: []byte("encrypted-emoji"),
		Avatar:     "profiles/avatar-key",
		Commitment: []byte("commitment-bytes"),
	}
}

// runProfileStoreContract drives every behavioral expectation of
// profiles.ProfileStore across all backends.
func runProfileStoreContract(t *testing.T, factory func(t *testing.T) profiles.ProfileStore) {
	t.Helper()

	t.Run("Set_Get_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		p := newTestProfile(uid, "v1")

		require.NoError(t, s.Set(ctx, p))

		got, err := s.Get(ctx, uid, "v1")
		require.NoError(t, err)
		assert.Equal(t, p.UUID, got.UUID)
		assert.Equal(t, p.Version, got.Version)
		assert.Equal(t, p.Name, got.Name)
		assert.Equal(t, p.About, got.About)
		assert.Equal(t, p.Avatar, got.Avatar)
	})

	t.Run("Get_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.Get(ctx, uuid.NewString(), "v1")
		require.Error(t, err)
	})

	t.Run("GetLatest_AfterMultipleVersions", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.Set(ctx, newTestProfile(uid, "v1")))
		require.NoError(t, s.Set(ctx, newTestProfile(uid, "v2")))
		require.NoError(t, s.Set(ctx, newTestProfile(uid, "v3")))

		latest, err := s.GetLatest(ctx, uid)
		require.NoError(t, err)
		// The latest version must be the most recently set one.
		assert.Equal(t, "v3", latest.Version)
	})

	t.Run("GetLatest_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetLatest(ctx, uuid.NewString())
		require.Error(t, err)
	})

	t.Run("Set_UpdatesExistingVersion", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		p1 := newTestProfile(uid, "v1")
		require.NoError(t, s.Set(ctx, p1))

		p2 := newTestProfile(uid, "v1")
		p2.Name = []byte("updated-name")
		require.NoError(t, s.Set(ctx, p2))

		got, err := s.Get(ctx, uid, "v1")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated-name"), got.Name)
	})

	t.Run("Delete_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.Set(ctx, newTestProfile(uid, "v1")))
		require.NoError(t, s.Delete(ctx, uid))

		_, err := s.GetLatest(ctx, uid)
		require.Error(t, err)

		_, err = s.Get(ctx, uid, "v1")
		require.Error(t, err)
	})

	t.Run("Delete_NotFound_Idempotent", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		// All backends must be idempotent: deleting a missing UUID returns nil.
		require.NoError(t, s.Delete(ctx, uuid.NewString()))
	})

	t.Run("AccountIsolation", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid1 := uuid.NewString()
		uid2 := uuid.NewString()

		require.NoError(t, s.Set(ctx, newTestProfile(uid1, "v1")))

		_, err := s.GetLatest(ctx, uid2)
		require.Error(t, err)
	})
}

// TestProfileStoreContract_Memory runs the profile contract against the
// in-memory backend.
func TestProfileStoreContract_Memory(t *testing.T) {
	runProfileStoreContract(t, func(t *testing.T) profiles.ProfileStore {
		return memorystorage.NewMemoryProfileStore()
	})
}

// TestProfileStoreContract_QRDB runs the profile contract against the qrdb
// (FakeKVStore) backend.
func TestProfileStoreContract_QRDB(t *testing.T) {
	runProfileStoreContract(t, func(t *testing.T) profiles.ProfileStore {
		return qrdbstorage.NewProfileStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestProfileStoreContract_Postgres runs the profile contract against a live
// Postgres instance. Skips if TEST_POSTGRES_URL is unset.
//
// The postgres profiles table has an FK to accounts(aci). Contract callers
// don't seed accounts (memory and qrdb don't require it), so the factory
// returns a tiny wrapper that auto-seeds the parent account row on Set.
// The wrapper is invisible to the contract — every other method delegates.
func TestProfileStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runProfileStoreContract(t, func(t *testing.T) profiles.ProfileStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return &seededProfileStore{
			inner: postgres.NewProfileStore(c.Pool()),
			pool:  c.Pool(),
		}
	})
}

// seededProfileStore is a thin wrapper that ensures the parent accounts row
// exists before delegating Set to the real store. Other methods delegate
// untouched.
type seededProfileStore struct {
	inner profiles.ProfileStore
	pool  *pgxpool.Pool
}

func (s *seededProfileStore) Set(ctx context.Context, p *profiles.Profile) error {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO accounts (aci, pni, e164, version, data)
		VALUES ($1, $2, $3, 0, '{}'::jsonb)
		ON CONFLICT (aci) DO NOTHING`,
		p.UUID, uuid.NewString(), "+1555"+p.UUID[:7],
	); err != nil {
		return err
	}
	return s.inner.Set(ctx, p)
}

func (s *seededProfileStore) Get(ctx context.Context, uuid, version string) (*profiles.Profile, error) {
	return s.inner.Get(ctx, uuid, version)
}

func (s *seededProfileStore) GetLatest(ctx context.Context, uuid string) (*profiles.Profile, error) {
	return s.inner.GetLatest(ctx, uuid)
}

func (s *seededProfileStore) Delete(ctx context.Context, uuid string) error {
	return s.inner.Delete(ctx, uuid)
}
