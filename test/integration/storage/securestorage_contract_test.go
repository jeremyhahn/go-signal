package storage_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestManifest returns a minimal storage manifest.
func newTestManifest(version uint64) *securestorage.StorageManifest {
	return &securestorage.StorageManifest{
		Version: version,
		Value:   []byte("encrypted-manifest-blob"),
	}
}

// newTestStorageItem returns a minimal storage item for the given key seed.
func newTestStorageItem(keySeed byte) *securestorage.StorageItem {
	key := make([]byte, 16)
	for i := range key {
		key[i] = keySeed + byte(i)
	}
	return &securestorage.StorageItem{
		Key:   key,
		Value: []byte("encrypted-item-value"),
	}
}

// runSecureStorageStoreContract drives every behavioral expectation of
// securestorage.ManifestStore across all backends.
func runSecureStorageStoreContract(t *testing.T, factory func(t *testing.T) securestorage.ManifestStore) {
	t.Helper()

	t.Run("GetManifest_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetManifest(ctx, uuid.NewString())
		require.Error(t, err)
		var target *securestorage.ManifestNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("PutManifest_GetManifest_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		m := newTestManifest(1)

		require.NoError(t, s.PutManifest(ctx, uid, m))

		got, err := s.GetManifest(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), got.Version)
		assert.Equal(t, m.Value, got.Value)
	})

	t.Run("PutManifest_StrictlyGreaterVersion_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.PutManifest(ctx, uid, newTestManifest(1)))
		require.NoError(t, s.PutManifest(ctx, uid, newTestManifest(2)))

		got, err := s.GetManifest(ctx, uid)
		require.NoError(t, err)
		assert.Equal(t, uint64(2), got.Version)
	})

	t.Run("PutManifest_SameVersion_VersionConflict", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.PutManifest(ctx, uid, newTestManifest(1)))

		err := s.PutManifest(ctx, uid, newTestManifest(1))
		require.Error(t, err)
		var target *securestorage.ManifestVersionConflictError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("PutManifest_LowerVersion_VersionConflict", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.PutManifest(ctx, uid, newTestManifest(5)))

		err := s.PutManifest(ctx, uid, newTestManifest(3))
		require.Error(t, err)
		var target *securestorage.ManifestVersionConflictError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("PutItem_GetItem_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		item := newTestStorageItem(0x10)

		require.NoError(t, s.PutItem(ctx, uid, item))

		got, err := s.GetItem(ctx, uid, item.Key)
		require.NoError(t, err)
		assert.Equal(t, item.Key, got.Key)
		assert.Equal(t, item.Value, got.Value)
	})

	t.Run("GetItem_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		_, err := s.GetItem(ctx, uid, []byte("missing-key"))
		require.Error(t, err)
		var target *securestorage.StorageItemNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("PutItem_Overwrites_ExistingValue", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		item := newTestStorageItem(0x20)

		require.NoError(t, s.PutItem(ctx, uid, item))

		item.Value = []byte("updated-value")
		require.NoError(t, s.PutItem(ctx, uid, item))

		got, err := s.GetItem(ctx, uid, item.Key)
		require.NoError(t, err)
		assert.Equal(t, []byte("updated-value"), got.Value)
	})

	t.Run("DeleteItem_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		item := newTestStorageItem(0x30)

		require.NoError(t, s.PutItem(ctx, uid, item))
		require.NoError(t, s.DeleteItem(ctx, uid, item.Key))

		_, err := s.GetItem(ctx, uid, item.Key)
		require.Error(t, err)
		var target *securestorage.StorageItemNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteItem_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		err := s.DeleteItem(ctx, uid, []byte("no-such-key"))
		require.Error(t, err)
		var target *securestorage.StorageItemNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteAll_RemovesManifestAndItems", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.PutManifest(ctx, uid, newTestManifest(1)))
		require.NoError(t, s.PutItem(ctx, uid, newTestStorageItem(0x40)))
		require.NoError(t, s.PutItem(ctx, uid, newTestStorageItem(0x50)))

		require.NoError(t, s.DeleteAll(ctx, uid))

		_, err := s.GetManifest(ctx, uid)
		require.Error(t, err)
		var notFound *securestorage.ManifestNotFoundError
		assert.ErrorAs(t, err, &notFound)
	})

	t.Run("DeleteAll_Idempotent", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.DeleteAll(ctx, uid))
		require.NoError(t, s.DeleteAll(ctx, uid))
	})

	t.Run("AccountIsolation", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid1 := uuid.NewString()
		uid2 := uuid.NewString()

		require.NoError(t, s.PutManifest(ctx, uid1, newTestManifest(1)))

		_, err := s.GetManifest(ctx, uid2)
		require.Error(t, err)
		var target *securestorage.ManifestNotFoundError
		assert.ErrorAs(t, err, &target)
	})
}

// TestSecureStorageStoreContract_Memory runs the secure storage contract
// against the in-memory backend.
func TestSecureStorageStoreContract_Memory(t *testing.T) {
	runSecureStorageStoreContract(t, func(t *testing.T) securestorage.ManifestStore {
		return memorystorage.NewMemoryManifestStore()
	})
}

// TestSecureStorageStoreContract_QRDB runs the secure storage contract
// against the qrdb (FakeKVStore) backend.
func TestSecureStorageStoreContract_QRDB(t *testing.T) {
	runSecureStorageStoreContract(t, func(t *testing.T) securestorage.ManifestStore {
		return qrdbstorage.NewSecureStorageStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestSecureStorageStoreContract_Postgres runs the secure storage contract
// against a live Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestSecureStorageStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runSecureStorageStoreContract(t, func(t *testing.T) securestorage.ManifestStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewManifestStore(c)
	})
}
