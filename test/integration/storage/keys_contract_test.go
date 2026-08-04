package storage_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/keys"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newECPreKey returns a minimal EC one-time pre-key for testing.
func newECPreKey(id uint64) *keys.PreKey {
	return &keys.PreKey{
		KeyID:     id,
		PublicKey: []byte{0x01, 0x02, 0x03, byte(id)},
	}
}

// newSignedPreKey returns a minimal signed pre-key for testing.
func newSignedPreKey(id uint64) *keys.SignedPreKey {
	return &keys.SignedPreKey{
		KeyID:     id,
		PublicKey: []byte{0x04, 0x05, 0x06, byte(id)},
		Signature: []byte{0x07, 0x08, 0x09, byte(id)},
	}
}

// newKEMPreKey returns a minimal KEM one-time pre-key for testing.
func newKEMPreKey(id uint64) *keys.KEMSignedPreKey {
	return &keys.KEMSignedPreKey{
		KeyID:     id,
		PublicKey: []byte{0x0a, 0x0b, 0x0c, byte(id)},
		Signature: []byte{0x0d, 0x0e, 0x0f, byte(id)},
	}
}

// newKEMLastResortPreKey returns a minimal KEM last-resort pre-key for testing.
func newKEMLastResortPreKey(id uint64) *keys.KEMSignedPreKey {
	k := newKEMPreKey(id)
	k.IsLastResort = true
	return k
}

// runPreKeyStoreContract drives every behavioral expectation of
// keys.PreKeyStore across all backends.
func runPreKeyStoreContract(t *testing.T, factory func(t *testing.T) keys.PreKeyStore) {
	t.Helper()

	const deviceID = uint64(1)

	t.Run("StoreECPreKeys_GetPreKeyCount_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		batch := []*keys.PreKey{newECPreKey(1), newECPreKey(2), newECPreKey(3)}
		require.NoError(t, s.StoreECPreKeys(ctx, uid, deviceID, batch))

		state, err := s.GetPreKeyCount(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, 3, state.ECCount)
	})

	t.Run("TakeEC_ConsumesKey", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.StoreECPreKeys(ctx, uid, deviceID, []*keys.PreKey{newECPreKey(10)}))

		pk, err := s.TakeEC(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, uint64(10), pk.KeyID)

		// Queue must now be empty.
		state, err := s.GetPreKeyCount(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, 0, state.ECCount)
	})

	t.Run("TakeEC_Empty_NilOrError", func(t *testing.T) {
		// DIVERGENCE: memory returns an error on an empty queue; qrdb returns
		// (nil, nil). The interface doc does not specify the empty-queue
		// contract. Both behaviours are captured here: the test passes if the
		// result is either (nil, non-nil) or (nil, nil). A caller should check
		// both the returned key and the error before using the key.
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		pk, err := s.TakeEC(ctx, uid, deviceID)
		// At least one of (pk, err) must indicate "not available":
		// either err != nil OR pk == nil.
		if err == nil {
			assert.Nil(t, pk, "empty TakeEC must return nil key when err is nil")
		}
	})

	t.Run("StoreKEMPreKeys_TakeKEM_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		batch := []*keys.KEMSignedPreKey{newKEMPreKey(20), newKEMPreKey(21)}
		require.NoError(t, s.StoreKEMPreKeys(ctx, uid, deviceID, batch))

		pk, err := s.TakeKEM(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, uint64(20), pk.KeyID)

		state, err := s.GetPreKeyCount(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, 1, state.KEMCount)
	})

	t.Run("TakeKEM_Empty_NilOrError", func(t *testing.T) {
		// DIVERGENCE: memory returns an error on an empty queue; qrdb returns
		// (nil, nil). See TakeEC_Empty_NilOrError for discussion.
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		pk, err := s.TakeKEM(ctx, uid, deviceID)
		if err == nil {
			assert.Nil(t, pk, "empty TakeKEM must return nil key when err is nil")
		}
	})

	t.Run("StoreKEMLastResortPreKey_GetKEMLastResortPreKey_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		lr := newKEMLastResortPreKey(99)
		require.NoError(t, s.StoreKEMLastResortPreKey(ctx, uid, deviceID, lr))

		got, err := s.GetKEMLastResortPreKey(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, uint64(99), got.KeyID)
		// Retrieving does not consume it.
		got2, err := s.GetKEMLastResortPreKey(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, uint64(99), got2.KeyID)
	})

	t.Run("StoreKEMLastResortPreKey_Replaces", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.StoreKEMLastResortPreKey(ctx, uid, deviceID, newKEMLastResortPreKey(100)))
		require.NoError(t, s.StoreKEMLastResortPreKey(ctx, uid, deviceID, newKEMLastResortPreKey(101)))

		got, err := s.GetKEMLastResortPreKey(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, uint64(101), got.KeyID)
	})

	t.Run("GetKEMLastResortPreKey_Missing_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetKEMLastResortPreKey(ctx, uuid.NewString(), deviceID)
		require.Error(t, err)
	})

	t.Run("StoreSignedPreKey_GetSignedPreKey_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		spk := newSignedPreKey(50)
		require.NoError(t, s.StoreSignedPreKey(ctx, uid, deviceID, spk))

		got, err := s.GetSignedPreKey(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, uint64(50), got.KeyID)
	})

	t.Run("GetSignedPreKey_Missing_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetSignedPreKey(ctx, uuid.NewString(), deviceID)
		require.Error(t, err)
	})

	t.Run("GetPreKeyCount_HasLastResort", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.StoreKEMLastResortPreKey(ctx, uid, deviceID, newKEMLastResortPreKey(200)))

		state, err := s.GetPreKeyCount(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.True(t, state.HasLastResort)
	})

	t.Run("GetPreKeyCount_NoLastResort", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		state, err := s.GetPreKeyCount(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.False(t, state.HasLastResort)
	})

	t.Run("DeleteAllForDevice_ClearsAllKeyTypes", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		require.NoError(t, s.StoreECPreKeys(ctx, uid, deviceID, []*keys.PreKey{newECPreKey(1)}))
		require.NoError(t, s.StoreKEMPreKeys(ctx, uid, deviceID, []*keys.KEMSignedPreKey{newKEMPreKey(2)}))
		require.NoError(t, s.StoreKEMLastResortPreKey(ctx, uid, deviceID, newKEMLastResortPreKey(3)))
		require.NoError(t, s.StoreSignedPreKey(ctx, uid, deviceID, newSignedPreKey(4)))

		require.NoError(t, s.DeleteAllForDevice(ctx, uid, deviceID))

		state, err := s.GetPreKeyCount(ctx, uid, deviceID)
		require.NoError(t, err)
		assert.Equal(t, 0, state.ECCount)
		assert.Equal(t, 0, state.KEMCount)
		assert.False(t, state.HasLastResort)

		_, err = s.GetSignedPreKey(ctx, uid, deviceID)
		require.Error(t, err)
	})

	t.Run("DeleteAllForAccount_ClearsMultipleDevices", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		const dev1, dev2 = uint64(1), uint64(2)

		require.NoError(t, s.StoreECPreKeys(ctx, uid, dev1, []*keys.PreKey{newECPreKey(1)}))
		require.NoError(t, s.StoreECPreKeys(ctx, uid, dev2, []*keys.PreKey{newECPreKey(2)}))

		require.NoError(t, s.DeleteAllForAccount(ctx, uid))

		for _, dev := range []uint64{dev1, dev2} {
			state, err := s.GetPreKeyCount(ctx, uid, dev)
			require.NoError(t, err)
			assert.Equal(t, 0, state.ECCount, "device %d should have 0 EC keys", dev)
		}
	})

	t.Run("MultiDeviceIsolation", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		const dev1, dev2 = uint64(1), uint64(2)

		require.NoError(t, s.StoreECPreKeys(ctx, uid, dev1, []*keys.PreKey{newECPreKey(1)}))
		require.NoError(t, s.StoreECPreKeys(ctx, uid, dev2, []*keys.PreKey{newECPreKey(2), newECPreKey(3)}))

		s1, err := s.GetPreKeyCount(ctx, uid, dev1)
		require.NoError(t, err)
		assert.Equal(t, 1, s1.ECCount)

		s2, err := s.GetPreKeyCount(ctx, uid, dev2)
		require.NoError(t, err)
		assert.Equal(t, 2, s2.ECCount)
	})
}

// TestPreKeyStoreContract_Memory runs the pre-key contract against the
// in-memory backend.
func TestPreKeyStoreContract_Memory(t *testing.T) {
	runPreKeyStoreContract(t, func(t *testing.T) keys.PreKeyStore {
		return memorystorage.NewMemoryPreKeyStore()
	})
}

// TestPreKeyStoreContract_QRDB runs the pre-key contract against the qrdb
// (FakeKVStore) backend.
func TestPreKeyStoreContract_QRDB(t *testing.T) {
	runPreKeyStoreContract(t, func(t *testing.T) keys.PreKeyStore {
		return qrdbstorage.NewPreKeyStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestPreKeyStoreContract_Postgres runs the pre-key contract against a live
// Postgres instance. Skips if TEST_POSTGRES_URL is unset.
//
// Pre-key tables FK-cascade from accounts(aci). The factory wraps the real
// store with seededPreKeyStore so the contract test (which doesn't seed
// accounts — memory and qrdb don't require it) passes against postgres.
func TestPreKeyStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runPreKeyStoreContract(t, func(t *testing.T) keys.PreKeyStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return &seededPreKeyStore{
			inner: postgres.NewPreKeyStore(c.Pool()),
			pool:  c.Pool(),
		}
	})
}

// seededPreKeyStore ensures the parent accounts row exists before any Store
// call delegates to the real store. Take/Get/Delete don't need seeding (the
// FK only fires on INSERT).
type seededPreKeyStore struct {
	inner keys.PreKeyStore
	pool  *pgxpool.Pool
}

func (s *seededPreKeyStore) seed(ctx context.Context, aci string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO accounts (aci, pni, e164, version, data)
		VALUES ($1, $2, $3, 0, '{}'::jsonb)
		ON CONFLICT (aci) DO NOTHING`,
		aci, uuid.NewString(), "+1555"+aci[:7],
	)
	return err
}

func (s *seededPreKeyStore) StoreECPreKeys(ctx context.Context, aci string, dev uint64, pk []*keys.PreKey) error {
	if err := s.seed(ctx, aci); err != nil {
		return err
	}
	return s.inner.StoreECPreKeys(ctx, aci, dev, pk)
}

func (s *seededPreKeyStore) StoreKEMPreKeys(ctx context.Context, aci string, dev uint64, pk []*keys.KEMSignedPreKey) error {
	if err := s.seed(ctx, aci); err != nil {
		return err
	}
	return s.inner.StoreKEMPreKeys(ctx, aci, dev, pk)
}

func (s *seededPreKeyStore) StoreKEMLastResortPreKey(ctx context.Context, aci string, dev uint64, pk *keys.KEMSignedPreKey) error {
	if err := s.seed(ctx, aci); err != nil {
		return err
	}
	return s.inner.StoreKEMLastResortPreKey(ctx, aci, dev, pk)
}

func (s *seededPreKeyStore) StoreSignedPreKey(ctx context.Context, aci string, dev uint64, pk *keys.SignedPreKey) error {
	if err := s.seed(ctx, aci); err != nil {
		return err
	}
	return s.inner.StoreSignedPreKey(ctx, aci, dev, pk)
}

func (s *seededPreKeyStore) TakeEC(ctx context.Context, aci string, dev uint64) (*keys.PreKey, error) {
	return s.inner.TakeEC(ctx, aci, dev)
}

func (s *seededPreKeyStore) TakeKEM(ctx context.Context, aci string, dev uint64) (*keys.KEMSignedPreKey, error) {
	return s.inner.TakeKEM(ctx, aci, dev)
}

func (s *seededPreKeyStore) GetKEMLastResortPreKey(ctx context.Context, aci string, dev uint64) (*keys.KEMSignedPreKey, error) {
	return s.inner.GetKEMLastResortPreKey(ctx, aci, dev)
}

func (s *seededPreKeyStore) GetSignedPreKey(ctx context.Context, aci string, dev uint64) (*keys.SignedPreKey, error) {
	return s.inner.GetSignedPreKey(ctx, aci, dev)
}

func (s *seededPreKeyStore) GetPreKeyCount(ctx context.Context, aci string, dev uint64) (*keys.PreKeyState, error) {
	return s.inner.GetPreKeyCount(ctx, aci, dev)
}

func (s *seededPreKeyStore) DeleteAllForDevice(ctx context.Context, aci string, dev uint64) error {
	return s.inner.DeleteAllForDevice(ctx, aci, dev)
}

func (s *seededPreKeyStore) DeleteAllForAccount(ctx context.Context, aci string) error {
	return s.inner.DeleteAllForAccount(ctx, aci)
}

func (s *seededPreKeyStore) ListAccountUUIDs(ctx context.Context) ([]string, error) {
	return s.inner.ListAccountUUIDs(ctx)
}
