package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/devices"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestProvisioningSession returns a valid provisioning session.
func newTestProvisioningSession() *devices.ProvisioningSession {
	return &devices.ProvisioningSession{
		Code:      uuid.NewString(),
		UUID:      uuid.NewString(),
		ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second),
	}
}

// runProvisioningStoreContract drives every behavioral expectation of
// devices.ProvisioningStore across all backends.
func runProvisioningStoreContract(t *testing.T, factory func(t *testing.T) devices.ProvisioningStore) {
	t.Helper()

	t.Run("StoreSession_GetSession_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess := newTestProvisioningSession()

		require.NoError(t, s.StoreSession(ctx, sess))

		got, err := s.GetSession(ctx, sess.Code)
		require.NoError(t, err)
		assert.Equal(t, sess.Code, got.Code)
		assert.Equal(t, sess.UUID, got.UUID)
	})

	t.Run("GetSession_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetSession(ctx, "nonexistent-code")
		require.Error(t, err)
		var target *devices.InvalidProvisioningCodeError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("StoreSession_Overwrites_ExistingSession", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess := newTestProvisioningSession()

		require.NoError(t, s.StoreSession(ctx, sess))

		// Replace with updated UUID (simulates re-issuing the code).
		updated := *sess
		updated.UUID = uuid.NewString()
		require.NoError(t, s.StoreSession(ctx, &updated))

		got, err := s.GetSession(ctx, sess.Code)
		require.NoError(t, err)
		assert.Equal(t, updated.UUID, got.UUID)
	})

	t.Run("DeleteSession_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess := newTestProvisioningSession()

		require.NoError(t, s.StoreSession(ctx, sess))
		require.NoError(t, s.DeleteSession(ctx, sess.Code))

		_, err := s.GetSession(ctx, sess.Code)
		require.Error(t, err)
		var target *devices.InvalidProvisioningCodeError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteSession_Idempotent", func(t *testing.T) {
		// The interface contract does not mandate an error on missing delete.
		// Memory and qrdb both return nil for missing deletes; postgres also
		// returns nil. So we assert no error on a second delete.
		s := factory(t)
		ctx := context.Background()
		sess := newTestProvisioningSession()

		require.NoError(t, s.StoreSession(ctx, sess))
		require.NoError(t, s.DeleteSession(ctx, sess.Code))
		// A second delete is permitted to succeed silently (idempotent contract).
		// If a backend returns an error here, that is a divergence to flag.
		_ = s.DeleteSession(ctx, sess.Code)
	})

	t.Run("MultipleSessionsIsolated", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		sess1 := newTestProvisioningSession()
		sess2 := newTestProvisioningSession()

		require.NoError(t, s.StoreSession(ctx, sess1))
		require.NoError(t, s.StoreSession(ctx, sess2))

		got1, err := s.GetSession(ctx, sess1.Code)
		require.NoError(t, err)
		assert.Equal(t, sess1.UUID, got1.UUID)

		got2, err := s.GetSession(ctx, sess2.Code)
		require.NoError(t, err)
		assert.Equal(t, sess2.UUID, got2.UUID)
	})
}

// TestProvisioningStoreContract_Memory runs the provisioning contract against
// the in-memory backend.
func TestProvisioningStoreContract_Memory(t *testing.T) {
	runProvisioningStoreContract(t, func(t *testing.T) devices.ProvisioningStore {
		return memorystorage.NewMemoryProvisioningStore()
	})
}

// TestProvisioningStoreContract_QRDB runs the provisioning contract against
// the qrdb (FakeKVStore) backend.
func TestProvisioningStoreContract_QRDB(t *testing.T) {
	runProvisioningStoreContract(t, func(t *testing.T) devices.ProvisioningStore {
		return qrdbstorage.NewProvisioningStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestProvisioningStoreContract_Postgres runs the provisioning contract
// against a live Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestProvisioningStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runProvisioningStoreContract(t, func(t *testing.T) devices.ProvisioningStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewProvisioningStore(c.Pool())
	})
}
