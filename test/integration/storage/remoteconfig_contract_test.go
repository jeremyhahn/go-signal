package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// runRemoteConfigStoreContract drives every behavioral expectation of
// remoteconfig.Store across every backend. Identical semantics are
// the locked-in contract — divergences must surface here before they
// can ship.
func runRemoteConfigStoreContract(t *testing.T, factory func(t *testing.T) remoteconfig.Store) {
	t.Helper()

	t.Run("Put_GetAll_RoundTrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		in := remoteconfig.Config{
			Name:         "global.calling",
			Percentage:   42,
			UUIDs:        map[string]struct{}{"u1": {}, "u2": {}},
			Value:        "on",
			DefaultValue: "off",
			HashKey:      "k",
		}
		require.NoError(t, s.Put(ctx, in))
		rows, err := s.GetAll(ctx)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		got := rows[0]
		assert.Equal(t, in.Name, got.Name)
		assert.Equal(t, in.Percentage, got.Percentage)
		assert.Equal(t, in.Value, got.Value)
		assert.Equal(t, in.DefaultValue, got.DefaultValue)
		assert.Equal(t, in.HashKey, got.HashKey)
		assert.Len(t, got.UUIDs, 2)
	})

	t.Run("Put_EmptyName_Rejects", func(t *testing.T) {
		s := factory(t)
		err := s.Put(context.Background(), remoteconfig.Config{Name: ""})
		var invalid *remoteconfig.InvalidConfigError
		assert.ErrorAs(t, err, &invalid)
	})

	t.Run("Put_PercentageOutOfRange_Rejects", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		var invalid *remoteconfig.InvalidConfigError
		err := s.Put(ctx, remoteconfig.Config{Name: "x", Percentage: -1})
		assert.ErrorAs(t, err, &invalid)
		err = s.Put(ctx, remoteconfig.Config{Name: "x", Percentage: 101})
		assert.ErrorAs(t, err, &invalid)
	})

	t.Run("Put_ReplacesExistingRow", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		require.NoError(t, s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 10, Value: "v1"}))
		require.NoError(t, s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 80, Value: "v2"}))
		rows, _ := s.GetAll(ctx)
		require.Len(t, rows, 1)
		assert.Equal(t, 80, rows[0].Percentage)
		assert.Equal(t, "v2", rows[0].Value)
	})

	t.Run("GetAll_SortedByName", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		for _, n := range []string{"zeta", "alpha", "mu"} {
			require.NoError(t, s.Put(ctx, remoteconfig.Config{Name: n}))
		}
		rows, _ := s.GetAll(ctx)
		assert.Equal(t, []string{"alpha", "mu", "zeta"},
			[]string{rows[0].Name, rows[1].Name, rows[2].Name})
	})

	t.Run("Delete_RemovesRow", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		require.NoError(t, s.Put(ctx, remoteconfig.Config{Name: "doomed", Percentage: 50}))
		require.NoError(t, s.Delete(ctx, "doomed"))
		rows, _ := s.GetAll(ctx)
		assert.Len(t, rows, 0)
	})

	t.Run("Delete_Missing_IsIdempotent", func(t *testing.T) {
		s := factory(t)
		require.NoError(t, s.Delete(context.Background(), "absent"))
		require.NoError(t, s.Delete(context.Background(), ""))
	})

	t.Run("EmptyUUIDs_RoundTripAsNil", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		require.NoError(t, s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 0}))
		rows, _ := s.GetAll(ctx)
		require.Len(t, rows, 1)
		assert.Nil(t, rows[0].UUIDs)
	})
}

// TestRemoteConfigStoreContract_Memory runs the contract against the
// in-memory store.
func TestRemoteConfigStoreContract_Memory(t *testing.T) {
	runRemoteConfigStoreContract(t, func(t *testing.T) remoteconfig.Store {
		return remoteconfig.NewMemoryStore()
	})
}

// TestRemoteConfigStoreContract_QRDB runs the contract against the
// qrdb (FakeKVStore) backend.
func TestRemoteConfigStoreContract_QRDB(t *testing.T) {
	runRemoteConfigStoreContract(t, func(t *testing.T) remoteconfig.Store {
		return qrdbstorage.NewRemoteConfigStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestRemoteConfigStoreContract_Postgres runs the contract against a
// live Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestRemoteConfigStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runRemoteConfigStoreContract(t, func(t *testing.T) remoteconfig.Store {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewRemoteConfigStore(c)
	})
}
