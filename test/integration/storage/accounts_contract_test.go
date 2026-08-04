package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestAccount returns a valid, minimal account suitable for insertion.
func newTestAccount() *accounts.Account {
	return &accounts.Account{
		UUID:      uuid.NewString(),
		PNI:       uuid.NewString(),
		Number:    "+1" + uuid.NewString()[:10],
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Version:   0,
	}
}

// runAccountStoreContract drives every behavioral expectation of the
// accounts.AccountStore interface. All backends must satisfy every sub-test.
func runAccountStoreContract(t *testing.T, factory func(t *testing.T) accounts.AccountStore) {
	t.Helper()

	t.Run("Create_Get_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()

		require.NoError(t, s.Create(ctx, a))

		got, err := s.Get(ctx, a.UUID)
		require.NoError(t, err)
		assert.Equal(t, a.UUID, got.UUID)
		assert.Equal(t, a.PNI, got.PNI)
		assert.Equal(t, a.Number, got.Number)
	})

	t.Run("Create_DuplicateUUID_AlreadyExists", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()

		require.NoError(t, s.Create(ctx, a))

		dup := *a
		err := s.Create(ctx, &dup)
		require.Error(t, err)
		var target *accounts.AccountAlreadyExistsError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Create_DuplicateNumber_AlreadyExists", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		b := newTestAccount()
		b.Number = a.Number // same phone number, different UUID/PNI

		err := s.Create(ctx, b)
		require.Error(t, err)
		var target *accounts.AccountAlreadyExistsError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Create_DuplicatePNI_AlreadyExists", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		b := newTestAccount()
		b.PNI = a.PNI // same PNI, different UUID/number

		err := s.Create(ctx, b)
		require.Error(t, err)
		var target *accounts.AccountAlreadyExistsError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Get_NotFound", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.Get(ctx, uuid.NewString())
		require.Error(t, err)
		var target *accounts.AccountNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("GetByNumber_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		got, err := s.GetByNumber(ctx, a.Number)
		require.NoError(t, err)
		assert.Equal(t, a.UUID, got.UUID)
	})

	t.Run("GetByNumber_NotFound", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetByNumber(ctx, "+10000000000")
		require.Error(t, err)
		var target *accounts.AccountNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("GetByPNI_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		got, err := s.GetByPNI(ctx, a.PNI)
		require.NoError(t, err)
		assert.Equal(t, a.UUID, got.UUID)
	})

	t.Run("GetByPNI_NotFound", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetByPNI(ctx, uuid.NewString())
		require.Error(t, err)
		var target *accounts.AccountNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Update_VersionIncrement_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		updated := *a
		updated.Version = 1 // version 0 → 1
		updated.Number = "+1" + uuid.NewString()[:10]

		require.NoError(t, s.Update(ctx, &updated))

		got, err := s.Get(ctx, a.UUID)
		require.NoError(t, err)
		assert.Equal(t, updated.Number, got.Number)
		assert.Equal(t, uint64(1), got.Version)
	})

	t.Run("Update_WrongVersion_VersionConflict", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		stale := *a
		stale.Version = 5 // wrong: expected version 1

		err := s.Update(ctx, &stale)
		require.Error(t, err)
		var target *accounts.VersionConflictError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Update_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		ghost := newTestAccount()
		ghost.Version = 1

		err := s.Update(ctx, ghost)
		require.Error(t, err)
		// Both AccountNotFoundError and VersionConflictError are acceptable
		// for a non-existent account; the important thing is that no nil error
		// is returned.
	})

	t.Run("Update_PhoneNumberChange_IndexUpdated", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		newNumber := "+1" + uuid.NewString()[:10]
		updated := *a
		updated.Version = 1
		updated.Number = newNumber

		require.NoError(t, s.Update(ctx, &updated))

		// New number must be reachable.
		got, err := s.GetByNumber(ctx, newNumber)
		require.NoError(t, err)
		assert.Equal(t, a.UUID, got.UUID)

		// Old number must no longer resolve.
		_, err = s.GetByNumber(ctx, a.Number)
		require.Error(t, err)
		var notFound *accounts.AccountNotFoundError
		assert.ErrorAs(t, err, &notFound)
	})

	t.Run("Delete_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))

		require.NoError(t, s.Delete(ctx, a.UUID))

		_, err := s.Get(ctx, a.UUID)
		require.Error(t, err)
		var target *accounts.AccountNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Delete_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		err := s.Delete(ctx, uuid.NewString())
		require.Error(t, err)
		var target *accounts.AccountNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Delete_RemovesNumberIndex", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))
		require.NoError(t, s.Delete(ctx, a.UUID))

		_, err := s.GetByNumber(ctx, a.Number)
		require.Error(t, err)
	})

	t.Run("Delete_RemovesPNIIndex", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		a := newTestAccount()
		require.NoError(t, s.Create(ctx, a))
		require.NoError(t, s.Delete(ctx, a.UUID))

		_, err := s.GetByPNI(ctx, a.PNI)
		require.Error(t, err)
	})
}

// TestAccountStoreContract_Memory runs the account contract against the
// in-memory backend.
func TestAccountStoreContract_Memory(t *testing.T) {
	runAccountStoreContract(t, func(t *testing.T) accounts.AccountStore {
		return memorystorage.NewMemoryAccountStore()
	})
}

// TestAccountStoreContract_QRDB runs the account contract against the
// qrdb (FakeKVStore) backend.
func TestAccountStoreContract_QRDB(t *testing.T) {
	runAccountStoreContract(t, func(t *testing.T) accounts.AccountStore {
		return qrdbstorage.NewAccountStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestAccountStoreContract_Postgres runs the account contract against a live
// Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestAccountStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runAccountStoreContract(t, func(t *testing.T) accounts.AccountStore {
		// Each sub-test gets a fresh truncated database.
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewAccountStore(c.Pool())
	})
}
