//go:build fido2

package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/fido2"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestFIDO2Credential returns a minimal FIDO2 credential for testing.
func newTestFIDO2Credential(accountUUID string) *fido2.FIDO2Credential {
	return &fido2.FIDO2Credential{
		CredentialID:    uuid.NewString(),
		AccountUUID:     accountUUID,
		Name:            "Test Key",
		PublicKey:       []byte{0x01, 0x02, 0x03, 0x04},
		AttestationType: "none",
		AAGUID:          make([]byte, 16),
		SignCount:       0,
		Transport:       []string{"usb"},
		CreatedAt:       time.Now().UTC().Truncate(time.Second),
		LastUsedAt:      time.Now().UTC().Truncate(time.Second),
	}
}

// newTestFIDO2Session returns a minimal FIDO2 session for testing.
func newTestFIDO2Session(accountUUID string) *fido2.FIDO2Session {
	return &fido2.FIDO2Session{
		ID:          uuid.NewString(),
		AccountUUID: accountUUID,
		Challenge:   []byte{0xde, 0xad, 0xbe, 0xef},
		SessionData: []byte("session-data-blob"),
		Type:        fido2.SessionTypeRegistration,
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		ExpiresAt:   time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second),
	}
}

// runFIDO2AccountsStoreContract drives every behavioral expectation of
// fido2.FIDO2AccountsStore across all backends.
func runFIDO2AccountsStoreContract(t *testing.T, factory func(t *testing.T) fido2.FIDO2AccountsStore) {
	t.Helper()

	t.Run("CreateCredential_GetCredential_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		cred := newTestFIDO2Credential(uid)

		require.NoError(t, s.CreateCredential(ctx, cred))

		got, err := s.GetCredential(ctx, cred.CredentialID)
		require.NoError(t, err)
		assert.Equal(t, cred.CredentialID, got.CredentialID)
		assert.Equal(t, cred.AccountUUID, got.AccountUUID)
		assert.Equal(t, cred.Name, got.Name)
		assert.Equal(t, cred.PublicKey, got.PublicKey)
	})

	t.Run("CreateCredential_Duplicate_CredentialExistsError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		cred := newTestFIDO2Credential(uid)

		require.NoError(t, s.CreateCredential(ctx, cred))

		err := s.CreateCredential(ctx, cred)
		require.Error(t, err)
		var target *fido2.CredentialExistsError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("GetCredential_NotFound_CredentialNotFoundError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetCredential(ctx, uuid.NewString())
		require.Error(t, err)
		var target *fido2.CredentialNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("GetCredentialsByAccount_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()

		cred1 := newTestFIDO2Credential(uid)
		cred2 := newTestFIDO2Credential(uid)

		require.NoError(t, s.CreateCredential(ctx, cred1))
		require.NoError(t, s.CreateCredential(ctx, cred2))

		creds, err := s.GetCredentialsByAccount(ctx, uid)
		require.NoError(t, err)
		assert.Len(t, creds, 2)
	})

	t.Run("GetCredentialsByAccount_Empty_ReturnsSlice", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		creds, err := s.GetCredentialsByAccount(ctx, uuid.NewString())
		require.NoError(t, err)
		assert.NotNil(t, creds)
		assert.Len(t, creds, 0)
	})

	t.Run("UpdateCredential_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		cred := newTestFIDO2Credential(uid)

		require.NoError(t, s.CreateCredential(ctx, cred))

		cred.SignCount = 42
		cred.Name = "Updated Key"
		require.NoError(t, s.UpdateCredential(ctx, cred))

		got, err := s.GetCredential(ctx, cred.CredentialID)
		require.NoError(t, err)
		assert.Equal(t, uint32(42), got.SignCount)
		assert.Equal(t, "Updated Key", got.Name)
	})

	t.Run("UpdateCredential_NotFound_CredentialNotFoundError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		cred := newTestFIDO2Credential(uid)

		err := s.UpdateCredential(ctx, cred)
		require.Error(t, err)
		var target *fido2.CredentialNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteCredential_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		cred := newTestFIDO2Credential(uid)

		require.NoError(t, s.CreateCredential(ctx, cred))
		require.NoError(t, s.DeleteCredential(ctx, cred.CredentialID))

		_, err := s.GetCredential(ctx, cred.CredentialID)
		require.Error(t, err)
		var target *fido2.CredentialNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteCredential_NotFound_CredentialNotFoundError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		err := s.DeleteCredential(ctx, uuid.NewString())
		require.Error(t, err)
		var target *fido2.CredentialNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteCredential_RemovedFromAccountIndex", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		cred := newTestFIDO2Credential(uid)

		require.NoError(t, s.CreateCredential(ctx, cred))
		require.NoError(t, s.DeleteCredential(ctx, cred.CredentialID))

		creds, err := s.GetCredentialsByAccount(ctx, uid)
		require.NoError(t, err)
		assert.Len(t, creds, 0)
	})

	t.Run("StoreSession_GetSession_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		sess := newTestFIDO2Session(uid)

		require.NoError(t, s.StoreSession(ctx, sess))

		got, err := s.GetSession(ctx, sess.ID)
		require.NoError(t, err)
		assert.Equal(t, sess.ID, got.ID)
		assert.Equal(t, sess.AccountUUID, got.AccountUUID)
		assert.Equal(t, sess.Challenge, got.Challenge)
		assert.Equal(t, sess.Type, got.Type)
	})

	t.Run("StoreSession_Overwrites_ExistingSession", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		sess := newTestFIDO2Session(uid)

		require.NoError(t, s.StoreSession(ctx, sess))

		sess.Challenge = []byte{0xca, 0xfe}
		require.NoError(t, s.StoreSession(ctx, sess))

		got, err := s.GetSession(ctx, sess.ID)
		require.NoError(t, err)
		assert.Equal(t, []byte{0xca, 0xfe}, got.Challenge)
	})

	t.Run("GetSession_NotFound_SessionNotFoundError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.GetSession(ctx, uuid.NewString())
		require.Error(t, err)
		var target *fido2.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteSession_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid := uuid.NewString()
		sess := newTestFIDO2Session(uid)

		require.NoError(t, s.StoreSession(ctx, sess))
		require.NoError(t, s.DeleteSession(ctx, sess.ID))

		_, err := s.GetSession(ctx, sess.ID)
		require.Error(t, err)
		var target *fido2.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("DeleteSession_NotFound_SessionNotFoundError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		err := s.DeleteSession(ctx, uuid.NewString())
		require.Error(t, err)
		var target *fido2.SessionNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("AccountIsolation_Credentials", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uid1 := uuid.NewString()
		uid2 := uuid.NewString()

		require.NoError(t, s.CreateCredential(ctx, newTestFIDO2Credential(uid1)))

		creds2, err := s.GetCredentialsByAccount(ctx, uid2)
		require.NoError(t, err)
		assert.Len(t, creds2, 0)
	})
}

// TestFIDO2AccountsStoreContract_Memory runs the FIDO2 contract against the
// in-memory backend (fido2.MemoryFIDO2AccountsStore).
func TestFIDO2AccountsStoreContract_Memory(t *testing.T) {
	runFIDO2AccountsStoreContract(t, func(t *testing.T) fido2.FIDO2AccountsStore {
		return fido2.NewMemoryFIDO2AccountsStore()
	})
}

// TestFIDO2AccountsStoreContract_QRDB runs the FIDO2 contract against the
// qrdb (FakeKVStore) backend.
func TestFIDO2AccountsStoreContract_QRDB(t *testing.T) {
	runFIDO2AccountsStoreContract(t, func(t *testing.T) fido2.FIDO2AccountsStore {
		return qrdbstorage.NewFIDO2AccountsStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestFIDO2AccountsStoreContract_Postgres runs the FIDO2 contract against a
// live Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestFIDO2AccountsStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runFIDO2AccountsStoreContract(t, func(t *testing.T) fido2.FIDO2AccountsStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewFIDO2AccountsStore(c.Pool())
	})
}
