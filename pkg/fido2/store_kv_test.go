//go:build fido2

package fido2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

func newKVStore() *KVFIDO2AccountsStore {
	return NewKVFIDO2AccountsStore(store.NewMemoryKVClient())
}

// --- CreateCredential tests ---

func TestKVStore_CreateCredential(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	err := s.CreateCredential(ctx, cred)
	require.NoError(t, err)

	got, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, "cred-1", got.CredentialID)
	assert.Equal(t, "acct-1", got.AccountUUID)
	assert.Equal(t, "Test Key", got.Name)
	assert.Equal(t, []byte("pk-cred-1"), got.PublicKey)
}

func TestKVStore_CreateCredential_Duplicate(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	require.NoError(t, s.CreateCredential(ctx, cred))

	err := s.CreateCredential(ctx, cred)
	require.Error(t, err)

	var target *CredentialExistsError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "cred-1", target.CredentialID)
}

// --- GetCredential tests ---

func TestKVStore_GetCredential(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")
	cred.SignCount = 5
	cred.Transport = []string{"usb", "ble"}

	require.NoError(t, s.CreateCredential(ctx, cred))

	got, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, uint32(5), got.SignCount)
	assert.Equal(t, []string{"usb", "ble"}, got.Transport)
}

func TestKVStore_GetCredential_NotFound(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	_, err := s.GetCredential(ctx, "nonexistent")
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.CredentialID)
}

// --- GetCredentialsByAccount tests ---

func TestKVStore_GetCredentialsByAccount_Multiple(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-2", "acct-1")))
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-3", "acct-2")))

	creds, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	assert.Len(t, creds, 2)

	ids := make(map[string]bool)
	for _, c := range creds {
		ids[c.CredentialID] = true
	}
	assert.True(t, ids["cred-1"])
	assert.True(t, ids["cred-2"])
}

func TestKVStore_GetCredentialsByAccount_Empty(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	creds, err := s.GetCredentialsByAccount(ctx, "nonexistent-account")
	require.NoError(t, err)
	assert.Empty(t, creds)
	assert.NotNil(t, creds)
}

func TestKVStore_GetCredentialsByAccount_IsolatedAccounts(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-2", "acct-2")))

	creds, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, "cred-1", creds[0].CredentialID)
}

// --- UpdateCredential tests ---

func TestKVStore_UpdateCredential(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	require.NoError(t, s.CreateCredential(ctx, cred))

	cred.SignCount = 99
	cred.LastUsedAt = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	require.NoError(t, s.UpdateCredential(ctx, cred))

	got, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, uint32(99), got.SignCount)
	assert.Equal(t, time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC), got.LastUsedAt)
}

func TestKVStore_UpdateCredential_NotFound(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	cred := newTestCredential("nonexistent", "acct-1")

	err := s.UpdateCredential(ctx, cred)
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.CredentialID)
}

// --- DeleteCredential tests ---

func TestKVStore_DeleteCredential(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.DeleteCredential(ctx, "cred-1"))

	_, err := s.GetCredential(ctx, "cred-1")
	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestKVStore_DeleteCredential_NotFound(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	err := s.DeleteCredential(ctx, "nonexistent")
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestKVStore_DeleteCredential_RemovesSecondaryIndex(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-2", "acct-1")))

	require.NoError(t, s.DeleteCredential(ctx, "cred-1"))

	creds, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, "cred-2", creds[0].CredentialID)
}

func TestKVStore_DeleteCredential_RemovesAllIndexEntries(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.DeleteCredential(ctx, "cred-1"))

	creds, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// --- StoreSession tests ---

func TestKVStore_StoreSession(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	session := newTestSession("sess-1", "acct-1", SessionTypeRegistration)

	err := s.StoreSession(ctx, session)
	require.NoError(t, err)

	got, err := s.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, "sess-1", got.ID)
	assert.Equal(t, SessionTypeRegistration, got.Type)
	assert.Equal(t, []byte("challenge-sess-1"), got.Challenge)
}

func TestKVStore_StoreSession_Overwrite(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	session1 := newTestSession("sess-1", "acct-1", SessionTypeRegistration)
	require.NoError(t, s.StoreSession(ctx, session1))

	session2 := newTestSession("sess-1", "acct-1", SessionTypeLogin)
	require.NoError(t, s.StoreSession(ctx, session2))

	got, err := s.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, SessionTypeLogin, got.Type)
}

// --- GetSession tests ---

func TestKVStore_GetSession(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	session := newTestSession("sess-1", "acct-1", SessionTypeLogin)

	require.NoError(t, s.StoreSession(ctx, session))

	got, err := s.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.AccountUUID, got.AccountUUID)
	assert.Equal(t, session.Username, got.Username)
}

func TestKVStore_GetSession_NotFound(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	_, err := s.GetSession(ctx, "nonexistent")
	require.Error(t, err)

	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.SessionID)
}

// --- DeleteSession tests ---

func TestKVStore_DeleteSession(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()
	session := newTestSession("sess-1", "acct-1", SessionTypeEnrollment)

	require.NoError(t, s.StoreSession(ctx, session))
	require.NoError(t, s.DeleteSession(ctx, "sess-1"))

	_, err := s.GetSession(ctx, "sess-1")
	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestKVStore_DeleteSession_NotFound(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	err := s.DeleteSession(ctx, "nonexistent")
	require.Error(t, err)

	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.SessionID)
}

func TestKVStore_DeleteSession_DoesNotAffectOtherSessions(t *testing.T) {
	s := newKVStore()
	ctx := context.Background()

	require.NoError(t, s.StoreSession(ctx, newTestSession("sess-1", "acct-1", SessionTypeLogin)))
	require.NoError(t, s.StoreSession(ctx, newTestSession("sess-2", "acct-1", SessionTypeLogin)))

	require.NoError(t, s.DeleteSession(ctx, "sess-1"))

	got, err := s.GetSession(ctx, "sess-2")
	require.NoError(t, err)
	assert.Equal(t, "sess-2", got.ID)
}

// --- Interface compliance ---

func TestKVStore_ImplementsFIDO2AccountsStore(t *testing.T) {
	var _ FIDO2AccountsStore = (*KVFIDO2AccountsStore)(nil)
}

// --- Error propagation tests using failing KV client ---

func TestKVStore_CreateCredential_ExistsFailure(t *testing.T) {
	fkv := newFailingKVClient()
	fkv.failExists = true
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	err := s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1"))
	require.ErrorIs(t, err, errFailing)
}

func TestKVStore_CreateCredential_PutFailure(t *testing.T) {
	fkv := newFailingKVClient()
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	// Put will fail, but Exists will succeed (returns false).
	fkv.failPut = true
	err := s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1"))
	require.ErrorIs(t, err, errFailing)
}

func TestKVStore_GetCredential_NonKeyNotFoundError(t *testing.T) {
	fkv := newFailingKVClient()
	fkv.failGet = true
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	_, err := s.GetCredential(ctx, "cred-1")
	require.ErrorIs(t, err, errFailing)

	// Verify it is NOT wrapped as CredentialNotFoundError.
	var target *CredentialNotFoundError
	assert.False(t, errors.As(err, &target))
}

func TestKVStore_GetCredential_CorruptData(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVFIDO2AccountsStore(kv)
	ctx := context.Background()

	// Write corrupt data directly to KV.
	require.NoError(t, kv.Put(ctx, "signal/fido2/creds/cred-bad", []byte("not-json")))

	_, err := s.GetCredential(ctx, "cred-bad")
	require.Error(t, err)
}

func TestKVStore_GetCredentialsByAccount_ListFailure(t *testing.T) {
	fkv := newFailingKVClient()
	fkv.failList = true
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	_, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.ErrorIs(t, err, errFailing)
}

func TestKVStore_GetCredentialsByAccount_GetIndexFailure(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVFIDO2AccountsStore(kv)
	ctx := context.Background()

	// Create a credential normally, then corrupt the index entry to point to
	// a nonexistent credential.
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))

	// Delete the primary credential but leave the index.
	require.NoError(t, kv.Delete(ctx, "signal/fido2/creds/cred-1"))

	_, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.Error(t, err)
}

func TestKVStore_UpdateCredential_ExistsFailure(t *testing.T) {
	fkv := newFailingKVClient()
	fkv.failExists = true
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	err := s.UpdateCredential(ctx, newTestCredential("cred-1", "acct-1"))
	require.ErrorIs(t, err, errFailing)
}

func TestKVStore_UpdateCredential_PutFailure(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVFIDO2AccountsStore(kv)
	ctx := context.Background()

	// Create the credential first.
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))

	// Now wrap with a failing client that only fails on Put.
	fkv := newFailingKVClient()
	fkv.data = map[string][]byte{"signal/fido2/creds/cred-1": {}} // Exists returns true.
	fkv.failPut = true
	s2 := NewKVFIDO2AccountsStore(fkv)

	err := s2.UpdateCredential(ctx, newTestCredential("cred-1", "acct-1"))
	require.ErrorIs(t, err, errFailing)
}

func TestKVStore_DeleteCredential_DeleteFailure(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVFIDO2AccountsStore(kv)
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))

	// Now use a client that has the data but fails on delete.
	fkv := newFailingKVClient()
	// Pre-populate with the credential JSON so GetCredential succeeds.
	credData, _ := kv.Get(ctx, "signal/fido2/creds/cred-1")
	fkv.data["signal/fido2/creds/cred-1"] = credData
	fkv.failDelete = true
	s2 := NewKVFIDO2AccountsStore(fkv)

	err := s2.DeleteCredential(ctx, "cred-1")
	require.ErrorIs(t, err, errFailing)
}

func TestKVStore_StoreSession_PutFailure(t *testing.T) {
	fkv := newFailingKVClient()
	fkv.failPut = true
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	err := s.StoreSession(ctx, newTestSession("sess-1", "acct-1", SessionTypeLogin))
	require.ErrorIs(t, err, errFailing)
}

func TestKVStore_GetSession_NonKeyNotFoundError(t *testing.T) {
	fkv := newFailingKVClient()
	fkv.failGet = true
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	_, err := s.GetSession(ctx, "sess-1")
	require.ErrorIs(t, err, errFailing)

	var target *SessionNotFoundError
	assert.False(t, errors.As(err, &target))
}

func TestKVStore_GetSession_CorruptData(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVFIDO2AccountsStore(kv)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "signal/fido2/sessions/sess-bad", []byte("not-json")))

	_, err := s.GetSession(ctx, "sess-bad")
	require.Error(t, err)
}

func TestKVStore_DeleteSession_NonKeyNotFoundError(t *testing.T) {
	fkv := newFailingKVClient()
	fkv.failDelete = true
	s := NewKVFIDO2AccountsStore(fkv)
	ctx := context.Background()

	err := s.DeleteSession(ctx, "sess-1")
	require.ErrorIs(t, err, errFailing)

	var target *SessionNotFoundError
	assert.False(t, errors.As(err, &target))
}
