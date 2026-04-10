//go:build fido2

package fido2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCredential(id, accountUUID string) *FIDO2Credential {
	return &FIDO2Credential{
		CredentialID:    id,
		AccountUUID:     accountUUID,
		Name:            "Test Key",
		PublicKey:       []byte("pk-" + id),
		AttestationType: "none",
		AAGUID:          []byte{0x01, 0x02, 0x03, 0x04},
		SignCount:       0,
		CloneWarning:    false,
		Transport:       []string{"usb", "nfc"},
		CreatedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUsedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func newTestSession(id, accountUUID string, sessionType FIDO2SessionType) *FIDO2Session {
	return &FIDO2Session{
		ID:          id,
		AccountUUID: accountUUID,
		Username:    "testuser",
		Challenge:   []byte("challenge-" + id),
		SessionData: []byte("session-data-" + id),
		Type:        sessionType,
		CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
	}
}

// --- CreateCredential tests ---

func TestMemoryStore_CreateCredential(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	err := s.CreateCredential(ctx, cred)
	require.NoError(t, err)

	got, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, "cred-1", got.CredentialID)
	assert.Equal(t, "acct-1", got.AccountUUID)
	assert.Equal(t, []string{"usb", "nfc"}, got.Transport)
}

func TestMemoryStore_CreateCredential_Duplicate(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
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

func TestMemoryStore_GetCredential(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	require.NoError(t, s.CreateCredential(ctx, cred))

	got, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, cred.CredentialID, got.CredentialID)
	assert.Equal(t, cred.Name, got.Name)
	assert.Equal(t, cred.PublicKey, got.PublicKey)
}

func TestMemoryStore_GetCredential_NotFound(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	_, err := s.GetCredential(ctx, "nonexistent")
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.CredentialID)
}

func TestMemoryStore_GetCredential_DeepCopy(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	require.NoError(t, s.CreateCredential(ctx, cred))

	got1, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)

	// Mutate the returned value.
	got1.Name = "MUTATED"
	got1.PublicKey[0] = 0xFF
	got1.Transport[0] = "mutated"

	// Fetch again and verify the store is unaffected.
	got2, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, "Test Key", got2.Name)
	assert.Equal(t, byte('p'), got2.PublicKey[0])
	assert.Equal(t, "usb", got2.Transport[0])
}

// --- GetCredentialsByAccount tests ---

func TestMemoryStore_GetCredentialsByAccount_Multiple(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
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

func TestMemoryStore_GetCredentialsByAccount_Empty(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	creds, err := s.GetCredentialsByAccount(ctx, "nonexistent-account")
	require.NoError(t, err)
	assert.Empty(t, creds)
	assert.NotNil(t, creds) // Returns empty slice, not nil.
}

func TestMemoryStore_GetCredentialsByAccount_DeepCopy(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))

	creds, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	require.Len(t, creds, 1)

	// Mutate the returned credential.
	creds[0].Name = "MUTATED"

	// Verify the store is unaffected.
	creds2, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	require.Len(t, creds2, 1)
	assert.Equal(t, "Test Key", creds2[0].Name)
}

// --- UpdateCredential tests ---

func TestMemoryStore_UpdateCredential(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	require.NoError(t, s.CreateCredential(ctx, cred))

	cred.SignCount = 42
	cred.LastUsedAt = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	require.NoError(t, s.UpdateCredential(ctx, cred))

	got, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, uint32(42), got.SignCount)
	assert.Equal(t, time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC), got.LastUsedAt)
}

func TestMemoryStore_UpdateCredential_NotFound(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	cred := newTestCredential("nonexistent", "acct-1")

	err := s.UpdateCredential(ctx, cred)
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.CredentialID)
}

// --- DeleteCredential tests ---

func TestMemoryStore_DeleteCredential(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.DeleteCredential(ctx, "cred-1"))

	_, err := s.GetCredential(ctx, "cred-1")
	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestMemoryStore_DeleteCredential_NotFound(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	err := s.DeleteCredential(ctx, "nonexistent")
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestMemoryStore_DeleteCredential_CleansSecondaryIndex(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-2", "acct-1")))

	require.NoError(t, s.DeleteCredential(ctx, "cred-1"))

	creds, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, "cred-2", creds[0].CredentialID)
}

func TestMemoryStore_DeleteCredential_RemovesAccountEntry(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.DeleteCredential(ctx, "cred-1"))

	// Verify the account entry is fully cleaned up.
	creds, err := s.GetCredentialsByAccount(ctx, "acct-1")
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestMemoryStore_DeleteCredential_DoesNotAffectOtherAccounts(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-1", "acct-1")))
	require.NoError(t, s.CreateCredential(ctx, newTestCredential("cred-2", "acct-2")))

	require.NoError(t, s.DeleteCredential(ctx, "cred-1"))

	creds, err := s.GetCredentialsByAccount(ctx, "acct-2")
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, "cred-2", creds[0].CredentialID)
}

// --- StoreSession tests ---

func TestMemoryStore_StoreSession(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
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

func TestMemoryStore_StoreSession_Overwrite(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
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

func TestMemoryStore_GetSession(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	session := newTestSession("sess-1", "acct-1", SessionTypeLogin)

	require.NoError(t, s.StoreSession(ctx, session))

	got, err := s.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.AccountUUID, got.AccountUUID)
	assert.Equal(t, session.Type, got.Type)
}

func TestMemoryStore_GetSession_NotFound(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	_, err := s.GetSession(ctx, "nonexistent")
	require.Error(t, err)

	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.SessionID)
}

func TestMemoryStore_GetSession_DeepCopy(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	session := newTestSession("sess-1", "acct-1", SessionTypeRegistration)

	require.NoError(t, s.StoreSession(ctx, session))

	got1, err := s.GetSession(ctx, "sess-1")
	require.NoError(t, err)

	// Mutate the returned session.
	got1.Username = "MUTATED"
	got1.Challenge[0] = 0xFF

	// Verify the store is unaffected.
	got2, err := s.GetSession(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, "testuser", got2.Username)
	assert.Equal(t, byte('c'), got2.Challenge[0])
}

// --- DeleteSession tests ---

func TestMemoryStore_DeleteSession(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	session := newTestSession("sess-1", "acct-1", SessionTypeEnrollment)

	require.NoError(t, s.StoreSession(ctx, session))
	require.NoError(t, s.DeleteSession(ctx, "sess-1"))

	_, err := s.GetSession(ctx, "sess-1")
	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestMemoryStore_DeleteSession_NotFound(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	err := s.DeleteSession(ctx, "nonexistent")
	require.Error(t, err)

	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.SessionID)
}

func TestMemoryStore_DeleteSession_DoesNotAffectOtherSessions(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()

	require.NoError(t, s.StoreSession(ctx, newTestSession("sess-1", "acct-1", SessionTypeLogin)))
	require.NoError(t, s.StoreSession(ctx, newTestSession("sess-2", "acct-1", SessionTypeLogin)))

	require.NoError(t, s.DeleteSession(ctx, "sess-1"))

	got, err := s.GetSession(ctx, "sess-2")
	require.NoError(t, err)
	assert.Equal(t, "sess-2", got.ID)
}

// --- Interface compliance ---

func TestMemoryStore_ImplementsFIDO2AccountsStore(t *testing.T) {
	var _ FIDO2AccountsStore = (*MemoryFIDO2AccountsStore)(nil)
}

func TestMemoryStore_CreateCredential_DeepCopyInput(t *testing.T) {
	s := NewMemoryFIDO2AccountsStore()
	ctx := context.Background()
	cred := newTestCredential("cred-1", "acct-1")

	require.NoError(t, s.CreateCredential(ctx, cred))

	// Mutate the input after creation.
	cred.Name = "MUTATED"
	cred.PublicKey[0] = 0xFF

	// Verify the store is unaffected.
	got, err := s.GetCredential(ctx, "cred-1")
	require.NoError(t, err)
	assert.Equal(t, "Test Key", got.Name)
	assert.Equal(t, byte('p'), got.PublicKey[0])
}
