//go:build fido2

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// newCredential builds a deterministic FIDO2Credential for tests.
func newCredential(credID, accountUUID string) *fido2.FIDO2Credential {
	return &fido2.FIDO2Credential{
		CredentialID:    credID,
		AccountUUID:     accountUUID,
		Name:            "test-key",
		PublicKey:       []byte("pubkey"),
		AttestationType: "packed",
		AAGUID:          []byte{0x01, 0x02},
		SignCount:       0,
		Transport:       []string{"usb"},
		CreatedAt:       time.Now().UTC().Truncate(time.Millisecond),
		LastUsedAt:      time.Now().UTC().Truncate(time.Millisecond),
	}
}

// newSession builds a deterministic FIDO2Session for tests.
func newSession(sessionID, accountUUID string) *fido2.FIDO2Session {
	return &fido2.FIDO2Session{
		ID:          sessionID,
		AccountUUID: accountUUID,
		Challenge:   []byte("challenge-bytes"),
		SessionData: []byte("session-data-bytes"),
		Type:        fido2.SessionTypeRegistration,
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
		ExpiresAt:   time.Now().Add(5 * time.Minute).UTC().Truncate(time.Millisecond),
	}
}

func TestFIDO2_CreateCredential_GetCredential_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	credID := uuid.NewString()
	accountUUID := uuid.NewString()
	want := newCredential(credID, accountUUID)

	if err := s.CreateCredential(ctx, want); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	got, err := s.GetCredential(ctx, credID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got.CredentialID != credID || got.AccountUUID != accountUUID || got.Name != "test-key" {
		t.Fatalf("GetCredential returned unexpected credential: %+v", got)
	}
}

func TestFIDO2_CreateCredential_Duplicate_ReturnsExistsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	credID := uuid.NewString()
	cred := newCredential(credID, uuid.NewString())

	if err := s.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential #1: %v", err)
	}
	err := s.CreateCredential(ctx, cred)
	var cee *fido2.CredentialExistsError
	if !errors.As(err, &cee) {
		t.Fatalf("expected CredentialExistsError, got %T: %v", err, err)
	}
	if cee.CredentialID != credID {
		t.Fatalf("CredentialExistsError carries wrong ID: %q", cee.CredentialID)
	}
}

func TestFIDO2_GetCredential_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	_, err := s.GetCredential(context.Background(), uuid.NewString())
	var nfe *fido2.CredentialNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected CredentialNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_GetCredentialsByAccount_ReturnsMultipleInOrder(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	accountUUID := uuid.NewString()
	id1 := uuid.NewString()
	id2 := uuid.NewString()

	cred1 := newCredential(id1, accountUUID)
	cred1.Name = "first"
	if err := s.CreateCredential(ctx, cred1); err != nil {
		t.Fatalf("CreateCredential #1: %v", err)
	}
	cred2 := newCredential(id2, accountUUID)
	cred2.Name = "second"
	if err := s.CreateCredential(ctx, cred2); err != nil {
		t.Fatalf("CreateCredential #2: %v", err)
	}

	got, err := s.GetCredentialsByAccount(ctx, accountUUID)
	if err != nil {
		t.Fatalf("GetCredentialsByAccount: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
	// Both credentials must belong to the right account.
	for _, cr := range got {
		if cr.AccountUUID != accountUUID {
			t.Fatalf("credential has wrong account UUID: %q", cr.AccountUUID)
		}
	}
}

func TestFIDO2_GetCredentialsByAccount_Empty(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	got, err := s.GetCredentialsByAccount(context.Background(), uuid.NewString())
	if err != nil {
		t.Fatalf("GetCredentialsByAccount: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 credentials for unknown account, got %d", len(got))
	}
}

func TestFIDO2_UpdateCredential_ChangesData(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	credID := uuid.NewString()
	cred := newCredential(credID, uuid.NewString())
	if err := s.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	cred.Name = "updated-key"
	cred.SignCount = 42
	if err := s.UpdateCredential(ctx, cred); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}

	got, err := s.GetCredential(ctx, credID)
	if err != nil {
		t.Fatalf("GetCredential after update: %v", err)
	}
	if got.Name != "updated-key" || got.SignCount != 42 {
		t.Fatalf("UpdateCredential did not persist changes: %+v", got)
	}
}

func TestFIDO2_UpdateCredential_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	cred := newCredential(uuid.NewString(), uuid.NewString())
	err := s.UpdateCredential(context.Background(), cred)
	var nfe *fido2.CredentialNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected CredentialNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_DeleteCredential_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	credID := uuid.NewString()
	if err := s.CreateCredential(ctx, newCredential(credID, uuid.NewString())); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if err := s.DeleteCredential(ctx, credID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	_, err := s.GetCredential(ctx, credID)
	var nfe *fido2.CredentialNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected CredentialNotFoundError after delete, got %T: %v", err, err)
	}
}

func TestFIDO2_DeleteCredential_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	err := s.DeleteCredential(context.Background(), uuid.NewString())
	var nfe *fido2.CredentialNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected CredentialNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_StoreSession_GetSession_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	sessionID := uuid.NewString()
	accountUUID := uuid.NewString()
	want := newSession(sessionID, accountUUID)

	if err := s.StoreSession(ctx, want); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	got, err := s.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sessionID || got.AccountUUID != accountUUID {
		t.Fatalf("GetSession returned unexpected session: %+v", got)
	}
	if string(got.Challenge) != "challenge-bytes" {
		t.Fatalf("Challenge not preserved: %q", got.Challenge)
	}
}

func TestFIDO2_StoreSession_Upserts_ExistingSession(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	sessionID := uuid.NewString()
	sess := newSession(sessionID, uuid.NewString())
	if err := s.StoreSession(ctx, sess); err != nil {
		t.Fatalf("StoreSession #1: %v", err)
	}

	// Re-store with a different challenge (simulates nonce refresh).
	sess.Challenge = []byte("new-challenge")
	if err := s.StoreSession(ctx, sess); err != nil {
		t.Fatalf("StoreSession #2 (upsert): %v", err)
	}

	got, err := s.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession after upsert: %v", err)
	}
	if string(got.Challenge) != "new-challenge" {
		t.Fatalf("upsert did not update challenge: %q", got.Challenge)
	}
}

func TestFIDO2_GetSession_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	_, err := s.GetSession(context.Background(), uuid.NewString())
	var nfe *fido2.SessionNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_DeleteSession_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	sessionID := uuid.NewString()
	if err := s.StoreSession(ctx, newSession(sessionID, uuid.NewString())); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	if err := s.DeleteSession(ctx, sessionID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	_, err := s.GetSession(ctx, sessionID)
	var nfe *fido2.SessionNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected SessionNotFoundError after delete, got %T: %v", err, err)
	}
}

func TestFIDO2_DeleteSession_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	err := s.DeleteSession(context.Background(), uuid.NewString())
	var nfe *fido2.SessionNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_CreateCredential_NilCredential_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	err := s.CreateCredential(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil credential, got nil")
	}
}

func TestFIDO2_UpdateCredential_NilCredential_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	err := s.UpdateCredential(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil credential, got nil")
	}
}

func TestFIDO2_StoreSession_NilSession_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	err := s.StoreSession(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil session, got nil")
	}
}

// TestFIDO2_GetCredentialsByAccount_ReturnsEmptySliceNotNil verifies that an
// account with no credentials returns a nil slice (the implementation
// uses append, so it starts nil and stays nil when no rows match).
func TestFIDO2_GetCredentialsByAccount_UnknownAccount_ReturnsNilOrEmpty(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())

	got, err := s.GetCredentialsByAccount(context.Background(), uuid.NewString())
	if err != nil {
		t.Fatalf("GetCredentialsByAccount: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 credentials, got %d", len(got))
	}
}

// TestFIDO2_StoreSession_EmptyAccountUUID exercises the nullableString("")
// path inside StoreSession (anonymous / pre-account sessions).
func TestFIDO2_DeleteCredential_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	c.Close()

	err := s.DeleteCredential(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestFIDO2_DeleteSession_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	c.Close()

	err := s.DeleteSession(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestFIDO2_UpdateCredential_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	c.Close()

	cred := newCredential(uuid.NewString(), uuid.NewString())
	err := s.UpdateCredential(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestFIDO2_CreateCredential_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	c.Close()

	cred := newCredential(uuid.NewString(), uuid.NewString())
	err := s.CreateCredential(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestFIDO2_GetCredentialsByAccount_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	c.Close()

	_, err := s.GetCredentialsByAccount(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestFIDO2_GetCredential_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	c.Close()

	_, err := s.GetCredential(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestFIDO2_GetSession_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	c.Close()

	_, err := s.GetSession(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestFIDO2_StoreSession_EmptyAccountUUID(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	sessionID := uuid.NewString()
	// A session with no AccountUUID is valid — it represents a pre-auth ceremony.
	sess := newSession(sessionID, "")
	sess.AccountUUID = ""
	if err := s.StoreSession(ctx, sess); err != nil {
		t.Fatalf("StoreSession with empty AccountUUID: %v", err)
	}

	got, err := s.GetSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sessionID {
		t.Fatalf("ID: got %q, want %q", got.ID, sessionID)
	}
}

// TestFIDO2_GetCredential_CorruptedData_UnmarshalError exercises the
// json.Unmarshal error branch in GetCredential (fido2.go:75-77). A row is
// inserted via raw SQL with a data value whose "createdAt" field is an invalid
// time string, causing json.Unmarshal to fail even though the row is found.
func TestFIDO2_GetCredential_CorruptedData_UnmarshalError(t *testing.T) {
	c := newTestClient(t)
	s := NewFIDO2AccountsStore(c.Pool())
	ctx := context.Background()

	credID := uuid.NewString()
	accountUUID := uuid.NewString()

	// Insert valid JSONB with an unparseable "createdAt" value.
	_, err := c.Pool().Exec(ctx,
		`INSERT INTO fido2_credentials (credential_id, account_uuid, data, created_at, updated_at)
		 VALUES ($1, $2, $3::jsonb, NOW(), NOW())`,
		credID,
		accountUUID,
		`{"credentialId":"`+credID+`","createdAt":"NOT-A-TIME"}`,
	)
	if err != nil {
		t.Fatalf("raw insert corrupted credential: %v", err)
	}

	_, err = s.GetCredential(ctx, credID)
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	var nfe *fido2.CredentialNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected unmarshal error, not CredentialNotFoundError")
	}
}
