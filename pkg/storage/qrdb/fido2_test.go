//go:build fido2

package qrdb

// fido2_test.go covers the FIDO2AccountsStore which is only compiled under
// the fido2 build tag. The tests mirror the pattern used throughout the other
// *_test.go files in this package: FakeKVStore for the happy paths and
// faultyKV / faultyListKV for error paths.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// newCred returns a minimal FIDO2Credential fixture.
func newCred(credID, accountUUID string) *fido2.FIDO2Credential {
	return &fido2.FIDO2Credential{
		CredentialID:    credID,
		AccountUUID:     accountUUID,
		Name:            "test-key",
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
		CreatedAt:       time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC),
	}
}

// newSession returns a minimal FIDO2Session fixture.
func newFIDO2Session(id string) *fido2.FIDO2Session {
	return &fido2.FIDO2Session{
		ID:          id,
		AccountUUID: "acc-" + id,
		Challenge:   []byte("challenge"),
		SessionData: []byte("data"),
		Type:        fido2.SessionTypeRegistration,
		CreatedAt:   time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 4, 22, 1, 0, 0, 0, time.UTC),
	}
}

// ─── CreateCredential ─────────────────────────────────────────────────────────

func TestFIDO2_CreateCredential_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	cred := newCred("cred-1", "acc-1")
	if err := s.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
}

func TestFIDO2_CreateCredential_Nil(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	if err := s.CreateCredential(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil credential")
	}
}

func TestFIDO2_CreateCredential_Duplicate_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	if err := s.CreateCredential(ctx, newCred("cred-1", "acc-1")); err != nil {
		t.Fatal(err)
	}
	err := s.CreateCredential(ctx, newCred("cred-1", "acc-2"))
	var cee *fido2.CredentialExistsError
	if !errors.As(err, &cee) {
		t.Fatalf("expected CredentialExistsError, got %T: %v", err, err)
	}
}

func TestFIDO2_CreateCredential_ExistsError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewFIDO2AccountsStore(kv)

	err := s.CreateCredential(context.Background(), newCred("c1", "a1"))
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error, got %v", err)
	}
}

func TestFIDO2_CreateCredential_PutCredError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewFIDO2AccountsStore(kv)

	err := s.CreateCredential(context.Background(), newCred("c1", "a1"))
	if err == nil || !strings.Contains(err.Error(), "put cred") {
		t.Fatalf("expected put-cred error, got %v", err)
	}
}

func TestFIDO2_CreateCredential_PutMirrorError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// First put (cred) succeeds; second put (mirror) fails.
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), putN: 1, putErr: errors.New("put-mirror failure")}
	s := NewFIDO2AccountsStore(kv)

	err := s.CreateCredential(ctx, newCred("c1", "a1"))
	if err == nil || !strings.Contains(err.Error(), "put mirror") {
		t.Fatalf("expected put-mirror error, got %v", err)
	}
}

// ─── GetCredential ────────────────────────────────────────────────────────────

func TestFIDO2_GetCredential_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	if err := s.CreateCredential(ctx, newCred("cred-1", "acc-1")); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCredential(ctx, "cred-1")
	if err != nil || got.CredentialID != "cred-1" {
		t.Fatalf("GetCredential: err=%v got=%+v", err, got)
	}
}

func TestFIDO2_GetCredential_Missing(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	_, err := s.GetCredential(context.Background(), "absent")
	var cnfe *fido2.CredentialNotFoundError
	if !errors.As(err, &cnfe) {
		t.Fatalf("expected CredentialNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_GetCredential_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewFIDO2AccountsStore(kv)

	_, err := s.GetCredential(context.Background(), "c1")
	if err == nil || !strings.Contains(err.Error(), "get cred") {
		t.Fatalf("expected get-cred error, got %v", err)
	}
}

func TestFIDO2_GetCredential_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, credKey("c1"), []byte("not-json"))
	s := NewFIDO2AccountsStore(kv)

	_, err := s.GetCredential(ctx, "c1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal cred") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

// ─── GetCredentialsByAccount ──────────────────────────────────────────────────

func TestFIDO2_GetCredentialsByAccount_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	_ = s.CreateCredential(ctx, newCred("c1", "acc-1"))
	_ = s.CreateCredential(ctx, newCred("c2", "acc-1"))
	_ = s.CreateCredential(ctx, newCred("c3", "acc-2"))

	got, err := s.GetCredentialsByAccount(ctx, "acc-1")
	if err != nil {
		t.Fatalf("GetCredentialsByAccount: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials for acc-1, got %d", len(got))
	}
}

func TestFIDO2_GetCredentialsByAccount_Empty(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	got, err := s.GetCredentialsByAccount(context.Background(), "nobody")
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty slice: err=%v got=%v", err, got)
	}
}

func TestFIDO2_GetCredentialsByAccount_ScanError(t *testing.T) {
	t.Parallel()
	boom := errors.New("scan failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), scanErr: boom}
	s := NewFIDO2AccountsStore(kv)

	_, err := s.GetCredentialsByAccount(context.Background(), "acc-1")
	if err == nil || !strings.Contains(err.Error(), "scan by account") {
		t.Fatalf("expected scan error, got %v", err)
	}
}

// TestFIDO2_GetCredentialsByAccount_StalesMirrorSkipped verifies that a stale
// mirror key pointing to a missing credential is silently skipped.
func TestFIDO2_GetCredentialsByAccount_StaleMirrorSkipped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	s := NewFIDO2AccountsStore(kv)

	// Manually insert a stale mirror entry pointing to a non-existent cred.
	_ = kv.Put(ctx, credByAccountKey("acc-1", "stale-cred"), []byte{})

	got, err := s.GetCredentialsByAccount(ctx, "acc-1")
	if err != nil {
		t.Fatalf("expected stale mirror to be silently skipped, got: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result with stale mirror, got %d", len(got))
	}
}

// ─── UpdateCredential ─────────────────────────────────────────────────────────

func TestFIDO2_UpdateCredential_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	cred := newCred("c1", "acc-1")
	if err := s.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}

	cred.SignCount = 5
	if err := s.UpdateCredential(ctx, cred); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}

	got, _ := s.GetCredential(ctx, "c1")
	if got.SignCount != 5 {
		t.Fatalf("SignCount not updated: %+v", got)
	}
}

func TestFIDO2_UpdateCredential_Nil(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	if err := s.UpdateCredential(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil credential")
	}
}

func TestFIDO2_UpdateCredential_Missing(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	err := s.UpdateCredential(context.Background(), newCred("absent", "acc-1"))
	var cnfe *fido2.CredentialNotFoundError
	if !errors.As(err, &cnfe) {
		t.Fatalf("expected CredentialNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_UpdateCredential_ExistsError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewFIDO2AccountsStore(kv)

	err := s.UpdateCredential(context.Background(), newCred("c1", "a1"))
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error, got %v", err)
	}
}

func TestFIDO2_UpdateCredential_PutError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewFIDO2AccountsStore(plain)
	if err := seedStore.CreateCredential(ctx, newCred("c1", "a1")); err != nil {
		t.Fatal(err)
	}

	kv := &faultyKV{FakeKVStore: plain, putErr: errors.New("put failure")}
	s := NewFIDO2AccountsStore(kv)

	err := s.UpdateCredential(ctx, newCred("c1", "a1"))
	if err == nil || !strings.Contains(err.Error(), "put cred") {
		t.Fatalf("expected put-cred error, got %v", err)
	}
}

// ─── DeleteCredential ─────────────────────────────────────────────────────────

func TestFIDO2_DeleteCredential_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	if err := s.CreateCredential(ctx, newCred("c1", "acc-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCredential(ctx, "c1"); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if _, err := s.GetCredential(ctx, "c1"); err == nil {
		t.Fatal("expected credential to be absent after Delete")
	}
}

func TestFIDO2_DeleteCredential_Missing(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	err := s.DeleteCredential(context.Background(), "absent")
	var cnfe *fido2.CredentialNotFoundError
	if !errors.As(err, &cnfe) {
		t.Fatalf("expected CredentialNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_DeleteCredential_DeleteCredError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewFIDO2AccountsStore(plain)
	if err := seedStore.CreateCredential(ctx, newCred("c1", "a1")); err != nil {
		t.Fatal(err)
	}

	kv := &faultyListKV{FakeKVStore: plain, deleteErr: errors.New("delete failure")}
	s := NewFIDO2AccountsStore(kv)

	err := s.DeleteCredential(ctx, "c1")
	if err == nil || !strings.Contains(err.Error(), "delete cred") {
		t.Fatalf("expected delete-cred error, got %v", err)
	}
}

func TestFIDO2_DeleteCredential_DeleteMirrorError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewFIDO2AccountsStore(plain)
	if err := seedStore.CreateCredential(ctx, newCred("c1", "a1")); err != nil {
		t.Fatal(err)
	}

	// First delete (cred) succeeds; second (mirror) fails.
	kv := &faultyListKV{FakeKVStore: plain, deleteN: 1, deleteErr: errors.New("delete-mirror failure")}
	s := NewFIDO2AccountsStore(kv)

	err := s.DeleteCredential(ctx, "c1")
	if err == nil || !strings.Contains(err.Error(), "delete mirror") {
		t.Fatalf("expected delete-mirror error, got %v", err)
	}
}

// ─── StoreSession ─────────────────────────────────────────────────────────────

func TestFIDO2_StoreSession_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	sess := newFIDO2Session("sess-1")
	if err := s.StoreSession(ctx, sess); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
}

func TestFIDO2_StoreSession_Nil(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	if err := s.StoreSession(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestFIDO2_StoreSession_PutError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewFIDO2AccountsStore(kv)

	err := s.StoreSession(context.Background(), newFIDO2Session("s1"))
	if err == nil || !strings.Contains(err.Error(), "put session") {
		t.Fatalf("expected put-session error, got %v", err)
	}
}

// ─── GetSession ───────────────────────────────────────────────────────────────

func TestFIDO2_GetSession_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	sess := newFIDO2Session("sess-1")
	if err := s.StoreSession(ctx, sess); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetSession(ctx, "sess-1")
	if err != nil || got.ID != "sess-1" {
		t.Fatalf("GetSession: err=%v got=%+v", err, got)
	}
}

func TestFIDO2_GetSession_Missing(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	_, err := s.GetSession(context.Background(), "absent")
	var snfe *fido2.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_GetSession_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewFIDO2AccountsStore(kv)

	_, err := s.GetSession(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "get session") {
		t.Fatalf("expected get-session error, got %v", err)
	}
}

func TestFIDO2_GetSession_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, sessionKey("s1"), []byte("not-json"))
	s := NewFIDO2AccountsStore(kv)

	_, err := s.GetSession(ctx, "s1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal session") {
		t.Fatalf("expected unmarshal-session error, got %v", err)
	}
}

// ─── DeleteSession ────────────────────────────────────────────────────────────

func TestFIDO2_DeleteSession_HappyPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFIDO2AccountsStore(NewFakeKVStore())

	sess := newFIDO2Session("sess-1")
	if err := s.StoreSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "sess-1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.GetSession(ctx, "sess-1"); err == nil {
		t.Fatal("expected session to be absent after Delete")
	}
}

func TestFIDO2_DeleteSession_Missing(t *testing.T) {
	t.Parallel()
	s := NewFIDO2AccountsStore(NewFakeKVStore())
	err := s.DeleteSession(context.Background(), "absent")
	var snfe *fido2.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestFIDO2_DeleteSession_ExistsError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewFIDO2AccountsStore(kv)

	err := s.DeleteSession(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error, got %v", err)
	}
}

func TestFIDO2_DeleteSession_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewFIDO2AccountsStore(plain)
	if err := seedStore.StoreSession(ctx, newFIDO2Session("s1")); err != nil {
		t.Fatal(err)
	}

	kv := &faultyListKV{FakeKVStore: plain, deleteErr: errors.New("delete failure")}
	s := NewFIDO2AccountsStore(kv)

	err := s.DeleteSession(ctx, "s1")
	if err == nil || !strings.Contains(err.Error(), "delete session") {
		t.Fatalf("expected delete-session error, got %v", err)
	}
}

// ─── GetCredentialsByAccount with non-stale cred get error ───────────────────

// TestFIDO2_GetCredentialsByAccount_GetError verifies that a non-NotFound
// backend error from GetCredential inside GetCredentialsByAccount propagates.
func TestFIDO2_GetCredentialsByAccount_GetError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewFIDO2AccountsStore(plain)
	if err := seedStore.CreateCredential(ctx, newCred("c1", "acc-1")); err != nil {
		t.Fatal(err)
	}

	// Arm a get error so GetCredential fails with a non-NotFound error.
	kv := &faultyKV{FakeKVStore: plain, getErr: errors.New("backend error")}
	s := NewFIDO2AccountsStore(kv)

	_, err := s.GetCredentialsByAccount(ctx, "acc-1")
	if err == nil {
		t.Fatal("expected backend error from GetCredentialsByAccount")
	}
}
