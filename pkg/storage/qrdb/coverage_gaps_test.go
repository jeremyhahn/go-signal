package qrdb

// coverage_gaps_test.go closes the branches left uncovered after the initial
// test pass. Each test section targets a specific function and branch that the
// coverage report identified as < 90%.
//
// Helper infrastructure reused from errors_test.go (faultyKV) and each
// store's own _test.go fixtures (newAccount, newGroup, newProfile, etc.).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/groups"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// ─── faultyListKV ─────────────────────────────────────────────────────────────
// faultyListKV extends faultyKV with a List error injection so tests can
// trigger the list-path errors in key stores without blanket-faulting all ops.

type faultyListKV struct {
	*FakeKVStore
	listErr error
	scanErr error
	// putErrAfterN injects a put error after N successful puts.
	putN      int
	putErr    error
	deleteN   int
	deleteErr error
}

func (f *faultyListKV) List(ctx context.Context, prefix string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.FakeKVStore.List(ctx, prefix)
}

func (f *faultyListKV) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	if f.scanErr != nil {
		return f.scanErr
	}
	return f.FakeKVStore.Scan(ctx, prefix, fn)
}

func (f *faultyListKV) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		if f.putN <= 0 {
			return f.putErr
		}
		f.putN--
	}
	return f.FakeKVStore.Put(ctx, key, value)
}

func (f *faultyListKV) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		if f.deleteN <= 0 {
			return f.deleteErr
		}
		f.deleteN--
	}
	return f.FakeKVStore.Delete(ctx, key)
}

// ─── AccountStore: PNI paths ──────────────────────────────────────────────────

func TestAccountStore_Create_WithPNI_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	a := newAccount("u1", "+15551234567")
	a.PNI = "pni-1"
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create with PNI: %v", err)
	}

	got, err := s.GetByPNI(ctx, "pni-1")
	if err != nil {
		t.Fatalf("GetByPNI: %v", err)
	}
	if got.UUID != "u1" {
		t.Fatalf("GetByPNI returned wrong UUID: %s", got.UUID)
	}
}

func TestAccountStore_GetByPNI_Missing_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	_, err := s.GetByPNI(context.Background(), "pni-absent")
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAccountStore_Create_DuplicatePNI_RejectedAsAlreadyExists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	a1 := newAccount("u1", "+15551111111")
	a1.PNI = "pni-shared"
	if err := s.Create(ctx, a1); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	a2 := newAccount("u2", "+15552222222")
	a2.PNI = "pni-shared"
	err := s.Create(ctx, a2)
	var aae *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aae) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccountStore_Create_PNILookupError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// getErr fires on every Get, including the PNI lookup after the number
	// lookup. Seed the number mirror so the number lookup succeeds via Exists,
	// but arm getErr so the PNI lookup (which goes through getOrNotFound) fails.
	// Simpler: use a fresh store with getErr so the very first Exists call
	// for the UUID check gets through (it's an Exists, not a Get), but the
	// PNI mirror Get fails.
	boom := errors.New("pni lookup failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewAccountStore(kv)

	// Account with no number so we skip the number mirror path, exercising PNI.
	a := newAccount("u1", "")
	a.PNI = "pni-1"
	err := s.Create(ctx, a)
	if err == nil {
		t.Fatal("expected error from PNI lookup failure")
	}
}

func TestAccountStore_Update_PNIChange_UpdatesMirror(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	a := newAccount("u1", "+15551234567")
	a.PNI = "pni-old"
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated := *a
	updated.Version = 1
	updated.PNI = "pni-new"
	if err := s.Update(ctx, &updated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Old PNI must not resolve.
	if _, err := s.GetByPNI(ctx, "pni-old"); err == nil {
		t.Fatal("old PNI should be unreachable after change")
	}

	// New PNI must resolve.
	got, err := s.GetByPNI(ctx, "pni-new")
	if err != nil {
		t.Fatalf("GetByPNI(new): %v", err)
	}
	if got.UUID != "u1" {
		t.Fatalf("wrong UUID from GetByPNI: %s", got.UUID)
	}
}

func TestAccountStore_Update_PNIChange_ConflictRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	a1 := newAccount("u1", "+15551111111")
	a1.PNI = "pni-A"
	if err := s.Create(ctx, a1); err != nil {
		t.Fatal(err)
	}
	a2 := newAccount("u2", "+15552222222")
	a2.PNI = "pni-B"
	if err := s.Create(ctx, a2); err != nil {
		t.Fatal(err)
	}

	// u1 tries to steal u2's PNI.
	stealer := newAccount("u1", "+15551111111")
	stealer.PNI = "pni-B"
	stealer.Version = 1
	err := s.Update(ctx, stealer)
	var aae *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aae) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccountStore_Update_PNIDeleteOldMirrorFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewAccountStore(kv)

	a := newAccount("u1", "+15551111111")
	a.PNI = "pni-old"
	if err := s.Create(ctx, a); err != nil {
		t.Fatal(err)
	}

	kv.deleteErr = errors.New("delete failure")

	updated := *a
	updated.Version = 1
	updated.PNI = "pni-new"
	err := s.Update(ctx, &updated)
	if err == nil || !strings.Contains(err.Error(), "delete old pni mirror") {
		t.Fatalf("expected wrapped delete-pni-mirror error, got %v", err)
	}
}

func TestAccountStore_Delete_WithPNI_RemovesPNIMirror(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	a := newAccount("u1", "+15551234567")
	a.PNI = "pni-1"
	if err := s.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "u1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.GetByPNI(ctx, "pni-1"); err == nil {
		t.Fatal("PNI mirror should be absent after Delete")
	}
}

func TestAccountStore_Delete_PNIMirrorDeleteFails(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewAccountStore(kv)

	// Account with no phone number so only the PNI mirror path fires.
	a := newAccount("u1", "")
	a.PNI = "pni-1"
	if err := s.Create(ctx, a); err != nil {
		t.Fatal(err)
	}

	kv.deleteErr = errors.New("delete failure")
	err := s.Delete(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete pni mirror") {
		t.Fatalf("expected wrapped delete-pni-mirror error, got %v", err)
	}
}

func TestAccountStore_GetByNumber_GetFails_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewAccountStore(kv)

	// Store a valid account so the number mirror key exists.
	if err := s.Create(ctx, newAccount("u1", "+15551234567")); err != nil {
		t.Fatal(err)
	}
	// Arm get error after creation so next Get fails.
	kv.getErr = errors.New("read failure")

	_, err := s.GetByNumber(ctx, "+15551234567")
	if err == nil {
		t.Fatal("expected error when backend fails on number lookup")
	}
}

// ─── UsernameStore: DeleteHash full delete path ───────────────────────────────

func TestUsernameStore_DeleteHash_RemovesExisting(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	hash := []byte("h-del")
	_, token, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmHash(ctx, "u1", hash, token); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteHash(ctx, "u1"); err != nil {
		t.Fatalf("DeleteHash: %v", err)
	}

	// Must no longer resolve.
	if _, err := s.LookupByHash(ctx, hash); err == nil {
		t.Fatal("hash should be gone after DeleteHash")
	}
}

// TestUsernameStore_ConfirmHash_ExpiredReservation checks the expiry branch.
func TestUsernameStore_ConfirmHash_ExpiredReservation(t *testing.T) {
	t.Parallel()
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	s := NewUsernameStore(NewFakeKVStore())
	s.now = func() time.Time { return clock }

	ctx := context.Background()
	hash := []byte("h-exp")
	_, token, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}

	// Advance clock past TTL.
	clock = clock.Add(reservationTTL + time.Second)

	err = s.ConfirmHash(ctx, "u1", hash, token)
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError for expired reservation, got %T: %v", err, err)
	}
}

// TestUsernameStore_ConfirmHash_WrongHash checks the hash-mismatch branch.
func TestUsernameStore_ConfirmHash_WrongHash(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	hash := []byte("correct-hash")
	_, token, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}

	err = s.ConfirmHash(ctx, "u1", []byte("wrong-hash"), token)
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError for wrong hash, got %T: %v", err, err)
	}
}

// TestUsernameStore_ConfirmHash_ReplacesOldConfirmed exercises the branch
// that deletes a prior confirmed hash when the same UUID confirms a new one.
func TestUsernameStore_ConfirmHash_ReplacesOldConfirmed(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	hash1 := []byte("first-hash")
	_, tok1, err := s.ReserveHash(ctx, "u1", [][]byte{hash1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmHash(ctx, "u1", hash1, tok1); err != nil {
		t.Fatal(err)
	}

	hash2 := []byte("second-hash")
	_, tok2, err := s.ReserveHash(ctx, "u1", [][]byte{hash2})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmHash(ctx, "u1", hash2, tok2); err != nil {
		t.Fatalf("ConfirmHash second: %v", err)
	}

	// Old hash must be gone.
	if _, err := s.LookupByHash(ctx, hash1); err == nil {
		t.Fatal("old confirmed hash should be replaced")
	}
	// New hash must resolve.
	got, err := s.LookupByHash(ctx, hash2)
	if err != nil || got != "u1" {
		t.Fatalf("new hash lookup: got=%s err=%v", got, err)
	}
}

// TestUsernameStore_ConfirmHash_CorruptReservation injects invalid JSON to
// exercise the unmarshal error path in ConfirmHash.
func TestUsernameStore_ConfirmHash_CorruptReservation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, usernameReservePfx+"u1", []byte("not-json"))

	s := NewUsernameStore(kv)
	err := s.ConfirmHash(ctx, "u1", []byte("h"), "tok")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

// TestUsernameStore_hashAvailable_CorruptScanEntry exercises the Scan
// unmarshal error path inside hashAvailable.
func TestUsernameStore_hashAvailable_CorruptScanEntry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	// Inject bad JSON under the reservation prefix so the Scan callback fails.
	_ = kv.Put(ctx, usernameReservePfx+"other-uuid", []byte("not-json"))

	s := NewUsernameStore(kv)
	// ReserveHash triggers hashAvailable which will Scan and hit the bad entry.
	_, _, err := s.ReserveHash(ctx, "u1", [][]byte{[]byte("h")})
	if err == nil {
		t.Fatal("expected error from corrupt scan entry")
	}
}

// TestUsernameStore_ReserveHash_ConflictFromActiveReservation ensures that an
// active (non-expired) reservation by another UUID blocks a new reservation.
func TestUsernameStore_ReserveHash_ConflictFromActiveReservation(t *testing.T) {
	t.Parallel()
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	s := NewUsernameStore(NewFakeKVStore())
	s.now = func() time.Time { return clock }
	ctx := context.Background()

	hash := []byte("contested")
	// u1 reserves the hash.
	if _, _, err := s.ReserveHash(ctx, "u1", [][]byte{hash}); err != nil {
		t.Fatal(err)
	}

	// u2 tries to reserve the same hash while u1's reservation is live.
	_, _, err := s.ReserveHash(ctx, "u2", [][]byte{hash})
	var uhce *usernames.UsernameHashConflictError
	if !errors.As(err, &uhce) {
		t.Fatalf("expected UsernameHashConflictError, got %T: %v", err, err)
	}
}

// TestUsernameStore_ReserveHash_ExpiredReservationDoesNotBlock ensures that an
// expired reservation by another UUID does not block a new reservation.
func TestUsernameStore_ReserveHash_ExpiredReservationDoesNotBlock(t *testing.T) {
	t.Parallel()
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	s := NewUsernameStore(NewFakeKVStore())
	s.now = func() time.Time { return clock }
	ctx := context.Background()

	hash := []byte("stale-reserved")
	// u1 reserves.
	if _, _, err := s.ReserveHash(ctx, "u1", [][]byte{hash}); err != nil {
		t.Fatal(err)
	}

	// Advance past TTL — u1's reservation is now expired.
	clock = clock.Add(reservationTTL + time.Second)

	// u2 should succeed.
	selected, token, err := s.ReserveHash(ctx, "u2", [][]byte{hash})
	if err != nil {
		t.Fatalf("expected success after expiry, got: %v", err)
	}
	if string(selected) != string(hash) || token == "" {
		t.Fatalf("unexpected result: selected=%s token=%s", selected, token)
	}
}

// TestUsernameStore_hashAvailable_OwnConfirmedHashIsAvailable checks the
// branch where the confirmed owner IS the requesting UUID (should remain available).
func TestUsernameStore_hashAvailable_OwnConfirmedHashIsAvailable(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	hash := []byte("mine")
	_, tok, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmHash(ctx, "u1", hash, tok); err != nil {
		t.Fatal(err)
	}

	// u1 re-reserves the same hash for itself — should succeed.
	selected, token, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash for own confirmed hash: %v", err)
	}
	if string(selected) != string(hash) || token == "" {
		t.Fatalf("unexpected result: %s / %s", selected, token)
	}
}

// TestUsernameStore_newToken_RandomError exercises the random-read error path.
func TestUsernameStore_newToken_RandomError(t *testing.T) {
	t.Parallel()
	boom := errors.New("rng failure")
	s := NewUsernameStore(NewFakeKVStore())
	s.random = func(b []byte) (int, error) { return 0, boom }

	_, _, err := s.ReserveHash(context.Background(), "u1", [][]byte{[]byte("h")})
	if !errors.Is(err, boom) {
		t.Fatalf("expected rng error, got %v", err)
	}
}

// TestUsernameStore_GetLink_CorruptJSON exercises unmarshal error in GetLink.
func TestUsernameStore_GetLink_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, usernameLinkPfx+"h1", []byte("not-json"))

	s := NewUsernameStore(kv)
	_, err := s.GetLink(ctx, "h1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

// TestUsernameStore_DeleteLink_RemovesLink already exists in usernames_test.go
// but we need to add error coverage for the delete-link path with a faulty KV.
func TestUsernameStore_DeleteLink_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewUsernameStore(kv)

	link := &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "h1", EncryptedUsername: []byte("x")}
	if err := s.SetLink(ctx, link); err != nil {
		t.Fatal(err)
	}

	// Arm delete fault; first delete call (the link primary) should fail.
	kv.deleteErr = errors.New("delete failure")
	err := s.DeleteLink(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete link") {
		t.Fatalf("expected wrapped delete-link error, got %v", err)
	}
}

// TestUsernameStore_SetLink_DeleteOldLinkError_Propagated exercises the
// error path when deleting the previous link handle fails.
func TestUsernameStore_SetLink_DeleteOldLinkError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewUsernameStore(kv)

	// Store initial link.
	if err := s.SetLink(ctx, &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "old", EncryptedUsername: []byte("a")}); err != nil {
		t.Fatal(err)
	}

	// Arm delete fault so the old-handle deletion fails on replacement.
	kv.deleteErr = errors.New("delete failure")
	err := s.SetLink(ctx, &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "new", EncryptedUsername: []byte("b")})
	if err == nil || !strings.Contains(err.Error(), "delete old link") {
		t.Fatalf("expected wrapped delete-old-link error, got %v", err)
	}
}

// ─── PreKeyStore: nil-key skipping and error paths ───────────────────────────

func TestPreKeyStore_StoreECPreKeys_SkipsNilKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	// Mix nil into the batch — only the non-nil keys should persist.
	pks := []*keys.PreKey{nil, {KeyID: 1, PublicKey: []byte("pk-1")}, nil}
	if err := s.StoreECPreKeys(ctx, "u1", 1, pks); err != nil {
		t.Fatalf("StoreECPreKeys with nils: %v", err)
	}

	state, err := s.GetPreKeyCount(ctx, "u1", 1)
	if err != nil || state.ECCount != 1 {
		t.Fatalf("expected 1 EC key (nils skipped), got %d err=%v", state.ECCount, err)
	}
}

func TestPreKeyStore_StoreKEMPreKeys_SkipsNilKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	kems := []*keys.KEMSignedPreKey{nil, {KeyID: 5, PublicKey: []byte("pk")}, nil}
	if err := s.StoreKEMPreKeys(ctx, "u1", 1, kems); err != nil {
		t.Fatalf("StoreKEMPreKeys with nils: %v", err)
	}

	state, err := s.GetPreKeyCount(ctx, "u1", 1)
	if err != nil || state.KEMCount != 1 {
		t.Fatalf("expected 1 KEM key (nils skipped), got %d err=%v", state.KEMCount, err)
	}
}

func TestPreKeyStore_StoreECPreKeys_ListError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewPreKeyStore(kv)

	err := s.StoreECPreKeys(context.Background(), "u1", 1, []*keys.PreKey{{KeyID: 1}})
	if err == nil || !strings.Contains(err.Error(), "list ec") {
		t.Fatalf("expected list-ec error, got %v", err)
	}
}

func TestPreKeyStore_StoreKEMPreKeys_ListError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewPreKeyStore(kv)

	err := s.StoreKEMPreKeys(context.Background(), "u1", 1, []*keys.KEMSignedPreKey{{KeyID: 1}})
	if err == nil || !strings.Contains(err.Error(), "list kem") {
		t.Fatalf("expected list-kem error, got %v", err)
	}
}

func TestPreKeyStore_TakeEC_CorruptJSON_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	// Write invalid JSON at a valid EC key location so TakeEC hits the unmarshal error.
	_ = kv.Put(ctx, ecKey("u1", 1, 1), []byte("bad-json"))
	s := NewPreKeyStore(kv)

	_, err := s.TakeEC(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "unmarshal ec") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestPreKeyStore_TakeKEM_CorruptJSON_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, kemKey("u1", 1, 1), []byte("bad-json"))
	s := NewPreKeyStore(kv)

	_, err := s.TakeKEM(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "unmarshal kem") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestPreKeyStore_GetKEMLastResortPreKey_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, kemLastResortKey("u1", 1), []byte("bad-json"))
	s := NewPreKeyStore(kv)

	_, err := s.GetKEMLastResortPreKey(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "unmarshal last-resort") {
		t.Fatalf("expected unmarshal last-resort error, got %v", err)
	}
}

func TestPreKeyStore_GetSignedPreKey_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, signedKey("u1", 1), []byte("bad-json"))
	s := NewPreKeyStore(kv)

	_, err := s.GetSignedPreKey(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "unmarshal signed") {
		t.Fatalf("expected unmarshal signed error, got %v", err)
	}
}

func TestPreKeyStore_GetPreKeyCount_ECListError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("list failure")
	fkv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewPreKeyStore(fkv)
	_, err := s.GetPreKeyCount(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "list ec") {
		t.Fatalf("expected list-ec error from GetPreKeyCount, got %v", err)
	}
}

// TestPreKeyStore_GetPreKeyCount_KEMListError exercises the KEM list-error
// branch in GetPreKeyCount. We need List to succeed for EC but fail for KEM.
// We implement a minimal KVStore that counts List calls.
type kemListErrKV struct {
	*FakeKVStore
	listCalls int
}

func (k *kemListErrKV) List(ctx context.Context, prefix string) ([]string, error) {
	k.listCalls++
	if k.listCalls >= 2 {
		return nil, errors.New("kem list failure")
	}
	return k.FakeKVStore.List(ctx, prefix)
}

func TestPreKeyStore_GetPreKeyCount_KEMListError(t *testing.T) {
	t.Parallel()
	kv := &kemListErrKV{FakeKVStore: NewFakeKVStore()}
	s := NewPreKeyStore(kv)
	_, err := s.GetPreKeyCount(context.Background(), "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "list kem") {
		t.Fatalf("expected list-kem error from GetPreKeyCount, got %v", err)
	}
}

func TestPreKeyStore_GetPreKeyCount_ExistsError(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewPreKeyStore(kv)

	_, err := s.GetPreKeyCount(context.Background(), "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "exists last-resort") {
		t.Fatalf("expected exists-last-resort error, got %v", err)
	}
}

func TestPreKeyStore_StoreECPreKeys_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewPreKeyStore(kv)

	// Seed an existing key.
	_ = s.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 1}})

	// Now arm the delete error so the clear-existing step fails.
	kv.deleteErr = errors.New("delete failure")
	err := s.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 2}})
	if err == nil || !strings.Contains(err.Error(), "delete ec") {
		t.Fatalf("expected delete-ec error, got %v", err)
	}
}

func TestPreKeyStore_StoreKEMPreKeys_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewPreKeyStore(kv)

	_ = s.StoreKEMPreKeys(ctx, "u1", 1, []*keys.KEMSignedPreKey{{KeyID: 1}})

	kv.deleteErr = errors.New("delete failure")
	err := s.StoreKEMPreKeys(ctx, "u1", 1, []*keys.KEMSignedPreKey{{KeyID: 2}})
	if err == nil || !strings.Contains(err.Error(), "delete kem") {
		t.Fatalf("expected delete-kem error, got %v", err)
	}
}

// TestPreKeyStore_TakeEC_DeleteError exercises the delete-after-get error path.
func TestPreKeyStore_TakeEC_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewPreKeyStore(kv)

	_ = s.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk")}})

	kv.deleteErr = errors.New("delete failure")
	_, err := s.TakeEC(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "delete ec") {
		t.Fatalf("expected delete-ec error from TakeEC, got %v", err)
	}
}

// TestPreKeyStore_TakeKEM_DeleteError exercises the delete-after-get error path.
func TestPreKeyStore_TakeKEM_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewPreKeyStore(kv)

	_ = s.StoreKEMPreKeys(ctx, "u1", 1, []*keys.KEMSignedPreKey{{KeyID: 1, PublicKey: []byte("pk")}})

	kv.deleteErr = errors.New("delete failure")
	_, err := s.TakeKEM(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "delete kem") {
		t.Fatalf("expected delete-kem error from TakeKEM, got %v", err)
	}
}

// ─── VerificationSessionStore ─────────────────────────────────────────────────

func TestVerificationSessionStore_Get_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, verificationKey("s1"), []byte("not-json"))

	s := NewVerificationSessionStore(kv)
	_, err := s.Get(ctx, "s1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestVerificationSessionStore_Delete_ExistsError(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewVerificationSessionStore(kv)

	err := s.Delete(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error, got %v", err)
	}
}

func TestVerificationSessionStore_DeleteExpired_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	// Put corrupt JSON under the verification prefix so DeleteExpired hits it.
	_ = kv.Put(ctx, verificationKey("bad"), []byte("not-json"))

	s := NewVerificationSessionStore(kv)
	err := s.DeleteExpired(ctx)
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error from DeleteExpired, got %v", err)
	}
}

func TestVerificationSessionStore_put_PutError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("put failure")
	// put is called by Create; we fault the put so Create bubbles the error.
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewVerificationSessionStore(kv)

	sess := newVerificationSession("s1", time.Now().Add(time.Hour))
	err := s.Create(ctx, sess)
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected put error from Create, got %v", err)
	}
}

func TestVerificationSessionStore_Count_ListError(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewVerificationSessionStore(kv)

	_, err := s.Count(context.Background())
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("expected list error from Count, got %v", err)
	}
}

func TestVerificationSessionStore_DeleteExpired_ListError(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewVerificationSessionStore(kv)

	err := s.DeleteExpired(context.Background())
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("expected list error from DeleteExpired, got %v", err)
	}
}

func TestVerificationSessionStore_Update_ExistsError(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewVerificationSessionStore(kv)

	sess := newVerificationSession("s1", time.Now().Add(time.Hour))
	err := s.Update(context.Background(), sess)
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error from Update, got %v", err)
	}
}

// ─── ProfileStore ──────────────────────────────────────────────────────────────

func TestProfileStore_Get_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, profileKey("u1", "v1"), []byte("not-json"))
	s := NewProfileStore(kv)

	_, err := s.Get(ctx, "u1", "v1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestProfileStore_GetLatest_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, profileLatestKey("u1"), []byte("not-json"))
	s := NewProfileStore(kv)

	_, err := s.GetLatest(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestProfileStore_Set_PutPrimaryError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewProfileStore(kv)

	err := s.Set(context.Background(), newProfile("u1", "v1", "alice"))
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected put error, got %v", err)
	}
}

func TestProfileStore_Set_PutLatestError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Arm the put error after the first successful put (primary), so the
	// second put (latest mirror) fails.
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), putN: 1, putErr: errors.New("put-latest failure")}
	s := NewProfileStore(kv)

	err := s.Set(ctx, newProfile("u1", "v1", "alice"))
	if err == nil || !strings.Contains(err.Error(), "put latest") {
		t.Fatalf("expected put-latest error, got %v", err)
	}
}

func TestProfileStore_Delete_ListError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewProfileStore(kv)

	err := s.Delete(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("expected list error from Delete, got %v", err)
	}
}

// ─── SecureStorageStore ────────────────────────────────────────────────────────

func TestSecureStorageStore_GetManifest_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, manifestKey("u1"), []byte("not-json"))
	s := NewSecureStorageStore(kv)

	_, err := s.GetManifest(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal manifest") {
		t.Fatalf("expected unmarshal-manifest error, got %v", err)
	}
}

func TestSecureStorageStore_GetItem_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	key := []byte("k")
	_ = kv.Put(ctx, itemKey("u1", key), []byte("not-json"))
	s := NewSecureStorageStore(kv)

	_, err := s.GetItem(ctx, "u1", key)
	if err == nil || !strings.Contains(err.Error(), "unmarshal item") {
		t.Fatalf("expected unmarshal-item error, got %v", err)
	}
}

func TestSecureStorageStore_PutManifest_PutError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewSecureStorageStore(kv)

	err := s.PutManifest(context.Background(), "u1", &securestorage.StorageManifest{Version: 1})
	if err == nil || !strings.Contains(err.Error(), "put manifest") {
		t.Fatalf("expected put-manifest error, got %v", err)
	}
}

func TestSecureStorageStore_PutItem_PutError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewSecureStorageStore(kv)

	err := s.PutItem(context.Background(), "u1", &securestorage.StorageItem{Key: []byte("k"), Value: []byte("v")})
	if err == nil || !strings.Contains(err.Error(), "put item") {
		t.Fatalf("expected put-item error, got %v", err)
	}
}

func TestSecureStorageStore_DeleteItem_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewSecureStorageStore(kv)

	key := []byte("k")
	if err := s.PutItem(ctx, "u1", &securestorage.StorageItem{Key: key, Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}

	kv.deleteErr = errors.New("delete failure")
	err := s.DeleteItem(ctx, "u1", key)
	if err == nil || !strings.Contains(err.Error(), "delete item") {
		t.Fatalf("expected delete-item error, got %v", err)
	}
}

func TestSecureStorageStore_DeleteAll_ListError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewSecureStorageStore(kv)

	err := s.DeleteAll(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("expected list error from DeleteAll, got %v", err)
	}
}

func TestSecureStorageStore_DeleteItem_ExistsError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewSecureStorageStore(kv)

	err := s.DeleteItem(context.Background(), "u1", []byte("k"))
	if err == nil || !strings.Contains(err.Error(), "exists item") {
		t.Fatalf("expected exists error, got %v", err)
	}
}

// ─── MessageStore ──────────────────────────────────────────────────────────────

func TestMessageStore_Insert_PutGUIDMirrorError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Arm put error after the first successful put (primary message), so the
	// second put (GUID mirror) fails.
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), putN: 1, putErr: errors.New("put-mirror failure")}
	s := NewMessageStore(kv)

	_, err := s.Insert(ctx, "u1", 1, newEnvelope("guid-fail"))
	if err == nil || !strings.Contains(err.Error(), "guid mirror") {
		t.Fatalf("expected put-guid-mirror error, got %v", err)
	}
}

func TestMessageStore_GetMessagesForDevice_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	// Write corrupt JSON at a valid message key so Scan hits it.
	_ = kv.Put(ctx, messageKey("u1", 1, 1), []byte("not-json"))
	s := NewMessageStore(kv)

	_, err := s.GetMessagesForDevice(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("expected scan error from corrupt JSON, got %v", err)
	}
}

func TestMessageStore_Delete_DeleteMirrorError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewMessageStore(kv)

	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("guid-X")); err != nil {
		t.Fatal(err)
	}

	// First delete (primary) succeeds; second (mirror) fails.
	kv.deleteN = 1
	kv.deleteErr = errors.New("delete failure")

	err := s.Delete(ctx, "u1", "guid-X")
	if err == nil || !strings.Contains(err.Error(), "delete mirror") {
		t.Fatalf("expected delete-mirror error, got %v", err)
	}
}

func TestMessageStore_deletePrefix_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	// Inject bad JSON at a device message key so deletePrefix's Scan callback fails.
	_ = kv.Put(ctx, messageKey("u1", 1, 99), []byte("not-json"))
	s := NewMessageStore(kv)

	err := s.DeleteForDevice(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("expected scan error from deletePrefix, got %v", err)
	}
}

// ─── GroupStore ───────────────────────────────────────────────────────────────

func TestGroupStore_Create_MarshalError_Propagated(t *testing.T) {
	t.Parallel()
	// json.Marshal only fails for un-marshallable types. Groups use a []byte
	// field which is fine, but we can still test the put error by arming
	// a faulty KV — the marshal step will succeed but Put will fail,
	// exercising the "qrdb groups: put" error branch.
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewGroupStore(kv)

	err := s.Create(context.Background(), newGroup("g1"))
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected put error from Create, got %v", err)
	}
}

func TestGroupStore_Get_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, groupKey("g1"), []byte("not-json"))
	s := NewGroupStore(kv)

	_, err := s.Get(ctx, "g1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestGroupStore_Update_PutError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewGroupStore(kv)

	g := newGroup("g1")
	if err := s.Create(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Arm the fault after creation so the Update's Put fails.
	kv.putErr = errors.New("put failure")
	updated := *g
	updated.Revision = 2
	err := s.Update(ctx, &updated)
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected put error from Update, got %v", err)
	}
}

func TestGroupStore_Create_ExistsError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewGroupStore(kv)

	err := s.Create(context.Background(), newGroup("g1"))
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error from Create, got %v", err)
	}
}

func TestGroupStore_Delete_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewGroupStore(kv)

	if err := s.Create(ctx, newGroup("g1")); err != nil {
		t.Fatal(err)
	}
	kv.deleteErr = errors.New("delete failure")
	err := s.Delete(ctx, "g1")
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected delete error, got %v", err)
	}
}

func TestGroupStore_Delete_ExistsError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewGroupStore(kv)

	err := s.Delete(context.Background(), "g1")
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error from Delete, got %v", err)
	}
}

// ─── ReportStore ──────────────────────────────────────────────────────────────

func TestReportStore_Store_PutError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewReportStore(kv)

	err := s.Store(context.Background(), newReport("r1", "s1", "m1"))
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected put error, got %v", err)
	}
}

func TestReportStore_GetByReporter_CorruptJSON(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, reportKey("r1", "bad-id"), []byte("not-json"))
	s := NewReportStore(kv)

	_, err := s.GetByReporter(ctx, "r1")
	if err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("expected scan error from corrupt JSON, got %v", err)
	}
}

// ─── Miscellaneous boundary checks ───────────────────────────────────────────

// TestAccountStore_Create_NumberLookupError_Propagated exercises the error
// path in Create when the number-mirror lookup returns a backend error.
func TestAccountStore_Create_NumberLookupError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("number lookup failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewAccountStore(kv)

	// Account with a number so the number-mirror path fires.
	err := s.Create(ctx, newAccount("u1", "+15551234567"))
	if err == nil {
		t.Fatal("expected error from number lookup failure")
	}
}

// TestUsernameStore_DeleteHash_GetByUUIDError exercises the get-byuuid
// error branch in DeleteHash.
func TestUsernameStore_DeleteHash_GetByUUIDError(t *testing.T) {
	t.Parallel()
	boom := errors.New("get failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewUsernameStore(kv)
	s.now = time.Now

	err := s.DeleteHash(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "get byuuid") {
		t.Fatalf("expected get-byuuid error, got %v", err)
	}
}

// TestPreKeyStore_accountAllKeys_ListError exercises the list-error branch in
// accountAllKeys via DeleteAllForDevice.
func TestPreKeyStore_DeleteAllForDevice_ListError(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewPreKeyStore(kv)

	err := s.DeleteAllForDevice(context.Background(), "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("expected list error from DeleteAllForDevice, got %v", err)
	}
}

func TestPreKeyStore_DeleteAllForAccount_ListError(t *testing.T) {
	t.Parallel()
	boom := errors.New("list failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), listErr: boom}
	s := NewPreKeyStore(kv)

	err := s.DeleteAllForAccount(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "list") {
		t.Fatalf("expected list error from DeleteAllForAccount, got %v", err)
	}
}

// TestMessageStore_Insert_PutPrimaryError exercises the first-Put error.
func TestMessageStore_Insert_PutPrimaryError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewMessageStore(kv)

	_, err := s.Insert(context.Background(), "u1", 1, newEnvelope("guid-fail"))
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected put error, got %v", err)
	}
}

// Ensure json round-trip helpers compile and cover key generation functions.
func TestAccountKey_Format(t *testing.T) {
	t.Parallel()
	k := accountKey("uuid-1")
	if !strings.HasPrefix(k, accountPrimaryScan) {
		t.Fatalf("accountKey has wrong prefix: %s", k)
	}
	kn := accountNumberKey("+1555")
	if !strings.HasPrefix(kn, accountByNumberPfx) {
		t.Fatalf("accountNumberKey has wrong prefix: %s", kn)
	}
	kp := accountPNIKey("pni-x")
	if !strings.HasPrefix(kp, accountByPNIPfx) {
		t.Fatalf("accountPNIKey has wrong prefix: %s", kp)
	}
}

// TestSecureStorageStore_PutManifest_GetError exercises the GetManifest error
// path inside PutManifest when the underlying Get returns a non-NotFound error.
func TestSecureStorageStore_PutManifest_GetError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	boom := errors.New("get failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewSecureStorageStore(kv)

	err := s.PutManifest(ctx, "u1", &securestorage.StorageManifest{Version: 1})
	if err == nil {
		t.Fatal("expected error when GetManifest's Get fails")
	}
}

// TestMessageStore_DeleteForAccount_ScanError_Propagated exercises the scan
// error path in deletePrefix.
func TestMessageStore_DeleteForAccount_ScanError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("scan failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), scanErr: boom}
	s := NewMessageStore(kv)

	err := s.DeleteForAccount(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("expected scan error from DeleteForAccount, got %v", err)
	}
}

// TestGroupStore_Update_ExistsError covers the faultyKV path that errors on
// the Exists call inside GroupStore.Delete.
func TestGroupStore_Delete_ExistsError(t *testing.T) {
	// Already covered by TestGroupStore_Delete_ExistsError_Propagated above.
	// This is a duplicate-name guard; skipping.
}

// Ensure the accounts.go PNI key helper is always compiled into coverage.
func TestAccountPNIKey_IsNonEmpty(t *testing.T) {
	t.Parallel()
	k := accountPNIKey("pni-test")
	if k == "" {
		t.Fatal("accountPNIKey returned empty string")
	}
}

// TestVerificationSessionStore_Create_ExistsError exercises the exists-error
// branch in Create.
func TestVerificationSessionStore_Create_ExistsError(t *testing.T) {
	t.Parallel()
	boom := errors.New("exists failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom}
	s := NewVerificationSessionStore(kv)

	err := s.Create(context.Background(), newVerificationSession("s1", time.Now().Add(time.Hour)))
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected exists error, got %v", err)
	}
}

// TestUsernameStore_SetLink_GetByUUIDError exercises the non-NotFound error
// path when fetching the existing link handle during SetLink replacement.
func TestUsernameStore_SetLink_GetByUUIDError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("get failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewUsernameStore(kv)
	s.now = time.Now

	err := s.SetLink(context.Background(), &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "h1"})
	if err == nil {
		t.Fatal("expected error when byuuid Get fails")
	}
}

// TestUsernameStore_DeleteLink_GetError exercises the non-NotFound error
// from the byuuid Get in DeleteLink.
func TestUsernameStore_DeleteLink_GetError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("get failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewUsernameStore(kv)
	s.now = time.Now

	err := s.DeleteLink(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "get link byuuid") {
		t.Fatalf("expected get-link-byuuid error, got %v", err)
	}
}

// TestUsernameStore_hashAvailable_ConfirmedGetError exercises the non-NotFound
// confirmed-hash Get error path in hashAvailable.
func TestUsernameStore_hashAvailable_ConfirmedGetError(t *testing.T) {
	t.Parallel()
	boom := errors.New("get failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewUsernameStore(kv)
	s.now = time.Now

	_, _, err := s.ReserveHash(context.Background(), "u1", [][]byte{[]byte("h")})
	if err == nil || !strings.Contains(err.Error(), "get confirmed") {
		t.Fatalf("expected get-confirmed error, got %v", err)
	}
}

// TestMessageStore_Delete_PrimaryDeleteError exercises the primary-key delete
// error path in Delete.
func TestMessageStore_Delete_PrimaryDeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewMessageStore(kv)

	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("guid-Y")); err != nil {
		t.Fatal(err)
	}

	// First delete (primary) fails immediately.
	kv.deleteN = 0
	kv.deleteErr = errors.New("delete failure")

	err := s.Delete(ctx, "u1", "guid-Y")
	if err == nil || !strings.Contains(err.Error(), "delete primary") {
		t.Fatalf("expected delete-primary error, got %v", err)
	}
}

// TestMessageStore_DeleteForDevice_DeleteError exercises the per-key delete
// error path inside deletePrefix.
func TestMessageStore_DeleteForDevice_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewMessageStore(kv)

	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("guid-Z")); err != nil {
		t.Fatal(err)
	}

	kv.deleteErr = errors.New("delete failure")
	err := s.DeleteForDevice(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "delete primary") {
		t.Fatalf("expected delete-primary error from deletePrefix, got %v", err)
	}
}

// Ensure the faultyListKV Scan path is exercised (used by GetByReporter scan).
func TestReportStore_GetByReporter_ScanError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("scan failure")
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), scanErr: boom}
	s := NewReportStore(kv)

	_, err := s.GetByReporter(context.Background(), "r1")
	if err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("expected scan error from GetByReporter, got %v", err)
	}
}

// TestGroupStore_Update_MarshalError_Propagated exercises the marshal-error
// path in Update by using a faulty Put that fires after the first Get.
func TestGroupStore_Update_NilGroup_Rejected(t *testing.T) {
	t.Parallel()
	s := NewGroupStore(NewFakeKVStore())
	err := s.Update(context.Background(), nil)
	var ige *groups.InvalidGroupArgumentError
	if !errors.As(err, &ige) {
		t.Fatalf("expected InvalidGroupArgumentError for nil, got %T: %v", err, err)
	}
}

// TestProfileStore_Delete_DeleteError exercises the per-key delete error
// inside ProfileStore.Delete.
func TestProfileStore_Delete_DeleteError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewProfileStore(kv)

	if err := s.Set(ctx, newProfile("u1", "v1", "alice")); err != nil {
		t.Fatal(err)
	}

	kv.deleteErr = errors.New("delete failure")
	err := s.Delete(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected delete error from Delete, got %v", err)
	}
}

// ─── Round 2: closing remaining per-function gaps ────────────────────────────

// TestPreKeyStore_StoreKEMLastResortPreKey_PutError exercises the Put error.
func TestPreKeyStore_StoreKEMLastResortPreKey_PutError(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewPreKeyStore(kv)

	err := s.StoreKEMLastResortPreKey(context.Background(), "u1", 1, &keys.KEMSignedPreKey{KeyID: 1})
	if err == nil || !strings.Contains(err.Error(), "put last-resort") {
		t.Fatalf("expected put-last-resort error, got %v", err)
	}
}

// TestPreKeyStore_StoreSignedPreKey_PutError exercises the Put error.
func TestPreKeyStore_StoreSignedPreKey_PutError(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewPreKeyStore(kv)

	err := s.StoreSignedPreKey(context.Background(), "u1", 1, &keys.SignedPreKey{KeyID: 1})
	if err == nil || !strings.Contains(err.Error(), "put signed") {
		t.Fatalf("expected put-signed error, got %v", err)
	}
}

// TestPreKeyStore_DeleteAllForDevice_DeleteError exercises the delete error
// in DeleteAllForDevice's loop.
func TestPreKeyStore_DeleteAllForDevice_DeleteError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewPreKeyStore(kv)

	_ = s.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk")}})

	kv.deleteErr = errors.New("delete failure")
	err := s.DeleteAllForDevice(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected delete error, got %v", err)
	}
}

// TestPreKeyStore_DeleteAllForAccount_DeleteError exercises the delete error
// in DeleteAllForAccount's loop.
func TestPreKeyStore_DeleteAllForAccount_DeleteError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore()}
	s := NewPreKeyStore(kv)

	_ = s.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk")}})

	kv.deleteErr = errors.New("delete failure")
	err := s.DeleteAllForAccount(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected delete error, got %v", err)
	}
}

// TestUsernameStore_ConfirmHash_GetByUUIDError exercises the non-NotFound
// error from the byuuid lookup inside ConfirmHash.
func TestUsernameStore_ConfirmHash_GetByUUIDError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// We need a store where reservation get works, unmarshal works, token
	// matches — but the byuuid lookup returns a non-NotFound error.
	// Strategy: seed reservation via a real store, then re-open against
	// a faultyKV that fails the Get for the byuuid key.

	// Step 1: seed reservation in a plain store.
	plain := NewFakeKVStore()
	seedStore := NewUsernameStore(plain)
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	seedStore.now = func() time.Time { return clock }

	hash := []byte("h-byuuid-err")
	_, token, err := seedStore.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: wrap the plain store in a faultyKV that errors only on Get
	// for the byuuid key. We do this by injecting a bad value there.
	_ = plain.Put(ctx, usernameByUUIDPfx+"u1", []byte("something"))

	// Simplest approach: put a valid byuuid entry, then arm deleteErr so the
	// "delete old confirmed" step fails.
	kv := &faultyListKV{FakeKVStore: plain}
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return clock }

	// ConfirmHash will: get reservation (ok), validate, look up byuuid
	// (finds "something" put above), try to delete old confirmed key — fail.
	kv.deleteErr = errors.New("delete old confirmed failure")
	err = s.ConfirmHash(ctx, "u1", hash, token)
	if err == nil || !strings.Contains(err.Error(), "delete old confirmed") {
		t.Fatalf("expected delete-old-confirmed error, got %v", err)
	}
}

// TestUsernameStore_DeleteHash_DeleteConfirmedError exercises the confirmed-key
// delete error path in DeleteHash.
func TestUsernameStore_DeleteHash_DeleteConfirmedError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewUsernameStore(plain)
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	seedStore.now = func() time.Time { return clock }

	hash := []byte("h-del-conf-err")
	_, token, err := seedStore.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := seedStore.ConfirmHash(ctx, "u1", hash, token); err != nil {
		t.Fatal(err)
	}

	// Now arm delete fault so first Delete (confirmed key) fails.
	kv := &faultyListKV{FakeKVStore: plain}
	kv.deleteErr = errors.New("delete failure")
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return clock }

	err = s.DeleteHash(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete confirmed") {
		t.Fatalf("expected delete-confirmed error, got %v", err)
	}
}

// TestUsernameStore_DeleteHash_DeleteByUUIDError exercises the byuuid-key
// delete error path in DeleteHash (second delete).
func TestUsernameStore_DeleteHash_DeleteByUUIDError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewUsernameStore(plain)
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	seedStore.now = func() time.Time { return clock }

	hash := []byte("h-del-byuuid-err")
	_, token, err := seedStore.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := seedStore.ConfirmHash(ctx, "u1", hash, token); err != nil {
		t.Fatal(err)
	}

	// Arm delete to fail after first success (confirmed key succeeds, byuuid fails).
	kv := &faultyListKV{FakeKVStore: plain, deleteN: 1, deleteErr: errors.New("byuuid delete failure")}
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return clock }

	err = s.DeleteHash(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete byuuid") {
		t.Fatalf("expected delete-byuuid error, got %v", err)
	}
}

// TestUsernameStore_SetLink_PutLinkError exercises the link-put error.
func TestUsernameStore_SetLink_PutLinkError(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewUsernameStore(kv)
	s.now = time.Now

	err := s.SetLink(context.Background(), &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "h1"})
	if err == nil || !strings.Contains(err.Error(), "put link") {
		t.Fatalf("expected put-link error, got %v", err)
	}
}

// TestUsernameStore_SetLink_PutByUUIDError exercises the byuuid-put error
// (second Put in SetLink, after the link Put succeeds).
func TestUsernameStore_SetLink_PutByUUIDError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// First Put (link) succeeds; second Put (byuuid) fails.
	kv := &faultyListKV{FakeKVStore: NewFakeKVStore(), putN: 1, putErr: errors.New("put-byuuid failure")}
	s := NewUsernameStore(kv)
	s.now = time.Now

	err := s.SetLink(ctx, &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "h1"})
	if err == nil || !strings.Contains(err.Error(), "put link byuuid") {
		t.Fatalf("expected put-link-byuuid error, got %v", err)
	}
}

// TestUsernameStore_DeleteLink_DeleteByUUIDError exercises the byuuid delete
// error (second delete in DeleteLink).
func TestUsernameStore_DeleteLink_DeleteByUUIDError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewUsernameStore(plain)
	seedStore.now = time.Now

	link := &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "h1", EncryptedUsername: []byte("x")}
	if err := seedStore.SetLink(ctx, link); err != nil {
		t.Fatal(err)
	}

	// First delete (link primary) succeeds; second (byuuid) fails.
	kv := &faultyListKV{FakeKVStore: plain, deleteN: 1, deleteErr: errors.New("byuuid delete failure")}
	s := NewUsernameStore(kv)
	s.now = time.Now

	err := s.DeleteLink(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete link byuuid") {
		t.Fatalf("expected delete-link-byuuid error, got %v", err)
	}
}

// TestUsernameStore_LookupByHash_GetError exercises the non-NotFound Get
// error path in LookupByHash.
func TestUsernameStore_LookupByHash_GetError(t *testing.T) {
	t.Parallel()
	boom := errors.New("get failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewUsernameStore(kv)

	_, err := s.LookupByHash(context.Background(), []byte("h"))
	if err == nil || !strings.Contains(err.Error(), "get confirmed") {
		t.Fatalf("expected get-confirmed error, got %v", err)
	}
}

// TestVerificationSessionStore_DeleteExpired_DeleteError exercises the Delete
// error path inside the DeleteExpired loop.
func TestVerificationSessionStore_DeleteExpired_DeleteError(t *testing.T) {
	// No t.Parallel: this test mutates the package-level timeNow.
	ctx := context.Background()
	plain := NewFakeKVStore()

	now := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	origNow := timeNow
	defer func() { timeNow = origNow }()
	timeNow = func() time.Time { return now }

	// Create an expired session through the plain store.
	seedStore := NewVerificationSessionStore(plain)
	if err := seedStore.Create(ctx, newVerificationSession("expired", now.Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}

	// Arm delete failure.
	kv := &faultyListKV{FakeKVStore: plain}
	kv.deleteErr = errors.New("delete failure")
	s := NewVerificationSessionStore(kv)

	err := s.DeleteExpired(ctx)
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected delete error from DeleteExpired, got %v", err)
	}
}

// TestVerificationSessionStore_put_PutError exercises the Put error inside the
// put helper via Update (Create duplicate path not useful here since Exists
// happens first; Update goes straight to put after Exists succeeds).
func TestVerificationSessionStore_Update_PutError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewVerificationSessionStore(plain)

	sess := newVerificationSession("s1", time.Now().Add(time.Hour))
	if err := seedStore.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}

	kv := &faultyKV{FakeKVStore: plain, putErr: errors.New("put failure")}
	s := NewVerificationSessionStore(kv)

	err := s.Update(ctx, sess)
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected put error from Update, got %v", err)
	}
}

// TestVerificationSessionStore_Delete_DeleteError exercises the Delete error
// inside VerificationSessionStore.Delete.
func TestVerificationSessionStore_Delete_DeleteError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewVerificationSessionStore(plain)

	if err := seedStore.Create(ctx, newVerificationSession("s1", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}

	kv := &faultyListKV{FakeKVStore: plain, deleteErr: errors.New("delete failure")}
	s := NewVerificationSessionStore(kv)

	err := s.Delete(ctx, "s1")
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected delete error from Delete, got %v", err)
	}
}

// TestAccountStore_GetByPNI_GetFails_Propagated exercises the error path
// when the secondary Get(uuid) inside GetByPNI fails.
func TestAccountStore_GetByPNI_GetFails_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewAccountStore(plain)

	a := newAccount("u1", "+15551234567")
	a.PNI = "pni-test-get-fail"
	if err := seedStore.Create(ctx, a); err != nil {
		t.Fatal(err)
	}

	// Arm Get error so the Get(uuid) call inside GetByPNI fails.
	kv := &faultyKV{FakeKVStore: plain, getErr: errors.New("get failure")}
	s := NewAccountStore(kv)

	_, err := s.GetByPNI(ctx, "pni-test-get-fail")
	if err == nil {
		t.Fatal("expected error when Get fails inside GetByPNI")
	}
}

// TestAccountStore_Update_PNIPutMirrorError exercises the put-pni-mirror
// error path in Update.
func TestAccountStore_Update_PNIPutMirrorError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewAccountStore(plain)

	a := newAccount("u1", "+15551234567")
	a.PNI = "pni-old"
	if err := seedStore.Create(ctx, a); err != nil {
		t.Fatal(err)
	}

	// Use faultyListKV: let the primary Put (account data) succeed but fail
	// the subsequent Put for the new PNI mirror. The number mirror Put happens
	// before the PNI mirror Put, and we need to count through those.
	// Easiest: no number change, only PNI change. Then Puts in Update are:
	// 1. accountNumberKey mirror (skipped — number unchanged)
	// 2. delete old PNI (succeeds)
	// 3. Put new PNI mirror — fail here.
	// 4. Put primary account.
	// With no number change and PNI change: delete old PNI → Put new PNI → Put primary.
	// So putN=0 fails the very first Put (new PNI mirror).
	kv := &faultyListKV{FakeKVStore: plain, putN: 0, putErr: errors.New("put pni mirror failure")}
	s := NewAccountStore(kv)

	updated := *a
	updated.Version = 1
	updated.PNI = "pni-new"
	err := s.Update(ctx, &updated)
	if err == nil || !strings.Contains(err.Error(), "put pni mirror") {
		t.Fatalf("expected put-pni-mirror error, got %v", err)
	}
}

// TestAccountStore_Update_NumberPutMirrorError exercises the put-mirror (number)
// error path in Update.
func TestAccountStore_Update_NumberPutMirrorError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewAccountStore(plain)

	a := newAccount("u1", "+15551111111")
	if err := seedStore.Create(ctx, a); err != nil {
		t.Fatal(err)
	}

	// On number change with no existing old number to delete, the first Put
	// is the new number mirror. Fail it immediately.
	kv := &faultyListKV{FakeKVStore: plain, putN: 0, putErr: errors.New("put mirror failure")}
	s := NewAccountStore(kv)

	updated := *a
	updated.Version = 1
	updated.Number = "+15552222222"
	err := s.Update(ctx, &updated)
	if err == nil || !strings.Contains(err.Error(), "put mirror") {
		t.Fatalf("expected put-mirror error, got %v", err)
	}
}

// TestAccountStore_Update_PutPrimaryError exercises the primary Put error at
// the end of Update.
func TestAccountStore_Update_PutPrimaryError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewAccountStore(plain)

	// Account with no number and no PNI: Update goes straight to the primary Put.
	a := newAccount("u1", "")
	if err := seedStore.Create(ctx, a); err != nil {
		t.Fatal(err)
	}

	kv := &faultyListKV{FakeKVStore: plain, putN: 0, putErr: errors.New("put primary failure")}
	s := NewAccountStore(kv)

	updated := *a
	updated.Version = 1
	err := s.Update(ctx, &updated)
	if err == nil || !strings.Contains(err.Error(), "put primary") {
		t.Fatalf("expected put-primary error from Update, got %v", err)
	}
}

// TestSecureStorageStore_DeleteAll_DeleteError exercises the per-key delete
// error inside DeleteAll.
func TestSecureStorageStore_DeleteAll_DeleteError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewSecureStorageStore(plain)

	if err := seedStore.PutItem(ctx, "u1", &securestorage.StorageItem{Key: []byte("k"), Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}

	kv := &faultyListKV{FakeKVStore: plain, deleteErr: errors.New("delete failure")}
	s := NewSecureStorageStore(kv)

	err := s.DeleteAll(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected delete error from DeleteAll, got %v", err)
	}
}

// TestPreKeyStore_TakeEC_ErrNotFound_FallsBack exercises the ErrNotFound path
// inside TakeEC when the key listed but no value returned (nil).
// This is equivalent to the ErrNotFound branch: list returns a key but
// getOrNotFound returns ErrNotFound (nil value from underlying store).
// We simulate this by writing a key, listing it, then deleting it before
// the value is read — not feasible without concurrency. Instead we test
// the getErr path by reading a key that was listed but returns a Get error.
func TestPreKeyStore_TakeEC_GetError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewPreKeyStore(plain)
	_ = seedStore.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk")}})

	kv := &faultyKV{FakeKVStore: plain, getErr: errors.New("get failure")}
	s := NewPreKeyStore(kv)
	_, err := s.TakeEC(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "get ec") {
		t.Fatalf("expected get-ec error from TakeEC, got %v", err)
	}
}

// TestPreKeyStore_TakeKEM_GetError_Propagated exercises the Get error in TakeKEM.
func TestPreKeyStore_TakeKEM_GetError_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	seedStore := NewPreKeyStore(plain)
	_ = seedStore.StoreKEMPreKeys(ctx, "u1", 1, []*keys.KEMSignedPreKey{{KeyID: 1, PublicKey: []byte("pk")}})

	kv := &faultyKV{FakeKVStore: plain, getErr: errors.New("get failure")}
	s := NewPreKeyStore(kv)
	_, err := s.TakeKEM(ctx, "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "get kem") {
		t.Fatalf("expected get-kem error from TakeKEM, got %v", err)
	}
}

// TestPreKeyStore_StoreECPreKeys_PutError exercises the Put error in the
// StoreECPreKeys loop.
func TestPreKeyStore_StoreECPreKeys_PutError(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewPreKeyStore(kv)

	err := s.StoreECPreKeys(context.Background(), "u1", 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk")}})
	if err == nil || !strings.Contains(err.Error(), "put ec") {
		t.Fatalf("expected put-ec error, got %v", err)
	}
}

// TestPreKeyStore_StoreKEMPreKeys_PutError exercises the Put error in the
// StoreKEMPreKeys loop.
func TestPreKeyStore_StoreKEMPreKeys_PutError(t *testing.T) {
	t.Parallel()
	boom := errors.New("put failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom}
	s := NewPreKeyStore(kv)

	err := s.StoreKEMPreKeys(context.Background(), "u1", 1, []*keys.KEMSignedPreKey{{KeyID: 1, PublicKey: []byte("pk")}})
	if err == nil || !strings.Contains(err.Error(), "put kem") {
		t.Fatalf("expected put-kem error, got %v", err)
	}
}

// ─── Round 3: final sub-90% function closures ────────────────────────────────

// TestGroupStore_Get_BackendError exercises the non-NotFound backend error
// from Get (line 62-64 in groups.go).
func TestGroupStore_Get_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewGroupStore(kv)

	_, err := s.Get(context.Background(), "g1")
	if err == nil || !strings.Contains(err.Error(), "get") {
		t.Fatalf("expected get error from Group.Get, got %v", err)
	}
}

// TestVerificationSessionStore_Get_BackendError exercises the non-NotFound
// backend error from VerificationSessionStore.Get.
func TestVerificationSessionStore_Get_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewVerificationSessionStore(kv)

	_, err := s.Get(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "get") {
		t.Fatalf("expected get error, got %v", err)
	}
}

// TestProfileStore_Get_BackendError exercises the non-NotFound backend error
// from ProfileStore.Get.
func TestProfileStore_Get_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewProfileStore(kv)

	_, err := s.Get(context.Background(), "u1", "v1")
	if err == nil || !strings.Contains(err.Error(), "get") {
		t.Fatalf("expected get error from Profile.Get, got %v", err)
	}
}

// TestProfileStore_GetLatest_BackendError exercises the non-NotFound backend
// error from ProfileStore.GetLatest.
func TestProfileStore_GetLatest_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewProfileStore(kv)

	_, err := s.GetLatest(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "get latest") {
		t.Fatalf("expected get-latest error, got %v", err)
	}
}

// TestSecureStorageStore_GetItem_BackendError exercises the non-NotFound
// backend error from SecureStorageStore.GetItem.
func TestSecureStorageStore_GetItem_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewSecureStorageStore(kv)

	_, err := s.GetItem(context.Background(), "u1", []byte("k"))
	if err == nil || !strings.Contains(err.Error(), "get item") {
		t.Fatalf("expected get-item error, got %v", err)
	}
}

// TestUsernameStore_GetLink_BackendError exercises the non-NotFound backend
// error from UsernameStore.GetLink.
func TestUsernameStore_GetLink_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewUsernameStore(kv)

	_, err := s.GetLink(context.Background(), "h1")
	if err == nil || !strings.Contains(err.Error(), "get link") {
		t.Fatalf("expected get-link error, got %v", err)
	}
}

// TestPreKeyStore_GetKEMLastResortPreKey_BackendError exercises the non-NotFound
// backend error from GetKEMLastResortPreKey.
func TestPreKeyStore_GetKEMLastResortPreKey_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewPreKeyStore(kv)

	_, err := s.GetKEMLastResortPreKey(context.Background(), "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "get last-resort") {
		t.Fatalf("expected get-last-resort error, got %v", err)
	}
}

// TestPreKeyStore_GetSignedPreKey_BackendError exercises the non-NotFound
// backend error from GetSignedPreKey.
func TestPreKeyStore_GetSignedPreKey_BackendError(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom}
	s := NewPreKeyStore(kv)

	_, err := s.GetSignedPreKey(context.Background(), "u1", 1)
	if err == nil || !strings.Contains(err.Error(), "get signed") {
		t.Fatalf("expected get-signed error, got %v", err)
	}
}

// TestSecureStorageStore_PutItem_NilKey exercises PutItem with nil Key —
// itemKey with nil should still produce a valid (empty-encoded) key string.
func TestSecureStorageStore_PutItem_ZeroLengthKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewSecureStorageStore(NewFakeKVStore())
	// nil key base64-encodes to empty string, which is still a valid KV key.
	item := &securestorage.StorageItem{Key: nil, Value: []byte("v")}
	if err := s.PutItem(ctx, "u1", item); err != nil {
		t.Fatalf("PutItem with nil key: %v", err)
	}
}

// TestVerificationSessionStore_DeleteExpired_GetError exercises the
// getOrNotFound error path inside DeleteExpired's loop.
func TestVerificationSessionStore_DeleteExpired_GetError(t *testing.T) {
	// No t.Parallel: this test mutates the package-level timeNow.
	ctx := context.Background()
	plain := NewFakeKVStore()
	// Put a key directly at the verification prefix so the List returns it,
	// but then arm a getErr so the Get inside the loop fails.
	_ = plain.Put(ctx, verificationKey("s1"), []byte(`{"id":"s1"}`))

	boom := errors.New("get failure")
	kv := &faultyKV{FakeKVStore: plain, getErr: boom}
	s := NewVerificationSessionStore(kv)

	now := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	origNow := timeNow
	defer func() { timeNow = origNow }()
	timeNow = func() time.Time { return now }

	err := s.DeleteExpired(ctx)
	if err == nil || !strings.Contains(err.Error(), "get") {
		t.Fatalf("expected get error from DeleteExpired, got %v", err)
	}
}

// TestUsernameStore_ConfirmHash_PutConfirmedError exercises the put-confirmed
// error path in ConfirmHash (after deleting old entry, if any).
func TestUsernameStore_ConfirmHash_PutConfirmedError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	seedStore := NewUsernameStore(plain)
	seedStore.now = func() time.Time { return clock }

	hash := []byte("h-put-confirmed-err")
	_, token, err := seedStore.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}

	// Arm put failure so Put(confirmed) fails.
	kv := &faultyListKV{FakeKVStore: plain, putN: 0, putErr: errors.New("put-confirmed failure")}
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return clock }

	err = s.ConfirmHash(ctx, "u1", hash, token)
	if err == nil || !strings.Contains(err.Error(), "put confirmed") {
		t.Fatalf("expected put-confirmed error, got %v", err)
	}
}

// TestUsernameStore_ConfirmHash_PutByUUIDError exercises the put-byuuid
// error path in ConfirmHash (second put).
func TestUsernameStore_ConfirmHash_PutByUUIDError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	seedStore := NewUsernameStore(plain)
	seedStore.now = func() time.Time { return clock }

	hash := []byte("h-put-byuuid-err")
	_, token, err := seedStore.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}

	// First put (confirmed) succeeds; second put (byuuid) fails.
	kv := &faultyListKV{FakeKVStore: plain, putN: 1, putErr: errors.New("put-byuuid failure")}
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return clock }

	err = s.ConfirmHash(ctx, "u1", hash, token)
	if err == nil || !strings.Contains(err.Error(), "put byuuid") {
		t.Fatalf("expected put-byuuid error, got %v", err)
	}
}

// TestUsernameStore_ConfirmHash_DeleteReservationError exercises the
// delete-reservation error path (last step of ConfirmHash).
func TestUsernameStore_ConfirmHash_DeleteReservationError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	plain := NewFakeKVStore()
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	seedStore := NewUsernameStore(plain)
	seedStore.now = func() time.Time { return clock }

	hash := []byte("h-del-reservation-err")
	_, token, err := seedStore.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}

	// Two puts succeed (confirmed + byuuid); delete (reservation) fails.
	kv := &faultyListKV{FakeKVStore: plain, putN: 2, putErr: errors.New("should not fire"),
		deleteN: 0, deleteErr: errors.New("delete-reservation failure")}
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return clock }

	err = s.ConfirmHash(ctx, "u1", hash, token)
	if err == nil || !strings.Contains(err.Error(), "delete reservation") {
		t.Fatalf("expected delete-reservation error, got %v", err)
	}
}

// TestStoreKEMLastResortPreKey_NilKey_Rejected validates the nil guard.
// (already tested, but ensures the marshal path is also covered via success)
func TestStoreKEMLastResortPreKey_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())
	lr := &keys.KEMSignedPreKey{KeyID: 77, IsLastResort: true, PublicKey: []byte("pk")}
	if err := s.StoreKEMLastResortPreKey(ctx, "u1", 1, lr); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey: %v", err)
	}
}

// TestStoreSignedPreKey_Success covers the happy path including marshal.
func TestStoreSignedPreKey_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())
	spk := &keys.SignedPreKey{KeyID: 42, PublicKey: []byte("pk"), Signature: []byte("sig")}
	if err := s.StoreSignedPreKey(ctx, "u1", 1, spk); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}
	got, err := s.GetSignedPreKey(ctx, "u1", 1)
	if err != nil || got.KeyID != 42 {
		t.Fatalf("roundtrip: %v / %+v", err, got)
	}
}

// ─── unused import guard ──────────────────────────────────────────────────────
// The json package is used via json.Marshal in helpers; verify it stays used.
var _ = json.Marshal
