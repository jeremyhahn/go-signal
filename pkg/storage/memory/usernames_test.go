package memory

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// --- NewMemoryUsernameStore tests ---

func TestNewMemoryUsernameStore(t *testing.T) {
	store := NewMemoryUsernameStore()
	if store == nil {
		t.Fatal("expected non-nil store")
		return
	}
	if store.hashToUUID == nil {
		t.Fatal("expected hashToUUID map to be initialized")
	}
	if store.uuidToHash == nil {
		t.Fatal("expected uuidToHash map to be initialized")
	}
	if store.reservations == nil {
		t.Fatal("expected reservations map to be initialized")
	}
	if store.handleToLink == nil {
		t.Fatal("expected handleToLink map to be initialized")
	}
	if store.uuidToHandle == nil {
		t.Fatal("expected uuidToHandle map to be initialized")
	}
}

func TestNewMemoryUsernameStoreEmptyMaps(t *testing.T) {
	store := NewMemoryUsernameStore()
	if len(store.hashToUUID) != 0 {
		t.Fatalf("expected empty hashToUUID, got %d", len(store.hashToUUID))
	}
	if len(store.uuidToHash) != 0 {
		t.Fatalf("expected empty uuidToHash, got %d", len(store.uuidToHash))
	}
	if len(store.reservations) != 0 {
		t.Fatalf("expected empty reservations, got %d", len(store.reservations))
	}
}

// --- ReserveHash tests ---

func TestReserveHash_Success(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	hashes := [][]byte{[]byte("hash-1"), []byte("hash-2")}
	selected, token, err := store.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if selected == nil {
		t.Fatal("expected non-nil selected hash")
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if !bytes.Equal(selected, []byte("hash-1")) {
		t.Fatalf("expected first hash to be selected, got %v", selected)
	}
}

func TestReserveHash_SkipsTakenHash(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	// First, reserve and confirm hash-1 for uuid-other.
	hashes1 := [][]byte{[]byte("hash-1")}
	selected, token, err := store.ReserveHash(ctx, "uuid-other", hashes1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.ConfirmHash(ctx, "uuid-other", selected, token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now uuid-1 tries to reserve hash-1 and hash-2.
	hashes2 := [][]byte{[]byte("hash-1"), []byte("hash-2")}
	selected2, _, err := store.ReserveHash(ctx, "uuid-1", hashes2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(selected2, []byte("hash-2")) {
		t.Fatalf("expected hash-2 to be selected (hash-1 taken), got %v", selected2)
	}
}

func TestReserveHash_AllTaken(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	// Reserve and confirm hash-1 for uuid-other.
	hashes1 := [][]byte{[]byte("hash-1")}
	selected, token, err := store.ReserveHash(ctx, "uuid-other", hashes1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.ConfirmHash(ctx, "uuid-other", selected, token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// uuid-1 tries to reserve only hash-1 (already taken).
	hashes2 := [][]byte{[]byte("hash-1")}
	_, _, err = store.ReserveHash(ctx, "uuid-1", hashes2)
	if err == nil {
		t.Fatal("expected error when all hashes are taken")
	}

	var conflictErr *usernames.UsernameHashConflictError
	if ce, ok := err.(*usernames.UsernameHashConflictError); !ok {
		t.Fatalf("expected *UsernameHashConflictError, got %T", err)
	} else {
		conflictErr = ce
	}
	if !bytes.Equal(conflictErr.Hash, []byte("hash-1")) {
		t.Fatalf("expected conflict hash %v, got %v", []byte("hash-1"), conflictErr.Hash)
	}
}

func TestReserveHash_SameUUIDCanReReserve(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	hashes := [][]byte{[]byte("hash-1")}
	_, token1, err := store.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same UUID can reserve again (replaces previous reservation).
	_, token2, err := store.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Tokens should be different.
	if token1 == token2 {
		t.Fatal("expected different tokens on re-reservation")
	}
}

func TestReserveHash_CopiesInput(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	original := []byte("hash-dc")
	hashes := [][]byte{original}
	selected, _, err := store.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the original input slice after reservation.
	original[0] = 0xFF

	// The selected hash and internal state should not be affected by input mutation.
	if selected[0] == 0xFF {
		t.Fatal("mutation of original input affected selected return value")
	}
}

// --- ConfirmHash tests ---

func TestConfirmHash_Success(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	hashes := [][]byte{[]byte("hash-1")}
	selected, token, err := store.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.ConfirmHash(ctx, "uuid-1", selected, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be able to look up by hash.
	uuid, err := store.LookupByHash(ctx, []byte("hash-1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uuid != "uuid-1" {
		t.Fatalf("expected UUID %q, got %q", "uuid-1", uuid)
	}
}

func TestConfirmHash_NoReservation(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	err := store.ConfirmHash(ctx, "uuid-no-res", []byte("hash"), "token")
	if err == nil {
		t.Fatal("expected error for no reservation")
	}

	var tokenErr *usernames.InvalidReservationTokenError
	if _, ok := err.(*usernames.InvalidReservationTokenError); !ok {
		t.Fatalf("expected *InvalidReservationTokenError, got %T", err)
	} else {
		tokenErr = err.(*usernames.InvalidReservationTokenError)
	}
	if tokenErr.UUID != "uuid-no-res" {
		t.Fatalf("expected UUID %q, got %q", "uuid-no-res", tokenErr.UUID)
	}
}

func TestConfirmHash_WrongToken(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	hashes := [][]byte{[]byte("hash-1")}
	selected, _, err := store.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.ConfirmHash(ctx, "uuid-1", selected, "wrong-token")
	if err == nil {
		t.Fatal("expected error for wrong token")
	}

	if _, ok := err.(*usernames.InvalidReservationTokenError); !ok {
		t.Fatalf("expected *InvalidReservationTokenError, got %T", err)
	}
}

func TestConfirmHash_WrongHash(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	hashes := [][]byte{[]byte("hash-1")}
	_, token, err := store.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.ConfirmHash(ctx, "uuid-1", []byte("different-hash"), token)
	if err == nil {
		t.Fatal("expected error for wrong hash")
	}

	if _, ok := err.(*usernames.InvalidReservationTokenError); !ok {
		t.Fatalf("expected *InvalidReservationTokenError, got %T", err)
	}
}

func TestConfirmHash_ReplacesOldConfirmedHash(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	// Confirm first hash.
	hashes1 := [][]byte{[]byte("old-hash")}
	selected1, token1, err := store.ReserveHash(ctx, "uuid-1", hashes1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.ConfirmHash(ctx, "uuid-1", selected1, token1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Confirm new hash.
	hashes2 := [][]byte{[]byte("new-hash")}
	selected2, token2, err := store.ReserveHash(ctx, "uuid-1", hashes2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.ConfirmHash(ctx, "uuid-1", selected2, token2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old hash should no longer resolve.
	_, err = store.LookupByHash(ctx, []byte("old-hash"))
	if err == nil {
		t.Fatal("expected old hash to be removed")
	}

	// New hash should resolve.
	uuid, err := store.LookupByHash(ctx, []byte("new-hash"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uuid != "uuid-1" {
		t.Fatalf("expected UUID %q, got %q", "uuid-1", uuid)
	}
}

// --- LookupByHash tests ---

func TestLookupByHash_Success(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	hashes := [][]byte{[]byte("lookup-hash")}
	selected, token, err := store.ReserveHash(ctx, "uuid-lookup", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.ConfirmHash(ctx, "uuid-lookup", selected, token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	uuid, err := store.LookupByHash(ctx, []byte("lookup-hash"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uuid != "uuid-lookup" {
		t.Fatalf("expected UUID %q, got %q", "uuid-lookup", uuid)
	}
}

func TestLookupByHash_NotFound(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	_, err := store.LookupByHash(ctx, []byte("nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent hash")
	}

	if _, ok := err.(*usernames.UsernameNotFoundError); !ok {
		t.Fatalf("expected *UsernameNotFoundError, got %T", err)
	}
}

// --- DeleteHash tests ---

func TestDeleteHash_Success(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	hashes := [][]byte{[]byte("del-hash")}
	selected, token, err := store.ReserveHash(ctx, "uuid-del", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.ConfirmHash(ctx, "uuid-del", selected, token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = store.DeleteHash(ctx, "uuid-del")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Hash should no longer resolve.
	_, err = store.LookupByHash(ctx, []byte("del-hash"))
	if err == nil {
		t.Fatal("expected hash to be deleted")
	}
}

func TestDeleteHash_NotFound_Idempotent(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	// Deleting a hash for a UUID with no confirmed hash is idempotent.
	err := store.DeleteHash(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("expected nil for nonexistent UUID delete, got %v", err)
	}
}

// --- SetLink tests ---

func TestSetLink_Success(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	link := &usernames.UsernameLink{
		UUID:               "uuid-link",
		UsernameLinkHandle: "handle-1",
		EncryptedUsername:  []byte("encrypted-data"),
	}
	err := store.SetLink(ctx, link)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetLink(ctx, "handle-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-link" {
		t.Fatalf("expected UUID %q, got %q", "uuid-link", got.UUID)
	}
	if !bytes.Equal(got.EncryptedUsername, []byte("encrypted-data")) {
		t.Fatal("EncryptedUsername mismatch")
	}
}

func TestSetLink_ReplacesExisting(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	link1 := &usernames.UsernameLink{
		UUID:               "uuid-1",
		UsernameLinkHandle: "handle-old",
		EncryptedUsername:  []byte("old-data"),
	}
	if err := store.SetLink(ctx, link1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	link2 := &usernames.UsernameLink{
		UUID:               "uuid-1",
		UsernameLinkHandle: "handle-new",
		EncryptedUsername:  []byte("new-data"),
	}
	if err := store.SetLink(ctx, link2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old handle should not resolve.
	_, err := store.GetLink(ctx, "handle-old")
	if err == nil {
		t.Fatal("expected old handle to be removed")
	}

	// New handle should work.
	got, err := store.GetLink(ctx, "handle-new")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.EncryptedUsername, []byte("new-data")) {
		t.Fatal("EncryptedUsername mismatch")
	}
}

func TestSetLink_DeepCopy(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	link := &usernames.UsernameLink{
		UUID:               "uuid-dc",
		UsernameLinkHandle: "handle-dc",
		EncryptedUsername:  []byte("encrypted"),
	}
	if err := store.SetLink(ctx, link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate original.
	link.EncryptedUsername[0] = 0xFF

	got, err := store.GetLink(ctx, "handle-dc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.EncryptedUsername[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
}

// --- GetLink tests ---

func TestGetLink_Success(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	link := &usernames.UsernameLink{
		UUID:               "uuid-get",
		UsernameLinkHandle: "handle-get",
		EncryptedUsername:  []byte("data"),
	}
	if err := store.SetLink(ctx, link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetLink(ctx, "handle-get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-get" {
		t.Fatalf("expected UUID %q, got %q", "uuid-get", got.UUID)
	}
	if got.UsernameLinkHandle != "handle-get" {
		t.Fatalf("expected handle %q, got %q", "handle-get", got.UsernameLinkHandle)
	}
}

func TestGetLink_NotFound(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	_, err := store.GetLink(ctx, "nonexistent-handle")
	if err == nil {
		t.Fatal("expected error for nonexistent handle")
	}

	if _, ok := err.(*usernames.UsernameLinkNotFoundError); !ok {
		t.Fatalf("expected *UsernameLinkNotFoundError, got %T", err)
	}
}

func TestGetLink_DeepCopy(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	link := &usernames.UsernameLink{
		UUID:               "uuid-gdc",
		UsernameLinkHandle: "handle-gdc",
		EncryptedUsername:  []byte("data-gdc"),
	}
	if err := store.SetLink(ctx, link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetLink(ctx, "handle-gdc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got.EncryptedUsername[0] = 0xAA

	got2, err := store.GetLink(ctx, "handle-gdc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.EncryptedUsername[0] == 0xAA {
		t.Fatal("mutation of returned value affected stored data")
	}
}

// --- DeleteLink tests ---

func TestDeleteLink_Success(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	link := &usernames.UsernameLink{
		UUID:               "uuid-dlink",
		UsernameLinkHandle: "handle-dlink",
		EncryptedUsername:  []byte("data"),
	}
	if err := store.SetLink(ctx, link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := store.DeleteLink(ctx, "uuid-dlink")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = store.GetLink(ctx, "handle-dlink")
	if err == nil {
		t.Fatal("expected link to be deleted")
	}
}

func TestDeleteLink_NotFound_Idempotent(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	// Deleting a link for a UUID with no link is idempotent.
	err := store.DeleteLink(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("expected nil for nonexistent UUID delete, got %v", err)
	}
}

func TestDeleteLink_DoesNotAffectOtherLinks(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	link1 := &usernames.UsernameLink{UUID: "uuid-1", UsernameLinkHandle: "handle-1", EncryptedUsername: []byte("d1")}
	link2 := &usernames.UsernameLink{UUID: "uuid-2", UsernameLinkHandle: "handle-2", EncryptedUsername: []byte("d2")}

	if err := store.SetLink(ctx, link1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.SetLink(ctx, link2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteLink(ctx, "uuid-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetLink(ctx, "handle-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-2" {
		t.Fatalf("expected UUID %q, got %q", "uuid-2", got.UUID)
	}
}

// --- Concurrency tests ---

func TestUsernameStoreConcurrentReserveAndConfirm(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			uuid := "uuid-conc-" + string(rune('A'+idx))
			hash := []byte("hash-conc-" + string(rune('A'+idx)))
			hashes := [][]byte{hash}
			selected, token, err := store.ReserveHash(ctx, uuid, hashes)
			if err != nil {
				return
			}
			_ = store.ConfirmHash(ctx, uuid, selected, token)
		}(i)
	}
	wg.Wait()
}

func TestUsernameStoreConcurrentLinkOps(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			link := &usernames.UsernameLink{
				UUID:               "uuid-cl-" + string(rune('A'+idx)),
				UsernameLinkHandle: "handle-cl-" + string(rune('A'+idx)),
				EncryptedUsername:  []byte("data"),
			}
			_ = store.SetLink(ctx, link)
		}(i)
		go func(idx int) {
			defer wg.Done()
			handle := "handle-cl-" + string(rune('A'+idx))
			_, _ = store.GetLink(ctx, handle)
		}(i)
	}
	wg.Wait()
}

// --- Interface satisfaction ---

func TestMemoryUsernameStoreImplementsInterface(t *testing.T) {
	var _ usernames.UsernameStore = (*MemoryUsernameStore)(nil)
}

func TestMemoryUsernameStoreInterfaceNonNil(t *testing.T) {
	var store usernames.UsernameStore = NewMemoryUsernameStore()
	_ = store
}

// --- Reservation TTL tests ---

// TestSetClock confirms the clock injection hook overrides the default clock.
func TestSetClock(t *testing.T) {
	store := NewMemoryUsernameStore()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return fixed })

	store.mu.RLock()
	got := store.now()
	store.mu.RUnlock()

	if !got.Equal(fixed) {
		t.Fatalf("expected injected clock to return %v, got %v", fixed, got)
	}
}

// TestConfirmHash_RejectsExpiredReservation verifies that ConfirmHash rejects
// a reservation once the TTL has elapsed, matching qrdb/Java parity.
func TestConfirmHash_RejectsExpiredReservation(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return now })

	hashes := [][]byte{[]byte("hash-expire")}
	selected, token, err := store.ReserveHash(ctx, "uuid-expire", hashes)
	if err != nil {
		t.Fatalf("ReserveHash: unexpected error: %v", err)
	}

	// Advance the clock past the reservation TTL.
	expired := now.Add(reservationTTL).Add(time.Second)
	store.SetClock(func() time.Time { return expired })

	err = store.ConfirmHash(ctx, "uuid-expire", selected, token)
	if err == nil {
		t.Fatal("expected expired reservation to be rejected")
	}
	if _, ok := err.(*usernames.InvalidReservationTokenError); !ok {
		t.Fatalf("expected *InvalidReservationTokenError, got %T", err)
	}

	// The expired reservation should have been purged.
	store.mu.RLock()
	_, exists := store.reservations["uuid-expire"]
	store.mu.RUnlock()
	if exists {
		t.Fatal("expected expired reservation to be purged from store")
	}
}

// TestReserveHash_ReplacesExpiredReservation verifies that a UUID's stale
// reservation is purged so a new ReserveHash call succeeds.
func TestReserveHash_ReplacesExpiredReservation(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return now })

	if _, _, err := store.ReserveHash(ctx, "uuid-stale", [][]byte{[]byte("h-old")}); err != nil {
		t.Fatalf("ReserveHash: unexpected error: %v", err)
	}

	// Advance past the TTL and reserve again.
	store.SetClock(func() time.Time { return now.Add(reservationTTL).Add(time.Second) })

	selected, token, err := store.ReserveHash(ctx, "uuid-stale", [][]byte{[]byte("h-new")})
	if err != nil {
		t.Fatalf("ReserveHash after expiry: unexpected error: %v", err)
	}
	if !bytes.Equal(selected, []byte("h-new")) {
		t.Fatalf("expected fresh hash to be selected, got %v", selected)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

// TestReserveHash_SkipsHashHeldByOtherActiveReservation verifies that a
// non-expired reservation held by a different UUID blocks reuse of that hash.
func TestReserveHash_SkipsHashHeldByOtherActiveReservation(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return now })

	// uuid-A reserves hash-shared but never confirms.
	if _, _, err := store.ReserveHash(ctx, "uuid-A", [][]byte{[]byte("hash-shared")}); err != nil {
		t.Fatalf("first ReserveHash: %v", err)
	}

	// uuid-B tries to reserve only hash-shared while A's reservation is still valid.
	_, _, err := store.ReserveHash(ctx, "uuid-B", [][]byte{[]byte("hash-shared")})
	if err == nil {
		t.Fatal("expected conflict when hash is held by another active reservation")
	}
	if _, ok := err.(*usernames.UsernameHashConflictError); !ok {
		t.Fatalf("expected *UsernameHashConflictError, got %T", err)
	}

	// Once A's reservation expires, B should succeed.
	store.SetClock(func() time.Time { return now.Add(reservationTTL).Add(time.Second) })
	selected, _, err := store.ReserveHash(ctx, "uuid-B", [][]byte{[]byte("hash-shared")})
	if err != nil {
		t.Fatalf("ReserveHash after expiry: unexpected error: %v", err)
	}
	if !bytes.Equal(selected, []byte("hash-shared")) {
		t.Fatalf("expected hash-shared to be selected, got %v", selected)
	}
}

// ─── HashForUUID ────────────────────────────────────────────────────────────

func TestMemoryUsernameStore_HashForUUID_Found(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	// Seed a confirmed hash directly.
	store.uuidToHash["u-hash-1"] = []byte("confirmed-hash")
	store.hashToUUID[string([]byte("confirmed-hash"))] = "u-hash-1"

	got, err := store.HashForUUID(ctx, "u-hash-1")
	if err != nil {
		t.Fatalf("HashForUUID: unexpected error: %v", err)
	}
	if !bytes.Equal(got, []byte("confirmed-hash")) {
		t.Errorf("HashForUUID: got %q, want 'confirmed-hash'", got)
	}
}

func TestMemoryUsernameStore_HashForUUID_NotFound(t *testing.T) {
	store := NewMemoryUsernameStore()
	_, err := store.HashForUUID(context.Background(), "u-hash-missing")
	if err == nil {
		t.Fatal("HashForUUID: expected error for missing UUID")
	}
	if _, ok := err.(*usernames.UsernameNotFoundError); !ok {
		t.Errorf("HashForUUID: expected *UsernameNotFoundError, got %T", err)
	}
}

// ─── LinkForUUID ────────────────────────────────────────────────────────────

func TestMemoryUsernameStore_LinkForUUID_Found(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	// Seed confirmed hash so SetLink won't reject.
	store.uuidToHash["u-link-1"] = []byte("some-hash")
	store.hashToUUID[string([]byte("some-hash"))] = "u-link-1"

	link := &usernames.UsernameLink{
		UUID:               "u-link-1",
		UsernameLinkHandle: "handle-xyz",
		EncryptedUsername:  []byte("enc"),
	}
	if err := store.SetLink(ctx, link); err != nil {
		t.Fatalf("SetLink: %v", err)
	}

	got, err := store.LinkForUUID(ctx, "u-link-1")
	if err != nil {
		t.Fatalf("LinkForUUID: unexpected error: %v", err)
	}
	if got.UsernameLinkHandle != "handle-xyz" {
		t.Errorf("LinkForUUID: expected handle-xyz, got %q", got.UsernameLinkHandle)
	}
}

func TestMemoryUsernameStore_LinkForUUID_NotFound(t *testing.T) {
	store := NewMemoryUsernameStore()
	_, err := store.LinkForUUID(context.Background(), "u-link-missing")
	if err == nil {
		t.Fatal("LinkForUUID: expected error for missing UUID")
	}
	if _, ok := err.(*usernames.UsernameLinkNotFoundError); !ok {
		t.Errorf("LinkForUUID: expected *UsernameLinkNotFoundError, got %T", err)
	}
}

// ─── DeleteExpiredReservations ──────────────────────────────────────────────

func TestMemoryUsernameStore_DeleteExpiredReservations_Empty(t *testing.T) {
	store := NewMemoryUsernameStore()
	n, err := store.DeleteExpiredReservations(context.Background())
	if err != nil {
		t.Fatalf("DeleteExpiredReservations: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 deleted, got %d", n)
	}
}

func TestMemoryUsernameStore_DeleteExpiredReservations_RemovesExpired(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return past })

	// Create reservation at past.
	_, _, err := store.ReserveHash(ctx, "u-exp-1", [][]byte{[]byte("exp-hash")})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	// Advance clock beyond TTL so the reservation is expired.
	future := past.Add(reservationTTL + time.Second)
	store.SetClock(func() time.Time { return future })

	n, err := store.DeleteExpiredReservations(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredReservations: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 deleted, got %d", n)
	}
}

func TestMemoryUsernameStore_DeleteExpiredReservations_PreservesActive(t *testing.T) {
	store := NewMemoryUsernameStore()
	ctx := context.Background()

	now := time.Now().UTC()
	store.SetClock(func() time.Time { return now })

	// Reserve hash — reservation is active (not yet expired).
	if _, _, err := store.ReserveHash(ctx, "u-active-1", [][]byte{[]byte("active-hash")}); err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	// Don't advance clock — reservation still live.
	n, err := store.DeleteExpiredReservations(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredReservations: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 deleted (reservation still active), got %d", n)
	}
}
