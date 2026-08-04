package qrdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

func newUsernameStoreWithClock(t *testing.T) (*UsernameStore, *time.Time) {
	t.Helper()
	clock := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	s := NewUsernameStore(NewFakeKVStore())
	s.now = func() time.Time { return clock }
	return s, &clock
}

func TestUsernameStore_ReserveHash_HappyPath(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	hash := []byte("hash-1")
	selected, token, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}
	if string(selected) != "hash-1" {
		t.Fatalf("wrong hash selected: %s", selected)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestUsernameStore_ReserveHash_InvalidInput(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	if _, _, err := s.ReserveHash(context.Background(), "", [][]byte{{1}}); err == nil {
		t.Fatal("expected error for empty UUID")
	}
	if _, _, err := s.ReserveHash(context.Background(), "u1", nil); err == nil {
		t.Fatal("expected error for nil hashes")
	}
}

func TestUsernameStore_Confirm_RequiresMatchingToken(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	hash := []byte("h")
	_, token, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}

	// Wrong token rejected.
	err = s.ConfirmHash(ctx, "u1", hash, "wrong-token")
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError, got %T: %v", err, err)
	}

	// Correct token succeeds.
	if err := s.ConfirmHash(ctx, "u1", hash, token); err != nil {
		t.Fatalf("ConfirmHash: %v", err)
	}

	// Lookup resolves to the account.
	got, err := s.LookupByHash(ctx, hash)
	if err != nil || got != "u1" {
		t.Fatalf("LookupByHash: got=%s err=%v", got, err)
	}
}

func TestUsernameStore_Confirm_NoReservation(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	err := s.ConfirmHash(context.Background(), "u1", []byte("h"), "token")
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError, got %T: %v", err, err)
	}
}

func TestUsernameStore_LookupByHash_Missing(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	_, err := s.LookupByHash(context.Background(), []byte("absent"))
	var unfe *usernames.UsernameNotFoundError
	if !errors.As(err, &unfe) {
		t.Fatalf("expected UsernameNotFoundError, got %T: %v", err, err)
	}
}

func TestUsernameStore_DeleteHash_Idempotent(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	// Delete when no hash exists should not error.
	if err := s.DeleteHash(context.Background(), "u1"); err != nil {
		t.Fatalf("DeleteHash should be idempotent: %v", err)
	}
}

func TestUsernameStore_SetAndGetLink(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	link := &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "h1", EncryptedUsername: []byte("enc")}
	if err := s.SetLink(ctx, link); err != nil {
		t.Fatalf("SetLink: %v", err)
	}
	got, err := s.GetLink(ctx, "h1")
	if err != nil || string(got.EncryptedUsername) != "enc" {
		t.Fatalf("GetLink: err=%v got=%+v", err, got)
	}
}

func TestUsernameStore_SetLink_Invalid(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	if err := s.SetLink(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil link")
	}
	if err := s.SetLink(context.Background(), &usernames.UsernameLink{UUID: "u1"}); err == nil {
		t.Fatal("expected error for missing handle")
	}
}

func TestUsernameStore_GetLink_Missing(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	_, err := s.GetLink(context.Background(), "absent")
	var unfe *usernames.UsernameLinkNotFoundError
	if !errors.As(err, &unfe) {
		t.Fatalf("expected UsernameLinkNotFoundError, got %T: %v", err, err)
	}
}

func TestUsernameStore_SetLink_ReplacesOld(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	if err := s.SetLink(ctx, &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "old", EncryptedUsername: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLink(ctx, &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "new", EncryptedUsername: []byte("b")}); err != nil {
		t.Fatal(err)
	}

	// Old handle should no longer resolve.
	if _, err := s.GetLink(ctx, "old"); err == nil {
		t.Fatal("old handle should be gone after SetLink replacement")
	}
	// New handle should.
	got, err := s.GetLink(ctx, "new")
	if err != nil || string(got.EncryptedUsername) != "b" {
		t.Fatalf("GetLink(new): err=%v got=%+v", err, got)
	}
}

func TestUsernameStore_DeleteLink_Idempotent(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	if err := s.DeleteLink(context.Background(), "u1"); err != nil {
		t.Fatalf("DeleteLink should be idempotent: %v", err)
	}
}

func TestUsernameStore_DeleteLink_RemovesExisting(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	if err := s.SetLink(ctx, &usernames.UsernameLink{UUID: "u1", UsernameLinkHandle: "h", EncryptedUsername: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteLink(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetLink(ctx, "h"); err == nil {
		t.Fatal("link should be gone after DeleteLink")
	}
}

func TestUsernameStore_ReserveHash_NonePossible(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	// u1 reserves and confirms hash.
	hash := []byte("taken")
	_, token, err := s.ReserveHash(ctx, "u1", [][]byte{hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmHash(ctx, "u1", hash, token); err != nil {
		t.Fatal(err)
	}

	// u2 tries to reserve the same hash — should conflict.
	_, _, err = s.ReserveHash(ctx, "u2", [][]byte{hash})
	var uhce *usernames.UsernameHashConflictError
	if !errors.As(err, &uhce) {
		t.Fatalf("expected UsernameHashConflictError, got %T: %v", err, err)
	}
}

// ─── HashForUUID ─────────────────────────────────────────────────────────────

func TestUsernameStore_HashForUUID_Found(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	hash := []byte("hfu-hash")
	_, token, err := s.ReserveHash(ctx, "hfu-u1", [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}
	if err := s.ConfirmHash(ctx, "hfu-u1", hash, token); err != nil {
		t.Fatalf("ConfirmHash: %v", err)
	}

	got, err := s.HashForUUID(ctx, "hfu-u1")
	if err != nil {
		t.Fatalf("HashForUUID: unexpected error: %v", err)
	}
	if string(got) != string(hash) {
		t.Errorf("HashForUUID: expected %q, got %q", hash, got)
	}
}

func TestUsernameStore_HashForUUID_NotFound(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	_, err := s.HashForUUID(context.Background(), "hfu-missing")
	var unfe *usernames.UsernameNotFoundError
	if !errors.As(err, &unfe) {
		t.Fatalf("HashForUUID missing: expected UsernameNotFoundError, got %T: %v", err, err)
	}
}

// ─── LinkForUUID ─────────────────────────────────────────────────────────────

func TestUsernameStore_LinkForUUID_Found(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	ctx := context.Background()

	link := &usernames.UsernameLink{
		UUID:               "lfu-u1",
		UsernameLinkHandle: "lfu-handle",
		EncryptedUsername:  []byte("lfu-enc"),
	}
	if err := s.SetLink(ctx, link); err != nil {
		t.Fatalf("SetLink: %v", err)
	}

	got, err := s.LinkForUUID(ctx, "lfu-u1")
	if err != nil {
		t.Fatalf("LinkForUUID: unexpected error: %v", err)
	}
	if got.UsernameLinkHandle != "lfu-handle" {
		t.Errorf("LinkForUUID: expected lfu-handle, got %q", got.UsernameLinkHandle)
	}
}

func TestUsernameStore_LinkForUUID_NotFound(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	_, err := s.LinkForUUID(context.Background(), "lfu-missing")
	var ulnfe *usernames.UsernameLinkNotFoundError
	if !errors.As(err, &ulnfe) {
		t.Fatalf("LinkForUUID missing: expected UsernameLinkNotFoundError, got %T: %v", err, err)
	}
}

// ─── DeleteExpiredReservations ───────────────────────────────────────────────

func TestUsernameStore_DeleteExpiredReservations_Empty(t *testing.T) {
	t.Parallel()
	s, _ := newUsernameStoreWithClock(t)
	n, err := s.DeleteExpiredReservations(context.Background())
	if err != nil {
		t.Fatalf("DeleteExpiredReservations: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 deleted, got %d", n)
	}
}

func TestUsernameStore_DeleteExpiredReservations_RemovesExpired(t *testing.T) {
	t.Parallel()
	kv := NewFakeKVStore()
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return past }
	ctx := context.Background()

	// Create a reservation at the past time.
	_, _, err := s.ReserveHash(ctx, "der-u1", [][]byte{[]byte("der-hash")})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	// Advance clock so the reservation is expired.
	const reservationTTL = 5 * time.Minute
	s.now = func() time.Time { return past.Add(reservationTTL + time.Second) }

	n, err := s.DeleteExpiredReservations(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredReservations: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 deleted, got %d", n)
	}
}

func TestUsernameStore_DeleteExpiredReservations_PreservesActive(t *testing.T) {
	t.Parallel()
	kv := NewFakeKVStore()
	now := time.Now().UTC()
	s := NewUsernameStore(kv)
	s.now = func() time.Time { return now }
	ctx := context.Background()

	// Reserve hash — still active (not expired).
	if _, _, err := s.ReserveHash(ctx, "der-u2", [][]byte{[]byte("der-active")}); err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	// Don't advance clock.
	n, err := s.DeleteExpiredReservations(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredReservations: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 deleted (reservation active), got %d", n)
	}
}
