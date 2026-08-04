package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// randHash returns a fresh 32-byte slice for use as a username hash. Each
// call produces a unique value so tests never collide.
func randHash(t *testing.T) []byte {
	t.Helper()
	tok, err := newToken()
	if err != nil {
		t.Fatalf("randHash: %v", err)
	}
	// newToken returns 32 hex chars; use the raw bytes so we have proper BYTEA.
	return []byte(tok)
}

// expireReservation backdates a reservation row so it looks expired in tests.
func expireReservation(ctx context.Context, t *testing.T, c *Client, accountUUID string) {
	t.Helper()
	_, err := c.Pool().Exec(ctx, `
		UPDATE usernames_reserved SET expires_at = NOW() - INTERVAL '1 hour'
		WHERE account_uuid = $1`, accountUUID)
	if err != nil {
		t.Fatalf("expireReservation: %v", err)
	}
}

// ---- ReserveHash -------------------------------------------------------

func TestUsernames_ReserveHash_PicksFirstAvailable(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	h1 := randHash(t)
	h2 := randHash(t)
	acct := uuid.NewString()

	chosen, token, err := s.ReserveHash(ctx, acct, [][]byte{h1, h2})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}
	if string(chosen) != string(h1) {
		t.Fatalf("expected first hash to be chosen; got %x", chosen)
	}
	if len(token) != 32 {
		t.Fatalf("expected 32-char token, got len=%d", len(token))
	}
}

func TestUsernames_ReserveHash_SameAccount_ReReserve_UpdatesRow(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	h1 := randHash(t)
	h2 := randHash(t)

	// First reservation.
	chosen1, token1, err := s.ReserveHash(ctx, acct, [][]byte{h1})
	if err != nil {
		t.Fatalf("ReserveHash #1: %v", err)
	}

	// Same account re-reserves with a different hash; must succeed and replace.
	chosen2, token2, err := s.ReserveHash(ctx, acct, [][]byte{h2})
	if err != nil {
		t.Fatalf("ReserveHash #2: %v", err)
	}
	if string(chosen2) != string(h2) {
		t.Fatalf("expected h2 chosen on re-reserve")
	}
	if token2 == token1 {
		t.Fatalf("expected new token on re-reserve, got same token")
	}
	_ = chosen1
}

func TestUsernames_ReserveHash_SecondAccount_CannotReserveConfirmedHash(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct1 := uuid.NewString()
	acct2 := uuid.NewString()
	hash := randHash(t)

	// acct1 reserves and confirms the hash.
	_, tok, err := s.ReserveHash(ctx, acct1, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash acct1: %v", err)
	}
	if err := s.ConfirmHash(ctx, acct1, hash, tok); err != nil {
		t.Fatalf("ConfirmHash acct1: %v", err)
	}

	// acct2 tries to reserve the same hash — must be rejected.
	_, _, err = s.ReserveHash(ctx, acct2, [][]byte{hash})
	var conflict *usernames.UsernameHashConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected UsernameHashConflictError, got %T: %v", err, err)
	}
}

func TestUsernames_ReserveHash_SecondAccount_CannotReserveActivelyReservedHash(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct1 := uuid.NewString()
	acct2 := uuid.NewString()
	hash := randHash(t)

	if _, _, err := s.ReserveHash(ctx, acct1, [][]byte{hash}); err != nil {
		t.Fatalf("ReserveHash acct1: %v", err)
	}

	_, _, err := s.ReserveHash(ctx, acct2, [][]byte{hash})
	var conflict *usernames.UsernameHashConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected UsernameHashConflictError, got %T: %v", err, err)
	}
}

func TestUsernames_ReserveHash_EmptyUUID_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	_, _, err := s.ReserveHash(context.Background(), "", [][]byte{randHash(t)})
	var iae *usernames.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestUsernames_ReserveHash_NoHashes_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	_, _, err := s.ReserveHash(context.Background(), uuid.NewString(), nil)
	var iae *usernames.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

// ---- ConfirmHash -------------------------------------------------------

func TestUsernames_ConfirmHash_ValidToken_Succeeds(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	hash := randHash(t)

	_, tok, err := s.ReserveHash(ctx, acct, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}
	if err := s.ConfirmHash(ctx, acct, hash, tok); err != nil {
		t.Fatalf("ConfirmHash: %v", err)
	}

	// Verify it is now retrievable.
	got, err := s.LookupByHash(ctx, hash)
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if got != acct {
		t.Fatalf("LookupByHash: got %q, want %q", got, acct)
	}
}

func TestUsernames_ConfirmHash_WrongToken_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	hash := randHash(t)

	if _, _, err := s.ReserveHash(ctx, acct, [][]byte{hash}); err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	err := s.ConfirmHash(ctx, acct, hash, "deadbeefdeadbeefdeadbeefdeadbeef")
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError, got %T: %v", err, err)
	}
}

func TestUsernames_ConfirmHash_ExpiredReservation_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	hash := randHash(t)

	_, tok, err := s.ReserveHash(ctx, acct, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	expireReservation(ctx, t, c, acct)

	err = s.ConfirmHash(ctx, acct, hash, tok)
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError, got %T: %v", err, err)
	}
}

func TestUsernames_ConfirmHash_NoReservation_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	err := s.ConfirmHash(ctx, uuid.NewString(), randHash(t), "aabbccddeeff00112233445566778899")
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError, got %T: %v", err, err)
	}
}

func TestUsernames_ConfirmHash_ReplacesExistingConfirmed(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	h1 := randHash(t)
	h2 := randHash(t)

	// Confirm h1.
	_, tok1, err := s.ReserveHash(ctx, acct, [][]byte{h1})
	if err != nil {
		t.Fatalf("ReserveHash h1: %v", err)
	}
	if err := s.ConfirmHash(ctx, acct, h1, tok1); err != nil {
		t.Fatalf("ConfirmHash h1: %v", err)
	}

	// Reserve and confirm h2 for the same account — replaces h1.
	_, tok2, err := s.ReserveHash(ctx, acct, [][]byte{h2})
	if err != nil {
		t.Fatalf("ReserveHash h2: %v", err)
	}
	if err := s.ConfirmHash(ctx, acct, h2, tok2); err != nil {
		t.Fatalf("ConfirmHash h2: %v", err)
	}

	// h1 must be gone.
	_, err = s.LookupByHash(ctx, h1)
	var nfe *usernames.UsernameNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected UsernameNotFoundError for h1, got %T: %v", err, err)
	}

	// h2 must be present.
	got, err := s.LookupByHash(ctx, h2)
	if err != nil {
		t.Fatalf("LookupByHash h2: %v", err)
	}
	if got != acct {
		t.Fatalf("LookupByHash h2: got %q, want %q", got, acct)
	}
}

// ---- LookupByHash ------------------------------------------------------

func TestUsernames_LookupByHash_MissingHash_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	_, err := s.LookupByHash(context.Background(), randHash(t))
	var nfe *usernames.UsernameNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected UsernameNotFoundError, got %T: %v", err, err)
	}
}

func TestUsernames_LookupByHash_ReturnsOwner(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	hash := randHash(t)

	_, tok, err := s.ReserveHash(ctx, acct, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}
	if err := s.ConfirmHash(ctx, acct, hash, tok); err != nil {
		t.Fatalf("ConfirmHash: %v", err)
	}

	got, err := s.LookupByHash(ctx, hash)
	if err != nil {
		t.Fatalf("LookupByHash: %v", err)
	}
	if got != acct {
		t.Fatalf("LookupByHash: got %q, want %q", got, acct)
	}
}

// ---- DeleteHash --------------------------------------------------------

func TestUsernames_DeleteHash_ClearsBothConfirmedAndReserved(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	hash := randHash(t)

	_, tok, err := s.ReserveHash(ctx, acct, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}
	if err := s.ConfirmHash(ctx, acct, hash, tok); err != nil {
		t.Fatalf("ConfirmHash: %v", err)
	}

	// Re-reserve with a second hash to also have a pending reservation.
	h2 := randHash(t)
	if _, _, err := s.ReserveHash(ctx, acct, [][]byte{h2}); err != nil {
		t.Fatalf("ReserveHash h2: %v", err)
	}

	if err := s.DeleteHash(ctx, acct); err != nil {
		t.Fatalf("DeleteHash: %v", err)
	}

	// Confirmed row must be gone.
	_, err = s.LookupByHash(ctx, hash)
	var nfe *usernames.UsernameNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected UsernameNotFoundError after delete, got %T: %v", err, err)
	}

	// Reserved row must be gone: a fresh reserve should succeed for the same hash.
	if _, _, err := s.ReserveHash(ctx, acct, [][]byte{h2}); err != nil {
		t.Fatalf("ReserveHash after DeleteHash should succeed: %v", err)
	}
}

func TestUsernames_DeleteHash_Idempotent(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	if err := s.DeleteHash(ctx, acct); err != nil {
		t.Fatalf("DeleteHash on empty account: %v", err)
	}
	// Second call also must not error.
	if err := s.DeleteHash(ctx, acct); err != nil {
		t.Fatalf("DeleteHash idempotent: %v", err)
	}
}

// ---- SetLink / GetLink / DeleteLink ------------------------------------

func TestUsernames_SetLink_GetLink_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	link := &usernames.UsernameLink{
		UUID:               uuid.NewString(),
		UsernameLinkHandle: uuid.NewString(),
		EncryptedUsername:  []byte("encrypted-payload"),
	}

	if err := s.SetLink(ctx, link); err != nil {
		t.Fatalf("SetLink: %v", err)
	}

	got, err := s.GetLink(ctx, link.UsernameLinkHandle)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.UUID != link.UUID ||
		got.UsernameLinkHandle != link.UsernameLinkHandle ||
		string(got.EncryptedUsername) != string(link.EncryptedUsername) {
		t.Fatalf("GetLink roundtrip mismatch: got %+v, want %+v", got, link)
	}
}

func TestUsernames_SetLink_ReplacesExistingLinkForSameUUID(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	oldHandle := uuid.NewString()
	newHandle := uuid.NewString()

	link1 := &usernames.UsernameLink{
		UUID:               acct,
		UsernameLinkHandle: oldHandle,
		EncryptedUsername:  []byte("old-payload"),
	}
	if err := s.SetLink(ctx, link1); err != nil {
		t.Fatalf("SetLink #1: %v", err)
	}

	link2 := &usernames.UsernameLink{
		UUID:               acct,
		UsernameLinkHandle: newHandle,
		EncryptedUsername:  []byte("new-payload"),
	}
	if err := s.SetLink(ctx, link2); err != nil {
		t.Fatalf("SetLink #2: %v", err)
	}

	// Old handle must be gone.
	_, err := s.GetLink(ctx, oldHandle)
	var nfe *usernames.UsernameLinkNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected UsernameLinkNotFoundError for old handle, got %T: %v", err, err)
	}

	// New handle must be present.
	got, err := s.GetLink(ctx, newHandle)
	if err != nil {
		t.Fatalf("GetLink new handle: %v", err)
	}
	if string(got.EncryptedUsername) != "new-payload" {
		t.Fatalf("expected new-payload, got %s", got.EncryptedUsername)
	}
}

func TestUsernames_GetLink_MissingHandle_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	_, err := s.GetLink(context.Background(), uuid.NewString())
	var nfe *usernames.UsernameLinkNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected UsernameLinkNotFoundError, got %T: %v", err, err)
	}
}

func TestUsernames_DeleteLink_RemovesLink(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	handle := uuid.NewString()
	link := &usernames.UsernameLink{
		UUID:               acct,
		UsernameLinkHandle: handle,
		EncryptedUsername:  []byte("payload"),
	}

	if err := s.SetLink(ctx, link); err != nil {
		t.Fatalf("SetLink: %v", err)
	}
	if err := s.DeleteLink(ctx, acct); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}

	_, err := s.GetLink(ctx, handle)
	var nfe *usernames.UsernameLinkNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected UsernameLinkNotFoundError after delete, got %T: %v", err, err)
	}
}

func TestUsernames_DeleteLink_Idempotent(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	if err := s.DeleteLink(ctx, acct); err != nil {
		t.Fatalf("DeleteLink on missing UUID: %v", err)
	}
	if err := s.DeleteLink(ctx, acct); err != nil {
		t.Fatalf("DeleteLink idempotent: %v", err)
	}
}

func TestUsernames_SetLink_NilLink_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	err := s.SetLink(context.Background(), nil)
	var iae *usernames.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError for nil link, got %T: %v", err, err)
	}
}

// TestUsernames_ReserveHash_ExpiredReservation_NotBlockingOtherAccounts
// verifies that an expired reservation by acct1 does not prevent acct2 from
// reserving the same hash.
func TestUsernames_ReserveHash_ExpiredReservation_NotBlockingOtherAccounts(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct1 := uuid.NewString()
	acct2 := uuid.NewString()
	hash := randHash(t)

	if _, _, err := s.ReserveHash(ctx, acct1, [][]byte{hash}); err != nil {
		t.Fatalf("ReserveHash acct1: %v", err)
	}

	expireReservation(ctx, t, c, acct1)

	// acct2 must be able to claim the hash now that acct1's reservation expired.
	chosen, _, err := s.ReserveHash(ctx, acct2, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash acct2 after expiry: %v", err)
	}
	if string(chosen) != string(hash) {
		t.Fatalf("expected acct2 to pick the hash, got %x", chosen)
	}
}

// TestUsernames_ConfirmHash_WrongHash_Rejected checks that presenting the
// right token for a different hash is rejected.
func TestUsernames_ConfirmHash_WrongHash_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct := uuid.NewString()
	hash := randHash(t)
	wrong := randHash(t)

	_, tok, err := s.ReserveHash(ctx, acct, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	err = s.ConfirmHash(ctx, acct, wrong, tok)
	var irte *usernames.InvalidReservationTokenError
	if !errors.As(err, &irte) {
		t.Fatalf("expected InvalidReservationTokenError for wrong hash, got %T: %v", err, err)
	}
}

// TestUsernames_SetLink_EmptyUUID_Rejected exercises the validation guard for
// a link with an empty account UUID.
func TestUsernames_SetLink_EmptyUUID_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	link := &usernames.UsernameLink{
		UUID:               "",
		UsernameLinkHandle: uuid.NewString(),
		EncryptedUsername:  []byte("payload"),
	}
	err := s.SetLink(context.Background(), link)
	var iae *usernames.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError for empty UUID, got %T: %v", err, err)
	}
}

// TestUsernames_SetLink_EmptyHandle_Rejected exercises the validation guard for
// a link with an empty handle.
func TestUsernames_SetLink_EmptyHandle_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	link := &usernames.UsernameLink{
		UUID:               uuid.NewString(),
		UsernameLinkHandle: "",
		EncryptedUsername:  []byte("payload"),
	}
	err := s.SetLink(context.Background(), link)
	var iae *usernames.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError for empty handle, got %T: %v", err, err)
	}
}

// TestUsernames_DeleteLink_NoLink_IsIdempotent verifies that DeleteLink on an
// account with no link returns nil (idempotent — zero rows affected is OK).
func TestUsernames_DeleteLink_NoLink_IsIdempotent(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)

	if err := s.DeleteLink(context.Background(), uuid.NewString()); err != nil {
		t.Fatalf("DeleteLink on account with no link: %v", err)
	}
}

func TestUsernames_LookupByHash_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	c.Close()

	_, err := s.LookupByHash(context.Background(), randHash(t))
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *usernames.UsernameNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not UsernameNotFoundError")
	}
}

func TestUsernames_GetLink_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	c.Close()

	_, err := s.GetLink(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *usernames.UsernameLinkNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not UsernameLinkNotFoundError")
	}
}

func TestUsernames_ReserveHash_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	c.Close()

	_, _, err := s.ReserveHash(context.Background(), uuid.NewString(), [][]byte{randHash(t)})
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestUsernames_ConfirmHash_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	c.Close()

	err := s.ConfirmHash(context.Background(), uuid.NewString(), randHash(t), "token")
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestUsernames_SetLink_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	c.Close()

	link := &usernames.UsernameLink{
		UUID:               uuid.NewString(),
		UsernameLinkHandle: uuid.NewString(),
		EncryptedUsername:  []byte("payload"),
	}
	err := s.SetLink(context.Background(), link)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestUsernames_DeleteHash_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	c.Close()

	err := s.DeleteHash(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestUsernames_DeleteLink_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	c.Close()

	err := s.DeleteLink(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

// TestUsernames_ConfirmHash_HashCollision_ReturnsConflict verifies that
// confirming a hash already held by another account returns UsernameHashConflictError.
func TestUsernames_ConfirmHash_HashCollision_ReturnsConflict(t *testing.T) {
	c := newTestClient(t)
	s := NewUsernameStore(c)
	ctx := context.Background()

	acct1 := uuid.NewString()
	acct2 := uuid.NewString()
	hash := randHash(t)

	// acct1 confirms the hash first.
	_, tok1, err := s.ReserveHash(ctx, acct1, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash acct1: %v", err)
	}
	if err := s.ConfirmHash(ctx, acct1, hash, tok1); err != nil {
		t.Fatalf("ConfirmHash acct1: %v", err)
	}

	// Manually insert a reservation for acct2 with the same hash to bypass
	// the ReserveHash guard and exercise the ConfirmHash collision path.
	tok2, err := newToken()
	if err != nil {
		t.Fatalf("newToken: %v", err)
	}
	_, err = c.Pool().Exec(ctx, `
		INSERT INTO usernames_reserved (account_uuid, username_hash, token, expires_at)
		VALUES ($1, $2, $3, $4)`,
		acct2, hash, tok2, time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("manual insert reservation: %v", err)
	}

	err = s.ConfirmHash(ctx, acct2, hash, tok2)
	var conflict *usernames.UsernameHashConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected UsernameHashConflictError, got %T: %v", err, err)
	}
}
