package service

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"

	libsignalusernames "github.com/jeremyhahn/go-libsignal/pkg/usernames"

	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// validHashAndProof returns a 32-byte username hash and a matching ZK proof
// suitable for ConfirmHash tests. Mirrors the helper in pkg/usernames/manager_test.go.
func validHashAndProof(t *testing.T) ([]byte, []byte) {
	t.Helper()
	u, err := libsignalusernames.FromParts("svctest", "01", libsignalusernames.DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("FromParts: %v", err)
	}
	hash := u.Hash()
	var randomness [32]byte
	if _, err := rand.Read(randomness[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	proof, err := u.Proof(randomness)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	out := make([]byte, 32)
	copy(out, hash[:])
	return out, proof
}

// dummyProof returns 64 arbitrary bytes that are the right size for a ZK
// proof but won't verify against any hash. Useful for tests that only need
// non-empty proof bytes to clear the input-validation check.
func dummyProof() []byte {
	out := make([]byte, 64)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// TestNewUsernameService_InterfaceSatisfaction verifies the concrete type
// satisfies the UsernameService interface at compile time.
func TestNewUsernameService_InterfaceSatisfaction(t *testing.T) {
	var _ UsernameService = (*usernameService)(nil)
}

func newTestUsernameService() UsernameService {
	store := newMockUsernameStore()
	mgr := usernames.NewUsernamesManager(store, slog.Default())
	return NewUsernameService(mgr)
}

// newTestUsernameServiceWithConfirmedHash returns a UsernameService whose
// backing store already has a confirmed hash recorded for the supplied UUID.
// SetLink now requires the precondition; tests that exercise the link surface
// without going through the full ConfirmHash flow use this fixture.
func newTestUsernameServiceWithConfirmedHash(uuid string) UsernameService {
	store := newMockUsernameStore()
	store.hashes[uuid] = []byte("seed-hash-" + uuid)
	mgr := usernames.NewUsernamesManager(store, slog.Default())
	return NewUsernameService(mgr)
}

func TestUsernameService_ReserveHash_Success(t *testing.T) {
	svc := newTestUsernameService()
	hashes := [][]byte{[]byte("hash1"), []byte("hash2")}

	hash, token, err := svc.ReserveHash(context.Background(), "uuid-u01", hashes)
	if err != nil {
		t.Fatalf("ReserveHash: unexpected error: %v", err)
	}
	if len(hash) == 0 {
		t.Error("ReserveHash: expected a hash")
	}
	if token == "" {
		t.Error("ReserveHash: expected a token")
	}
}

func TestUsernameService_ReserveHash_EmptyUUID(t *testing.T) {
	svc := newTestUsernameService()
	_, _, err := svc.ReserveHash(context.Background(), "", [][]byte{[]byte("h")})
	if err == nil {
		t.Fatal("ReserveHash: expected error for empty UUID")
	}
}

func TestUsernameService_ReserveHash_EmptyHashes(t *testing.T) {
	svc := newTestUsernameService()
	_, _, err := svc.ReserveHash(context.Background(), "uuid-u01", nil)
	if err == nil {
		t.Fatal("ReserveHash: expected error for nil hashes")
	}
}

func TestUsernameService_ReserveHash_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.reserveErr = errors.New("reserve failure")
	mgr := usernames.NewUsernamesManager(store, slog.Default())
	svc := NewUsernameService(mgr)

	_, _, err := svc.ReserveHash(context.Background(), "uuid-u01", [][]byte{[]byte("h")})
	if err == nil {
		t.Fatal("ReserveHash: expected error from store")
	}
}

func TestUsernameService_ConfirmHash_Success(t *testing.T) {
	svc := newTestUsernameService()
	hash, proof := validHashAndProof(t)
	_, token, err := svc.ReserveHash(context.Background(), "uuid-u02", [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	if err := svc.ConfirmHash(context.Background(), "uuid-u02", hash, token, proof); err != nil {
		t.Fatalf("ConfirmHash: unexpected error: %v", err)
	}
}

func TestUsernameService_ConfirmHash_EmptyUUID(t *testing.T) {
	svc := newTestUsernameService()
	err := svc.ConfirmHash(context.Background(), "", []byte("h"), "tok", dummyProof())
	if err == nil {
		t.Fatal("ConfirmHash: expected error for empty UUID")
	}
}

func TestUsernameService_ConfirmHash_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.confirmErr = errors.New("confirm failure")
	mgr := usernames.NewUsernamesManager(store, slog.Default())
	svc := NewUsernameService(mgr)
	hash, proof := validHashAndProof(t)

	err := svc.ConfirmHash(context.Background(), "uuid-u02", hash, "tok", proof)
	if err == nil {
		t.Fatal("ConfirmHash: expected error from store")
	}
}

func TestUsernameService_LookupByHash_Success(t *testing.T) {
	svc := newTestUsernameService()
	hash, proof := validHashAndProof(t)
	_, tok, _ := svc.ReserveHash(context.Background(), "uuid-u03", [][]byte{hash})
	_ = svc.ConfirmHash(context.Background(), "uuid-u03", hash, tok, proof)

	found, err := svc.LookupByHash(context.Background(), hash)
	if err != nil {
		t.Fatalf("LookupByHash: unexpected error: %v", err)
	}
	if found != "uuid-u03" {
		t.Errorf("LookupByHash: expected uuid-u03, got %q", found)
	}
}

func TestUsernameService_LookupByHash_NotFound(t *testing.T) {
	svc := newTestUsernameService()
	_, err := svc.LookupByHash(context.Background(), []byte("unknownhash"))
	if err == nil {
		t.Fatal("LookupByHash: expected error for missing hash")
	}
}

func TestUsernameService_LookupByHash_EmptyHash(t *testing.T) {
	svc := newTestUsernameService()
	_, err := svc.LookupByHash(context.Background(), nil)
	if err == nil {
		t.Fatal("LookupByHash: expected error for nil hash")
	}
}

func TestUsernameService_DeleteHash_Success(t *testing.T) {
	svc := newTestUsernameService()
	hash, proof := validHashAndProof(t)
	_, tok, _ := svc.ReserveHash(context.Background(), "uuid-u04", [][]byte{hash})
	_ = svc.ConfirmHash(context.Background(), "uuid-u04", hash, tok, proof)

	if err := svc.DeleteHash(context.Background(), "uuid-u04"); err != nil {
		t.Fatalf("DeleteHash: unexpected error: %v", err)
	}

	_, err := svc.LookupByHash(context.Background(), hash)
	if err == nil {
		t.Fatal("DeleteHash: hash still accessible after deletion")
	}
}

func TestUsernameService_DeleteHash_EmptyUUID(t *testing.T) {
	svc := newTestUsernameService()
	err := svc.DeleteHash(context.Background(), "")
	if err == nil {
		t.Fatal("DeleteHash: expected error for empty UUID")
	}
}

func TestUsernameService_SetLink_Success(t *testing.T) {
	svc := newTestUsernameServiceWithConfirmedHash("uuid-u05")
	link := &usernames.UsernameLink{
		UUID:               "uuid-u05",
		UsernameLinkHandle: "handle-abc",
		EncryptedUsername:  []byte("encrypted"),
	}

	if err := svc.SetLink(context.Background(), link); err != nil {
		t.Fatalf("SetLink: unexpected error: %v", err)
	}
}

func TestUsernameService_SetLink_NilLink(t *testing.T) {
	svc := newTestUsernameService()
	err := svc.SetLink(context.Background(), nil)
	if err == nil {
		t.Fatal("SetLink: expected error for nil link")
	}
}

func TestUsernameService_GetLink_Success(t *testing.T) {
	svc := newTestUsernameServiceWithConfirmedHash("uuid-u06")
	link := &usernames.UsernameLink{
		UUID:               "uuid-u06",
		UsernameLinkHandle: "handle-get",
		EncryptedUsername:  []byte("encrypted-val"),
	}
	if err := svc.SetLink(context.Background(), link); err != nil {
		t.Fatalf("SetLink: %v", err)
	}

	got, err := svc.GetLink(context.Background(), "handle-get")
	if err != nil {
		t.Fatalf("GetLink: unexpected error: %v", err)
	}
	if string(got.EncryptedUsername) != "encrypted-val" {
		t.Errorf("GetLink: EncryptedUsername mismatch")
	}
}

func TestUsernameService_GetLink_NotFound(t *testing.T) {
	svc := newTestUsernameService()
	_, err := svc.GetLink(context.Background(), "missing-handle")
	if err == nil {
		t.Fatal("GetLink: expected error for missing handle")
	}
}

func TestUsernameService_GetLink_EmptyHandle(t *testing.T) {
	svc := newTestUsernameService()
	_, err := svc.GetLink(context.Background(), "")
	if err == nil {
		t.Fatal("GetLink: expected error for empty handle")
	}
}

func TestUsernameService_DeleteLink_Success(t *testing.T) {
	svc := newTestUsernameService()
	link := &usernames.UsernameLink{
		UUID:               "uuid-u07",
		UsernameLinkHandle: "handle-del",
		EncryptedUsername:  []byte("enc"),
	}
	_ = svc.SetLink(context.Background(), link)

	if err := svc.DeleteLink(context.Background(), "uuid-u07"); err != nil {
		t.Fatalf("DeleteLink: unexpected error: %v", err)
	}

	_, err := svc.GetLink(context.Background(), "handle-del")
	if err == nil {
		t.Fatal("DeleteLink: link still accessible after deletion")
	}
}

func TestUsernameService_DeleteLink_EmptyUUID(t *testing.T) {
	svc := newTestUsernameService()
	err := svc.DeleteLink(context.Background(), "")
	if err == nil {
		t.Fatal("DeleteLink: expected error for empty UUID")
	}
}

func TestUsernameService_DeleteExpiredReservations_NoOp(t *testing.T) {
	svc := newTestUsernameService()
	n, err := svc.DeleteExpiredReservations(context.Background())
	if err != nil {
		t.Fatalf("DeleteExpiredReservations: unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("DeleteExpiredReservations: expected 0 deleted, got %d", n)
	}
}

func TestUsernameService_DeleteExpiredReservations_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.deleteExpiredErr = errors.New("sweep failure")
	mgr := usernames.NewUsernamesManager(store, slog.Default())
	svc := NewUsernameService(mgr)

	_, err := svc.DeleteExpiredReservations(context.Background())
	if err == nil {
		t.Fatal("DeleteExpiredReservations: expected error from store")
	}
}

func TestUsernameService_ExistingLinkHandle_Found(t *testing.T) {
	svc := newTestUsernameServiceWithConfirmedHash("uuid-u10")
	link := &usernames.UsernameLink{
		UUID:               "uuid-u10",
		UsernameLinkHandle: "handle-existing",
		EncryptedUsername:  []byte("enc"),
	}
	if err := svc.SetLink(context.Background(), link); err != nil {
		t.Fatalf("SetLink: %v", err)
	}

	handle, err := svc.ExistingLinkHandle(context.Background(), "uuid-u10")
	if err != nil {
		t.Fatalf("ExistingLinkHandle: unexpected error: %v", err)
	}
	if handle != "handle-existing" {
		t.Errorf("ExistingLinkHandle: expected %q, got %q", "handle-existing", handle)
	}
}

func TestUsernameService_ExistingLinkHandle_NotFound(t *testing.T) {
	svc := newTestUsernameService()
	_, err := svc.ExistingLinkHandle(context.Background(), "uuid-no-link")
	if err == nil {
		t.Fatal("ExistingLinkHandle: expected error when no link exists")
	}
}

func TestUsernameService_ExistingLinkHandle_EmptyUUID(t *testing.T) {
	svc := newTestUsernameService()
	_, err := svc.ExistingLinkHandle(context.Background(), "")
	if err == nil {
		t.Fatal("ExistingLinkHandle: expected error for empty UUID")
	}
}
