package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/usernames"
	"log/slog"
)

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
	hash := []byte("confirmhash")
	_, token, err := svc.ReserveHash(context.Background(), "uuid-u02", [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	if err := svc.ConfirmHash(context.Background(), "uuid-u02", hash, token); err != nil {
		t.Fatalf("ConfirmHash: unexpected error: %v", err)
	}
}

func TestUsernameService_ConfirmHash_EmptyUUID(t *testing.T) {
	svc := newTestUsernameService()
	err := svc.ConfirmHash(context.Background(), "", []byte("h"), "tok")
	if err == nil {
		t.Fatal("ConfirmHash: expected error for empty UUID")
	}
}

func TestUsernameService_ConfirmHash_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.confirmErr = errors.New("confirm failure")
	mgr := usernames.NewUsernamesManager(store, slog.Default())
	svc := NewUsernameService(mgr)

	err := svc.ConfirmHash(context.Background(), "uuid-u02", []byte("h"), "tok")
	if err == nil {
		t.Fatal("ConfirmHash: expected error from store")
	}
}

func TestUsernameService_LookupByHash_Success(t *testing.T) {
	svc := newTestUsernameService()
	hash := []byte("lookuphash")
	_, tok, _ := svc.ReserveHash(context.Background(), "uuid-u03", [][]byte{hash})
	_ = svc.ConfirmHash(context.Background(), "uuid-u03", hash, tok)

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
	hash := []byte("deletehash")
	_, tok, _ := svc.ReserveHash(context.Background(), "uuid-u04", [][]byte{hash})
	_ = svc.ConfirmHash(context.Background(), "uuid-u04", hash, tok)

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
	svc := newTestUsernameService()
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
	svc := newTestUsernameService()
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
