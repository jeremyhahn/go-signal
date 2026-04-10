package usernames

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
)

// discardWriter is an io.Writer that discards all output.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(
		discardWriter{}, &slog.HandlerOptions{Level: slog.LevelDebug},
	))
}

// mockUsernameStore is an in-memory implementation of UsernameStore for testing.
type mockUsernameStore struct {
	mu           sync.Mutex
	reservations map[string]*UsernameReservation // uuid -> reservation
	confirmed    map[string]string               // hex(hash) -> uuid
	links        map[string]*UsernameLink        // handle -> link
	linksByUUID  map[string]*UsernameLink        // uuid -> link

	reserveErr error
	confirmErr error
	lookupErr  error
	deleteErr  error
	setLinkErr error
	getLinkErr error
	delLinkErr error
}

func newMockUsernameStore() *mockUsernameStore {
	return &mockUsernameStore{
		reservations: make(map[string]*UsernameReservation),
		confirmed:    make(map[string]string),
		links:        make(map[string]*UsernameLink),
		linksByUUID:  make(map[string]*UsernameLink),
	}
}

func (s *mockUsernameStore) ReserveHash(_ context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reserveErr != nil {
		return nil, "", s.reserveErr
	}
	token := "reservation-token-" + uuid
	s.reservations[uuid] = &UsernameReservation{
		UUID:             uuid,
		UsernameHashes:   hashes,
		ReservationToken: token,
	}
	return hashes[0], token, nil
}

func (s *mockUsernameStore) ConfirmHash(_ context.Context, uuid string, hash []byte, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.confirmErr != nil {
		return s.confirmErr
	}
	s.confirmed[string(hash)] = uuid
	return nil
}

func (s *mockUsernameStore) LookupByHash(_ context.Context, hash []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lookupErr != nil {
		return "", s.lookupErr
	}
	uuid, ok := s.confirmed[string(hash)]
	if !ok {
		return "", &UsernameNotFoundError{Hash: hash}
	}
	return uuid, nil
}

func (s *mockUsernameStore) DeleteHash(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	for k, v := range s.confirmed {
		if v == uuid {
			delete(s.confirmed, k)
			break
		}
	}
	return nil
}

func (s *mockUsernameStore) SetLink(_ context.Context, link *UsernameLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setLinkErr != nil {
		return s.setLinkErr
	}
	s.links[link.UsernameLinkHandle] = link
	s.linksByUUID[link.UUID] = link
	return nil
}

func (s *mockUsernameStore) GetLink(_ context.Context, handle string) (*UsernameLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getLinkErr != nil {
		return nil, s.getLinkErr
	}
	link, ok := s.links[handle]
	if !ok {
		return nil, &UsernameLinkNotFoundError{Handle: handle}
	}
	return link, nil
}

func (s *mockUsernameStore) DeleteLink(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delLinkErr != nil {
		return s.delLinkErr
	}
	link, ok := s.linksByUUID[uuid]
	if ok {
		delete(s.links, link.UsernameLinkHandle)
		delete(s.linksByUUID, uuid)
	}
	return nil
}

func TestNewUsernamesManager(t *testing.T) {
	t.Run("creates manager", func(t *testing.T) {
		store := newMockUsernameStore()
		m := NewUsernamesManager(store, newTestLogger())
		if m == nil {
			t.Fatal("expected non-nil manager")
		}
	})

	t.Run("stores references", func(t *testing.T) {
		store := newMockUsernameStore()
		logger := newTestLogger()
		m := NewUsernamesManager(store, logger)
		if m.store != store {
			t.Error("store not set correctly")
		}
		if m.logger != logger {
			t.Error("logger not set correctly")
		}
	})
}

func TestReserveHash_Success(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	hashes := [][]byte{{1, 2, 3}, {4, 5, 6}}
	hash, token, err := m.ReserveHash(ctx, "uuid-1", hashes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) == 0 {
		t.Error("expected non-empty hash")
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
}

func TestReserveHash_EmptyUUID(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, _, err := m.ReserveHash(ctx, "", [][]byte{{1}})
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "uuid" {
		t.Errorf("Field = %q, want %q", target.Field, "uuid")
	}
}

func TestReserveHash_EmptyHashes(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, _, err := m.ReserveHash(ctx, "uuid-1", [][]byte{})
	if err == nil {
		t.Fatal("expected error for empty hashes")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "hashes" {
		t.Errorf("Field = %q, want %q", target.Field, "hashes")
	}
}

func TestReserveHash_NilHashes(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, _, err := m.ReserveHash(ctx, "uuid-1", nil)
	if err == nil {
		t.Fatal("expected error for nil hashes")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestReserveHash_EmptyHashInSlice(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	hashes := [][]byte{{1, 2}, {}, {3, 4}}
	_, _, err := m.ReserveHash(ctx, "uuid-1", hashes)
	if err == nil {
		t.Fatal("expected error for empty hash element")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestReserveHash_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.reserveErr = errors.New("store failure")
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, _, err := m.ReserveHash(ctx, "uuid-1", [][]byte{{1}})
	if err == nil {
		t.Fatal("expected error from store")
	}
	if err.Error() != "store failure" {
		t.Errorf("error = %q, want %q", err.Error(), "store failure")
	}
}

func TestConfirmHash_Success(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.ConfirmHash(ctx, "uuid-1", []byte{1, 2, 3}, "token-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfirmHash_EmptyUUID(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.ConfirmHash(ctx, "", []byte{1}, "token")
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "uuid" {
		t.Errorf("Field = %q, want %q", target.Field, "uuid")
	}
}

func TestConfirmHash_EmptyHash(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.ConfirmHash(ctx, "uuid-1", []byte{}, "token")
	if err == nil {
		t.Fatal("expected error for empty hash")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "hash" {
		t.Errorf("Field = %q, want %q", target.Field, "hash")
	}
}

func TestConfirmHash_NilHash(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.ConfirmHash(ctx, "uuid-1", nil, "token")
	if err == nil {
		t.Fatal("expected error for nil hash")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestConfirmHash_EmptyToken(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.ConfirmHash(ctx, "uuid-1", []byte{1}, "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "token" {
		t.Errorf("Field = %q, want %q", target.Field, "token")
	}
}

func TestConfirmHash_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.confirmErr = errors.New("confirm failure")
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.ConfirmHash(ctx, "uuid-1", []byte{1}, "token")
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestLookupByHash_Success(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	// First confirm a hash.
	hashBytes := []byte{10, 20, 30}
	if err := m.ConfirmHash(ctx, "uuid-lookup", hashBytes, "token"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	uuid, err := m.LookupByHash(ctx, hashBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uuid != "uuid-lookup" {
		t.Errorf("uuid = %q, want %q", uuid, "uuid-lookup")
	}
}

func TestLookupByHash_EmptyHash(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, err := m.LookupByHash(ctx, []byte{})
	if err == nil {
		t.Fatal("expected error for empty hash")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestLookupByHash_NilHash(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, err := m.LookupByHash(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil hash")
	}
}

func TestLookupByHash_NotFound(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, err := m.LookupByHash(ctx, []byte{99, 99, 99})
	if err == nil {
		t.Fatal("expected error for non-existent hash")
	}
	var target *UsernameNotFoundError
	if !errors.As(err, &target) {
		t.Fatalf("expected *UsernameNotFoundError, got %T", err)
	}
}

func TestDeleteHash_Success(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	if err := m.DeleteHash(ctx, "uuid-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteHash_EmptyUUID(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.DeleteHash(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestDeleteHash_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.deleteErr = errors.New("delete failure")
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.DeleteHash(ctx, "uuid-1")
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestSetLink_Success(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	link := &UsernameLink{
		UUID:               "uuid-link",
		UsernameLinkHandle: "handle-1",
		EncryptedUsername:  []byte{1, 2, 3},
	}
	if err := m.SetLink(ctx, link); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetLink_NilLink(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.SetLink(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil link")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "link" {
		t.Errorf("Field = %q, want %q", target.Field, "link")
	}
}

func TestSetLink_EmptyUUID(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	link := &UsernameLink{
		UUID:               "",
		UsernameLinkHandle: "handle",
		EncryptedUsername:  []byte{1},
	}
	err := m.SetLink(ctx, link)
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestSetLink_EmptyHandle(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	link := &UsernameLink{
		UUID:               "uuid",
		UsernameLinkHandle: "",
		EncryptedUsername:  []byte{1},
	}
	err := m.SetLink(ctx, link)
	if err == nil {
		t.Fatal("expected error for empty handle")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "usernameLinkHandle" {
		t.Errorf("Field = %q, want %q", target.Field, "usernameLinkHandle")
	}
}

func TestSetLink_EmptyEncryptedUsername(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	link := &UsernameLink{
		UUID:               "uuid",
		UsernameLinkHandle: "handle",
		EncryptedUsername:  []byte{},
	}
	err := m.SetLink(ctx, link)
	if err == nil {
		t.Fatal("expected error for empty encrypted username")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
	if target.Field != "encryptedUsername" {
		t.Errorf("Field = %q, want %q", target.Field, "encryptedUsername")
	}
}

func TestSetLink_NilEncryptedUsername(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	link := &UsernameLink{
		UUID:               "uuid",
		UsernameLinkHandle: "handle",
		EncryptedUsername:  nil,
	}
	err := m.SetLink(ctx, link)
	if err == nil {
		t.Fatal("expected error for nil encrypted username")
	}
}

func TestSetLink_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.setLinkErr = errors.New("set link failure")
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	link := &UsernameLink{
		UUID:               "uuid",
		UsernameLinkHandle: "handle",
		EncryptedUsername:  []byte{1},
	}
	err := m.SetLink(ctx, link)
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestGetLink_Success(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	original := &UsernameLink{
		UUID:               "uuid-get",
		UsernameLinkHandle: "handle-get",
		EncryptedUsername:  []byte{7, 8, 9},
	}
	if err := m.SetLink(ctx, original); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	link, err := m.GetLink(ctx, "handle-get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if link.UUID != "uuid-get" {
		t.Errorf("UUID = %q, want %q", link.UUID, "uuid-get")
	}
}

func TestGetLink_EmptyHandle(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, err := m.GetLink(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty handle")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestGetLink_NotFound(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, err := m.GetLink(ctx, "nonexistent-handle")
	if err == nil {
		t.Fatal("expected error for non-existent link")
	}
	var target *UsernameLinkNotFoundError
	if !errors.As(err, &target) {
		t.Fatalf("expected *UsernameLinkNotFoundError, got %T", err)
	}
}

func TestGetLink_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.getLinkErr = errors.New("get link failure")
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	_, err := m.GetLink(ctx, "handle")
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestDeleteLink_Success(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	if err := m.DeleteLink(ctx, "uuid-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteLink_EmptyUUID(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.DeleteLink(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestDeleteLink_StoreError(t *testing.T) {
	store := newMockUsernameStore()
	store.delLinkErr = errors.New("delete link failure")
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	err := m.DeleteLink(ctx, "uuid-1")
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestReserveAndConfirmAndLookup_Integration(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	hashes := [][]byte{{0xAA, 0xBB}}
	hash, token, err := m.ReserveHash(ctx, "uuid-int", hashes)
	if err != nil {
		t.Fatalf("ReserveHash failed: %v", err)
	}

	if err := m.ConfirmHash(ctx, "uuid-int", hash, token); err != nil {
		t.Fatalf("ConfirmHash failed: %v", err)
	}

	uuid, err := m.LookupByHash(ctx, hash)
	if err != nil {
		t.Fatalf("LookupByHash failed: %v", err)
	}
	if uuid != "uuid-int" {
		t.Errorf("uuid = %q, want %q", uuid, "uuid-int")
	}
}

func TestSetAndGetAndDeleteLink_Integration(t *testing.T) {
	store := newMockUsernameStore()
	m := NewUsernamesManager(store, newTestLogger())
	ctx := context.Background()

	link := &UsernameLink{
		UUID:               "uuid-int2",
		UsernameLinkHandle: "handle-int2",
		EncryptedUsername:  []byte{0xCC, 0xDD},
	}

	if err := m.SetLink(ctx, link); err != nil {
		t.Fatalf("SetLink failed: %v", err)
	}

	got, err := m.GetLink(ctx, "handle-int2")
	if err != nil {
		t.Fatalf("GetLink failed: %v", err)
	}
	if got.UUID != "uuid-int2" {
		t.Errorf("UUID = %q, want %q", got.UUID, "uuid-int2")
	}

	if err := m.DeleteLink(ctx, "uuid-int2"); err != nil {
		t.Fatalf("DeleteLink failed: %v", err)
	}

	_, err = m.GetLink(ctx, "handle-int2")
	if err == nil {
		t.Fatal("expected error after deleting link")
	}
}
