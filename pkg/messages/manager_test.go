package messages

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// mockMessageStore is an in-memory MessageStore for testing.
type mockMessageStore struct {
	mu       sync.Mutex
	messages map[string][]*Envelope // key: "uuid:deviceID"
	nextID   atomic.Uint64

	// Error injection hooks
	insertErr    error
	getErr       error
	deleteErr    error
	deleteDevErr error
	deleteAccErr error
}

func newMockMessageStore() *mockMessageStore {
	return &mockMessageStore{
		messages: make(map[string][]*Envelope),
	}
}

func msgDeviceKey(uuid string, deviceID uint64) string {
	return fmt.Sprintf("%s:%d", uuid, deviceID)
}

func (s *mockMessageStore) Insert(_ context.Context, destinationUUID string, destinationDevice uint64, envelope *Envelope) (uint64, error) {
	if s.insertErr != nil {
		return 0, s.insertErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID.Add(1)
	envelope.ID = id
	k := msgDeviceKey(destinationUUID, destinationDevice)
	s.messages[k] = append(s.messages[k], envelope)
	return id, nil
}

func (s *mockMessageStore) GetMessagesForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) ([]*Envelope, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := msgDeviceKey(destinationUUID, destinationDevice)
	msgs := s.messages[k]
	result := make([]*Envelope, len(msgs))
	copy(result, msgs)
	return result, nil
}

func (s *mockMessageStore) HasMessagesForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) (bool, error) {
	if s.getErr != nil {
		return false, s.getErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages[msgDeviceKey(destinationUUID, destinationDevice)]) > 0, nil
}

func (s *mockMessageStore) Delete(_ context.Context, destinationUUID string, serverGUID string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, msgs := range s.messages {
		for i, m := range msgs {
			if m.ServerGUID == serverGUID && m.DestinationUUID == destinationUUID {
				s.messages[k] = append(msgs[:i], msgs[i+1:]...)
				return nil
			}
		}
	}
	return nil
}

func (s *mockMessageStore) DeleteForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) error {
	if s.deleteDevErr != nil {
		return s.deleteDevErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.messages, msgDeviceKey(destinationUUID, destinationDevice))
	return nil
}

func (s *mockMessageStore) DeleteForAccount(_ context.Context, uuid string) error {
	if s.deleteAccErr != nil {
		return s.deleteAccErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.messages {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.messages, k)
		}
	}
	return nil
}

func (s *mockMessageStore) RemoveExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

// --- NewMessagesManager tests ---

func TestNewMessagesManager_ReturnsNonNil(t *testing.T) {
	mgr := NewMessagesManager(newMockMessageStore())
	if mgr == nil {
		t.Fatal("expected non-nil MessagesManager")
	}
}

func TestNewMessagesManager_StoresReference(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)
	if mgr.store != store {
		t.Fatal("expected manager to hold reference to provided store")
	}
}

// --- SetDeliveryCallback tests ---

func TestSetDeliveryCallback_SetsCallback(t *testing.T) {
	mgr := NewMessagesManager(newMockMessageStore())
	// Before setting, loading the atomic value returns nil.
	if h, ok := mgr.deliveryCallback.Load().(*deliveryCallbackHolder); ok && h != nil {
		t.Fatal("expected nil callback initially")
	}
	called := false
	mgr.SetDeliveryCallback(func(uuid string, deviceID uint64, envelope *Envelope) {
		called = true
	})
	h, ok := mgr.deliveryCallback.Load().(*deliveryCallbackHolder)
	if !ok || h == nil || h.fn == nil {
		t.Fatal("expected non-nil callback after setting")
	}
	h.fn("test", 1, &Envelope{})
	if !called {
		t.Error("expected callback to be invoked")
	}
}

func TestSetDeliveryCallback_CanOverwrite(t *testing.T) {
	mgr := NewMessagesManager(newMockMessageStore())
	count := 0
	mgr.SetDeliveryCallback(func(string, uint64, *Envelope) { count += 1 })
	mgr.SetDeliveryCallback(func(string, uint64, *Envelope) { count += 10 })
	h, ok := mgr.deliveryCallback.Load().(*deliveryCallbackHolder)
	if !ok || h == nil || h.fn == nil {
		t.Fatal("expected non-nil callback after overwrite")
	}
	h.fn("", 0, nil)
	if count != 10 {
		t.Errorf("expected count 10 from overwritten callback, got %d", count)
	}
}

// --- Insert tests ---

func TestInsert_Success(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)
	env := &Envelope{
		Type:    EnvelopeTypeCiphertext,
		Content: []byte{0x01},
	}
	err := mgr.Insert(context.Background(), "dst-uuid", 1, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.ServerGUID == "" {
		t.Error("expected ServerGUID to be set")
	}
	if env.ServerTimestamp == 0 {
		t.Error("expected ServerTimestamp to be set")
	}
	if env.DestinationUUID != "dst-uuid" {
		t.Errorf("expected DestinationUUID 'dst-uuid', got %q", env.DestinationUUID)
	}
}

// TestInsert_PreservesCallerProvidedGUID covers the loop-detector send-path
// invariant: when the handler pre-assigns a ServerGUID so the loop detector
// can Check the same value it later Records, the manager must NOT overwrite
// it during Insert.
func TestInsert_PreservesCallerProvidedGUID(t *testing.T) {
	mgr := NewMessagesManager(newMockMessageStore())
	const preassigned = "11111111-2222-3333-4444-555555555555"
	env := &Envelope{
		Type:       EnvelopeTypeCiphertext,
		Content:    []byte{0x01},
		ServerGUID: preassigned,
	}
	if err := mgr.Insert(context.Background(), "dst-uuid", 1, env); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if env.ServerGUID != preassigned {
		t.Errorf("ServerGUID = %q; want preserved %q", env.ServerGUID, preassigned)
	}
}

func TestInsert_NilEnvelope(t *testing.T) {
	mgr := NewMessagesManager(newMockMessageStore())
	err := mgr.Insert(context.Background(), "dst-uuid", 1, nil)
	if err == nil {
		t.Fatal("expected error for nil envelope")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %d", sigErr.Code)
	}
}

func TestInsert_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.insertErr = errors.New("insert failure")
	mgr := NewMessagesManager(store)
	env := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}

	err := mgr.Insert(context.Background(), "dst-uuid", 1, env)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
	if sigErr.Cause == nil {
		t.Error("expected wrapped cause")
	}
}

func TestInsert_CallbackInvoked(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	var cbUUID string
	var cbDeviceID uint64
	var cbEnvelope *Envelope
	mgr.SetDeliveryCallback(func(uuid string, deviceID uint64, envelope *Envelope) {
		cbUUID = uuid
		cbDeviceID = deviceID
		cbEnvelope = envelope
	})

	env := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	err := mgr.Insert(context.Background(), "dst-uuid", 5, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cbUUID != "dst-uuid" {
		t.Errorf("expected callback uuid 'dst-uuid', got %q", cbUUID)
	}
	if cbDeviceID != 5 {
		t.Errorf("expected callback deviceID 5, got %d", cbDeviceID)
	}
	if cbEnvelope != env {
		t.Error("expected callback to receive the same envelope pointer")
	}
}

func TestInsert_NoCallbackRegistered(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)
	env := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}

	err := mgr.Insert(context.Background(), "dst-uuid", 1, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInsert_CallbackNotInvokedOnStoreError(t *testing.T) {
	store := newMockMessageStore()
	store.insertErr = errors.New("insert failure")
	mgr := NewMessagesManager(store)

	called := false
	mgr.SetDeliveryCallback(func(string, uint64, *Envelope) { called = true })

	env := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	_ = mgr.Insert(context.Background(), "dst-uuid", 1, env)

	if called {
		t.Error("callback should not be invoked on store error")
	}
}

func TestInsert_SetsUniqueServerGUIDs(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	env1 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	env2 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x02}}

	if err := mgr.Insert(context.Background(), "dst", 1, env1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mgr.Insert(context.Background(), "dst", 1, env2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if env1.ServerGUID == env2.ServerGUID {
		t.Errorf("expected unique ServerGUIDs, both are %q", env1.ServerGUID)
	}
}

// --- GetMessagesForDevice tests ---

func TestGetMessagesForDevice_Success(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	env1 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	env2 := &Envelope{Type: EnvelopeTypePrekeyBundle, Content: []byte{0x02}}
	if err := mgr.Insert(context.Background(), "dst", 1, env1); err != nil {
		t.Fatalf("failed to insert env1: %v", err)
	}
	if err := mgr.Insert(context.Background(), "dst", 1, env2); err != nil {
		t.Fatalf("failed to insert env2: %v", err)
	}

	msgs, err := mgr.GetMessagesForDevice(context.Background(), "dst", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
}

func TestGetMessagesForDevice_Empty(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	msgs, err := mgr.GetMessagesForDevice(context.Background(), "nonexistent", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestGetMessagesForDevice_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.getErr = errors.New("get failure")
	mgr := NewMessagesManager(store)

	_, err := mgr.GetMessagesForDevice(context.Background(), "dst", 1)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

func TestGetMessagesForDevice_DeviceIsolation(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	env1 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	env2 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x02}}
	if err := mgr.Insert(context.Background(), "dst", 1, env1); err != nil {
		t.Fatalf("failed to insert env1: %v", err)
	}
	if err := mgr.Insert(context.Background(), "dst", 2, env2); err != nil {
		t.Fatalf("failed to insert env2: %v", err)
	}

	msgs1, _ := mgr.GetMessagesForDevice(context.Background(), "dst", 1)
	msgs2, _ := mgr.GetMessagesForDevice(context.Background(), "dst", 2)

	if len(msgs1) != 1 {
		t.Errorf("expected 1 message for device 1, got %d", len(msgs1))
	}
	if len(msgs2) != 1 {
		t.Errorf("expected 1 message for device 2, got %d", len(msgs2))
	}
}

// --- Delete tests ---

func TestDelete_Success(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	env := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	if err := mgr.Insert(context.Background(), "dst", 1, env); err != nil {
		t.Fatalf("failed to insert envelope: %v", err)
	}
	guid := env.ServerGUID

	err := mgr.Delete(context.Background(), "dst", guid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, _ := mgr.GetMessagesForDevice(context.Background(), "dst", 1)
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages after delete, got %d", len(msgs))
	}
}

func TestDelete_EmptyGUID(t *testing.T) {
	mgr := NewMessagesManager(newMockMessageStore())
	err := mgr.Delete(context.Background(), "dst", "")
	if err == nil {
		t.Fatal("expected error for empty GUID")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %d", sigErr.Code)
	}
}

func TestDelete_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.deleteErr = errors.New("delete failure")
	mgr := NewMessagesManager(store)

	err := mgr.Delete(context.Background(), "dst", "some-guid")
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

func TestDelete_Idempotent(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	// Delete a nonexistent message - should not error (idempotent)
	err := mgr.Delete(context.Background(), "dst", "nonexistent-guid")
	if err != nil {
		t.Fatalf("expected idempotent delete, got error: %v", err)
	}
}

// --- DeleteForDevice tests ---

func TestDeleteForDevice_Success(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	env1 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	env2 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x02}}
	if err := mgr.Insert(context.Background(), "dst", 1, env1); err != nil {
		t.Fatalf("failed to insert env1: %v", err)
	}
	if err := mgr.Insert(context.Background(), "dst", 1, env2); err != nil {
		t.Fatalf("failed to insert env2: %v", err)
	}

	err := mgr.DeleteForDevice(context.Background(), "dst", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, _ := mgr.GetMessagesForDevice(context.Background(), "dst", 1)
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages after device delete, got %d", len(msgs))
	}
}

func TestDeleteForDevice_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.deleteDevErr = errors.New("device delete failure")
	mgr := NewMessagesManager(store)

	err := mgr.DeleteForDevice(context.Background(), "dst", 1)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

func TestDeleteForDevice_DoesNotAffectOtherDevices(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	env1 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	env2 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x02}}
	if err := mgr.Insert(context.Background(), "dst", 1, env1); err != nil {
		t.Fatalf("failed to insert env1: %v", err)
	}
	if err := mgr.Insert(context.Background(), "dst", 2, env2); err != nil {
		t.Fatalf("failed to insert env2: %v", err)
	}

	if err := mgr.DeleteForDevice(context.Background(), "dst", 1); err != nil {
		t.Fatalf("failed to delete for device: %v", err)
	}

	msgs, _ := mgr.GetMessagesForDevice(context.Background(), "dst", 2)
	if len(msgs) != 1 {
		t.Errorf("expected 1 message for device 2 after deleting device 1, got %d", len(msgs))
	}
}

// --- DeleteForAccount tests ---

func TestDeleteForAccount_Success(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	env1 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	env2 := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x02}}
	if err := mgr.Insert(context.Background(), "dst", 1, env1); err != nil {
		t.Fatalf("failed to insert env1: %v", err)
	}
	if err := mgr.Insert(context.Background(), "dst", 2, env2); err != nil {
		t.Fatalf("failed to insert env2: %v", err)
	}

	err := mgr.DeleteForAccount(context.Background(), "dst")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs1, _ := mgr.GetMessagesForDevice(context.Background(), "dst", 1)
	msgs2, _ := mgr.GetMessagesForDevice(context.Background(), "dst", 2)
	if len(msgs1)+len(msgs2) != 0 {
		t.Errorf("expected 0 total messages after account delete, got %d", len(msgs1)+len(msgs2))
	}
}

func TestDeleteForAccount_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.deleteAccErr = errors.New("account delete failure")
	mgr := NewMessagesManager(store)

	err := mgr.DeleteForAccount(context.Background(), "dst")
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

func TestDeleteForAccount_DoesNotAffectOtherAccounts(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	envA := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x01}}
	envB := &Envelope{Type: EnvelopeTypeCiphertext, Content: []byte{0x02}}
	if err := mgr.Insert(context.Background(), "acct-A", 1, envA); err != nil {
		t.Fatalf("failed to insert envA: %v", err)
	}
	if err := mgr.Insert(context.Background(), "acct-B", 1, envB); err != nil {
		t.Fatalf("failed to insert envB: %v", err)
	}

	if err := mgr.DeleteForAccount(context.Background(), "acct-A"); err != nil {
		t.Fatalf("failed to delete for account: %v", err)
	}

	msgsB, _ := mgr.GetMessagesForDevice(context.Background(), "acct-B", 1)
	if len(msgsB) != 1 {
		t.Errorf("expected 1 message for acct-B, got %d", len(msgsB))
	}
}

// --- HasMessagesForDevice ---

func TestHasMessagesForDevice_NoMessages(t *testing.T) {
	mgr := NewMessagesManager(newMockMessageStore())
	has, err := mgr.HasMessagesForDevice(context.Background(), "uuid-empty", 1)
	if err != nil {
		t.Fatalf("HasMessagesForDevice: %v", err)
	}
	if has {
		t.Error("expected false for device with no messages")
	}
}

func TestHasMessagesForDevice_WithMessages(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)
	ctx := context.Background()

	if err := mgr.Insert(ctx, "uuid-has", 1, &Envelope{
		Type:    EnvelopeTypeCiphertext,
		Content: []byte{0x01},
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	has, err := mgr.HasMessagesForDevice(ctx, "uuid-has", 1)
	if err != nil {
		t.Fatalf("HasMessagesForDevice: %v", err)
	}
	if !has {
		t.Error("expected true for device with messages")
	}
}

func TestHasMessagesForDevice_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.getErr = errors.New("store error")
	mgr := NewMessagesManager(store)

	_, err := mgr.HasMessagesForDevice(context.Background(), "uuid-err", 1)
	if err == nil {
		t.Fatal("expected error from store")
	}
}

// --- RemoveExpired ---

func TestRemoveExpired_NoExpired(t *testing.T) {
	store := newMockMessageStore()
	mgr := NewMessagesManager(store)

	n, err := mgr.RemoveExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 removed, got %d", n)
	}
}

func TestRemoveExpired_StoreError(t *testing.T) {
	ms := &mockRemoveExpiredStore{removeErr: errors.New("remove error")}
	mgr := NewMessagesManager(ms)

	_, err := mgr.RemoveExpired(context.Background(), time.Now())
	if err == nil {
		t.Fatal("expected error from store")
	}
}

// mockRemoveExpiredStore extends mockMessageStore to inject RemoveExpired errors.
type mockRemoveExpiredStore struct {
	mockMessageStore
	removeErr error
}

func (s *mockRemoveExpiredStore) RemoveExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, s.removeErr
}
