package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// TestNewMessageService_InterfaceSatisfaction verifies the concrete type
// satisfies the MessageService interface at compile time.
func TestNewMessageService_InterfaceSatisfaction(t *testing.T) {
	var _ MessageService = (*messageService)(nil)
}

func newTestMessageService() MessageService {
	store := newMockMessageStore()
	mgr := messages.NewMessagesManager(store)
	return NewMessageService(mgr)
}

func newTestEnvelope() *messages.Envelope {
	return &messages.Envelope{
		Type:      messages.EnvelopeTypeCiphertext,
		Timestamp: 1_000_000,
		Content:   []byte("encrypted content"),
		Urgent:    true,
	}
}

func TestMessageService_Insert_Success(t *testing.T) {
	svc := newTestMessageService()
	env := newTestEnvelope()

	if err := svc.Insert(context.Background(), "dest-uuid", 1, env); err != nil {
		t.Fatalf("Insert: unexpected error: %v", err)
	}
	if env.ServerGUID == "" {
		t.Error("Insert: ServerGUID not set by manager")
	}
}

func TestMessageService_Insert_NilEnvelope(t *testing.T) {
	svc := newTestMessageService()
	err := svc.Insert(context.Background(), "dest-uuid", 1, nil)
	if err == nil {
		t.Fatal("Insert: expected error for nil envelope")
	}
}

func TestMessageService_Insert_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.insertErr = errors.New("storage failure")
	mgr := messages.NewMessagesManager(store)
	svc := NewMessageService(mgr)

	err := svc.Insert(context.Background(), "dest-uuid", 1, newTestEnvelope())
	if err == nil {
		t.Fatal("Insert: expected error from store")
	}
}

func TestMessageService_GetMessagesForDevice_Empty(t *testing.T) {
	svc := newTestMessageService()
	envs, err := svc.GetMessagesForDevice(context.Background(), "empty-uuid", 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: unexpected error: %v", err)
	}
	if len(envs) != 0 {
		t.Errorf("GetMessagesForDevice: expected 0, got %d", len(envs))
	}
}

func TestMessageService_GetMessagesForDevice_WithMessages(t *testing.T) {
	svc := newTestMessageService()
	for i := range 3 {
		env := newTestEnvelope()
		env.Timestamp = uint64(i + 1)
		if err := svc.Insert(context.Background(), "recv-uuid", 1, env); err != nil {
			t.Fatalf("Insert[%d]: %v", i, err)
		}
	}

	envs, err := svc.GetMessagesForDevice(context.Background(), "recv-uuid", 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: unexpected error: %v", err)
	}
	if len(envs) != 3 {
		t.Errorf("GetMessagesForDevice: expected 3, got %d", len(envs))
	}
}

func TestMessageService_GetMessagesForDevice_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.getErr = errors.New("db down")
	mgr := messages.NewMessagesManager(store)
	svc := NewMessageService(mgr)

	_, err := svc.GetMessagesForDevice(context.Background(), "uuid", 1)
	if err == nil {
		t.Fatal("GetMessagesForDevice: expected error from store")
	}
}

func TestMessageService_Delete_Success(t *testing.T) {
	svc := newTestMessageService()
	env := newTestEnvelope()
	if err := svc.Insert(context.Background(), "del-uuid", 1, env); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if err := svc.Delete(context.Background(), "del-uuid", env.ServerGUID); err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	remaining, _ := svc.GetMessagesForDevice(context.Background(), "del-uuid", 1)
	if len(remaining) != 0 {
		t.Errorf("Delete: expected 0 remaining, got %d", len(remaining))
	}
}

func TestMessageService_Delete_EmptyGUID(t *testing.T) {
	svc := newTestMessageService()
	err := svc.Delete(context.Background(), "uuid", "")
	if err == nil {
		t.Fatal("Delete: expected error for empty GUID")
	}
}

func TestMessageService_DeleteForDevice_Success(t *testing.T) {
	svc := newTestMessageService()
	for range 2 {
		_ = svc.Insert(context.Background(), "batch-uuid", 1, newTestEnvelope())
	}

	if err := svc.DeleteForDevice(context.Background(), "batch-uuid", 1); err != nil {
		t.Fatalf("DeleteForDevice: unexpected error: %v", err)
	}

	remaining, _ := svc.GetMessagesForDevice(context.Background(), "batch-uuid", 1)
	if len(remaining) != 0 {
		t.Errorf("DeleteForDevice: expected 0, got %d", len(remaining))
	}
}

func TestMessageService_DeleteForDevice_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.deleteErr = errors.New("delete failed")
	mgr := messages.NewMessagesManager(store)
	svc := NewMessageService(mgr)

	err := svc.DeleteForDevice(context.Background(), "uuid", 1)
	if err == nil {
		t.Fatal("DeleteForDevice: expected error from store")
	}
}

func TestMessageService_DeleteForAccount_Success(t *testing.T) {
	svc := newTestMessageService()
	// Insert for two different devices under the same account.
	_ = svc.Insert(context.Background(), "acct-uuid", 1, newTestEnvelope())
	_ = svc.Insert(context.Background(), "acct-uuid", 2, newTestEnvelope())

	if err := svc.DeleteForAccount(context.Background(), "acct-uuid"); err != nil {
		t.Fatalf("DeleteForAccount: unexpected error: %v", err)
	}

	d1, _ := svc.GetMessagesForDevice(context.Background(), "acct-uuid", 1)
	d2, _ := svc.GetMessagesForDevice(context.Background(), "acct-uuid", 2)
	if len(d1) != 0 || len(d2) != 0 {
		t.Errorf("DeleteForAccount: expected 0/0, got %d/%d", len(d1), len(d2))
	}
}

func TestMessageService_DeleteForAccount_StoreError(t *testing.T) {
	store := newMockMessageStore()
	store.deleteErr = errors.New("delete failed")
	mgr := messages.NewMessagesManager(store)
	svc := NewMessageService(mgr)

	err := svc.DeleteForAccount(context.Background(), "uuid")
	if err == nil {
		t.Fatal("DeleteForAccount: expected error from store")
	}
}

func TestMessageService_SetDeliveryCallback(t *testing.T) {
	store := newMockMessageStore()
	mgr := messages.NewMessagesManager(store)
	svc := NewMessageService(mgr)

	var called bool
	svc.SetDeliveryCallback(func(uuid string, deviceID uint64, env *messages.Envelope) {
		called = true
	})

	env := newTestEnvelope()
	if err := svc.Insert(context.Background(), "cb-uuid", 1, env); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if !called {
		t.Error("SetDeliveryCallback: callback not invoked after insert")
	}
}

func TestMessageService_HasMessagesForDevice_Empty(t *testing.T) {
	svc := newTestMessageService()
	has, err := svc.HasMessagesForDevice(context.Background(), "empty-has-uuid", 1)
	if err != nil {
		t.Fatalf("HasMessagesForDevice: unexpected error: %v", err)
	}
	if has {
		t.Error("HasMessagesForDevice: expected false for empty device")
	}
}

func TestMessageService_HasMessagesForDevice_WithMessages(t *testing.T) {
	svc := newTestMessageService()
	if err := svc.Insert(context.Background(), "has-uuid", 1, newTestEnvelope()); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	has, err := svc.HasMessagesForDevice(context.Background(), "has-uuid", 1)
	if err != nil {
		t.Fatalf("HasMessagesForDevice: unexpected error: %v", err)
	}
	if !has {
		t.Error("HasMessagesForDevice: expected true after insert")
	}
}

func TestMessageService_SendMRMBinary_NoCache(t *testing.T) {
	svc := newTestMessageService()
	req := messages.MRMSendRequest{}
	_, err := svc.SendMRMBinary(context.Background(), req)
	// Without a cache configured this should return ErrMRMNoCache.
	if err == nil {
		t.Fatal("SendMRMBinary: expected error when no MRM cache is set")
	}
}

func TestMessageService_SetMRMCache_Nil(t *testing.T) {
	svc := newTestMessageService()
	// Setting nil should not panic and should leave the cache unset.
	svc.SetMRMCache(nil)
}

func TestMessageService_RemoveExpired_NoOp(t *testing.T) {
	svc := newTestMessageService()
	n, err := svc.RemoveExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RemoveExpired: unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("RemoveExpired: expected 0 removed from memory store, got %d", n)
	}
}
