package qrdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

func newEnvelope(guid string) *messages.Envelope {
	return &messages.Envelope{
		ServerGUID:        guid,
		DestinationUUID:   "u1",
		DestinationDevice: 1,
		Content:           []byte("ciphertext"),
	}
}

func TestMessageStore_Insert_AssignsID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMessageStore(NewFakeKVStore())

	env := newEnvelope("guid-1")
	id, err := s.Insert(ctx, "u1", 1, env)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if id == 0 || env.ID != id {
		t.Fatalf("ID not assigned correctly: returned=%d env.ID=%d", id, env.ID)
	}
}

func TestMessageStore_Insert_NilOrEmpty(t *testing.T) {
	t.Parallel()
	s := NewMessageStore(NewFakeKVStore())
	if _, err := s.Insert(context.Background(), "u1", 1, nil); err == nil {
		t.Fatal("expected error for nil envelope")
	}
	if _, err := s.Insert(context.Background(), "u1", 1, &messages.Envelope{}); err == nil {
		t.Fatal("expected error for empty server GUID")
	}
}

func TestMessageStore_GetMessagesForDevice_ReturnsInsertOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMessageStore(NewFakeKVStore())

	for i := 0; i < 3; i++ {
		env := newEnvelope("guid-" + string(rune('a'+i)))
		if _, err := s.Insert(ctx, "u1", 1, env); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.GetMessagesForDevice(ctx, "u1", 1)
	if err != nil || len(got) != 3 {
		t.Fatalf("GetMessagesForDevice: err=%v len=%d", err, len(got))
	}
	for i := 0; i < len(got)-1; i++ {
		if got[i].ID >= got[i+1].ID {
			t.Fatalf("messages not in insert order: %+v", got)
		}
	}
}

func TestMessageStore_GetMessagesForDevice_Empty(t *testing.T) {
	t.Parallel()
	s := NewMessageStore(NewFakeKVStore())
	got, err := s.GetMessagesForDevice(context.Background(), "u1", 1)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected empty slice, err=%v len=%d", err, len(got))
	}
}

func TestMessageStore_Delete_ByGUID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMessageStore(NewFakeKVStore())

	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("guid-A")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("guid-B")); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(ctx, "u1", "guid-A"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	remaining, _ := s.GetMessagesForDevice(ctx, "u1", 1)
	if len(remaining) != 1 || remaining[0].ServerGUID != "guid-B" {
		t.Fatalf("Delete did not remove guid-A: %+v", remaining)
	}
}

func TestMessageStore_Delete_MissingGUID(t *testing.T) {
	t.Parallel()
	s := NewMessageStore(NewFakeKVStore())
	err := s.Delete(context.Background(), "u1", "absent")
	var mnfe *messages.MessageNotFoundError
	if !errors.As(err, &mnfe) {
		t.Fatalf("expected MessageNotFoundError, got %T: %v", err, err)
	}
}

func TestMessageStore_DeleteForDevice_ClearsQueue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMessageStore(NewFakeKVStore())

	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("b")); err != nil {
		t.Fatal(err)
	}
	// Different device should not be affected.
	if _, err := s.Insert(ctx, "u1", 2, newEnvelope("c")); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteForDevice(ctx, "u1", 1); err != nil {
		t.Fatal(err)
	}
	got1, _ := s.GetMessagesForDevice(ctx, "u1", 1)
	got2, _ := s.GetMessagesForDevice(ctx, "u1", 2)
	if len(got1) != 0 {
		t.Fatalf("device 1 should be empty: %+v", got1)
	}
	if len(got2) != 1 {
		t.Fatalf("device 2 should retain: %+v", got2)
	}
}

func TestMessageStore_DeleteForAccount_ClearsAllDevices(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMessageStore(NewFakeKVStore())

	if _, err := s.Insert(ctx, "u1", 1, newEnvelope("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Insert(ctx, "u1", 2, newEnvelope("b")); err != nil {
		t.Fatal(err)
	}
	// Other account untouched.
	if _, err := s.Insert(ctx, "u2", 1, newEnvelope("c")); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteForAccount(ctx, "u1"); err != nil {
		t.Fatal(err)
	}

	for _, dev := range []uint64{1, 2} {
		got, _ := s.GetMessagesForDevice(ctx, "u1", dev)
		if len(got) != 0 {
			t.Fatalf("u1 device %d should be empty: %+v", dev, got)
		}
	}
	other, _ := s.GetMessagesForDevice(ctx, "u2", 1)
	if len(other) != 1 {
		t.Fatalf("u2 should be retained: %+v", other)
	}
}

// countingKV wraps a KVStore and records how many entries Scan visited
// before the callback returned. Used by the HasMessagesForDevice early-
// exit test to prove we stop on the first hit and never materialise
// every queued envelope.
type countingKV struct {
	KVStore
	scanCallbacks int
}

func (c *countingKV) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	return c.KVStore.Scan(ctx, prefix, func(key string, value []byte) error {
		c.scanCallbacks++
		return fn(key, value)
	})
}

// HasMessagesForDevice must stop after the first hit. Before the fix
// it called List(), which materialised every key under the prefix —
// a 10K-deep queue would allocate 10K strings just to answer "any?".
func TestMessageStore_HasMessagesForDevice_StopsOnFirstHit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &countingKV{KVStore: NewFakeKVStore()}
	s := NewMessageStore(kv)

	for i := 0; i < 25; i++ {
		if _, err := s.Insert(ctx, "u1", 1, newEnvelope(
			"guid-"+time.Duration(i).String())); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}
	kv.scanCallbacks = 0

	has, err := s.HasMessagesForDevice(ctx, "u1", 1)
	if err != nil {
		t.Fatalf("HasMessagesForDevice: %v", err)
	}
	if !has {
		t.Fatal("expected has=true after 25 inserts")
	}
	if kv.scanCallbacks != 1 {
		t.Errorf("Scan visited %d entries; want exactly 1 (early-exit broken)", kv.scanCallbacks)
	}
}

// HasMessagesForDevice returns false (cleanly, no error) when the
// device's queue is empty.
func TestMessageStore_HasMessagesForDevice_EmptyQueue(t *testing.T) {
	t.Parallel()
	s := NewMessageStore(NewFakeKVStore())
	has, err := s.HasMessagesForDevice(context.Background(), "u1", 1)
	if err != nil {
		t.Fatalf("HasMessagesForDevice: %v", err)
	}
	if has {
		t.Error("expected has=false on empty queue")
	}
}

// TestQrdbMessageStore_RemoveExpired_NoOpReturnsZero documents that the
// qrdb backend does not record per-row expires_at and reports a clean zero
// rather than failing the uniform sweep run by RemoveExpiredMessagesWorker.
func TestQrdbMessageStore_RemoveExpired_NoOpReturnsZero(t *testing.T) {
	s := NewMessageStore(NewFakeKVStore())
	n, err := s.RemoveExpired(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("removed = %d; want 0", n)
	}
}
