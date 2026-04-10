package memory

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

func testEnvelope(serverGUID string) *messages.Envelope {
	return &messages.Envelope{
		Type:            messages.EnvelopeTypeCiphertext,
		SourceUUID:      "source-uuid",
		SourceDevice:    1,
		Timestamp:       1000,
		ServerTimestamp: 2000,
		Content:         []byte("encrypted-content"),
		ServerGUID:      serverGUID,
		Urgent:          true,
		Story:           false,
		ReportSpamToken: []byte("spam-token"),
	}
}

func TestNewMemoryMessageStore(t *testing.T) {
	store := NewMemoryMessageStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.byDevice == nil {
		t.Fatal("expected byDevice map to be initialized")
	}
	if store.byGUID == nil {
		t.Fatal("expected byGUID map to be initialized")
	}
}

func TestNewMemoryMessageStoreEmptyMaps(t *testing.T) {
	store := NewMemoryMessageStore()
	if len(store.byDevice) != 0 {
		t.Fatalf("expected empty byDevice, got %d", len(store.byDevice))
	}
	if len(store.byGUID) != 0 {
		t.Fatalf("expected empty byGUID, got %d", len(store.byGUID))
	}
}

func TestInsert(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	env := testEnvelope("guid-1")
	id, err := store.Insert(ctx, "dest-uuid", 1, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero ID")
	}
}

func TestInsertAssignsIncrementingIDs(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	id1, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	id2, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-2"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id2 <= id1 {
		t.Fatalf("expected id2 > id1, got id1=%d id2=%d", id1, id2)
	}
}

func TestInsertSetsDestinationFields(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	env := testEnvelope("guid-1")
	if _, err := store.Insert(ctx, "dest-uuid", 5, env); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, err := store.GetMessagesForDevice(ctx, "dest-uuid", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].DestinationUUID != "dest-uuid" {
		t.Fatalf("expected DestinationUUID %q, got %q", "dest-uuid", msgs[0].DestinationUUID)
	}
	if msgs[0].DestinationDevice != 5 {
		t.Fatalf("expected DestinationDevice 5, got %d", msgs[0].DestinationDevice)
	}
}

func TestInsertDeepCopy(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	env := testEnvelope("guid-dc")
	if _, err := store.Insert(ctx, "dest-uuid", 1, env); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate original.
	env.Content[0] = 0xFF

	msgs, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgs[0].Content[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
}

func TestInsertWithEmptyServerGUID(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	env := testEnvelope("")
	id, err := store.Insert(ctx, "dest-uuid", 1, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero ID")
	}

	// Should not be in GUID index.
	if len(store.byGUID) != 0 {
		t.Fatalf("expected empty GUID index for empty ServerGUID, got %d", len(store.byGUID))
	}
}

func TestGetMessagesForDevice(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		env := testEnvelope("guid-" + string(rune('a'+i)))
		if _, err := store.Insert(ctx, "dest-uuid", 1, env); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	msgs, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
}

func TestGetMessagesForDeviceEmpty(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	msgs, err := store.GetMessagesForDevice(ctx, "nonexistent", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages, got %d", len(msgs))
	}
}

func TestGetMessagesForDeviceDeepCopy(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs[0].Content[0] = 0xFF

	msgs2, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msgs2[0].Content[0] == 0xFF {
		t.Fatal("mutation of returned message affected stored data")
	}
}

func TestGetMessagesForDeviceIsolation(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "uuid-1", 1, testEnvelope("guid-1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := store.Insert(ctx, "uuid-1", 2, testEnvelope("guid-2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs1, err := store.GetMessagesForDevice(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs1) != 1 {
		t.Fatalf("expected 1 message for device 1, got %d", len(msgs1))
	}

	msgs2, err := store.GetMessagesForDevice(ctx, "uuid-1", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs2) != 1 {
		t.Fatalf("expected 1 message for device 2, got %d", len(msgs2))
	}
}

func TestMessageStore_Delete(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-del")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := store.Delete(ctx, "dest-uuid", "guid-del")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages after delete, got %d", len(msgs))
	}
}

func TestMessageStore_DeleteNotFound(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	err := store.Delete(ctx, "dest-uuid", "nonexistent-guid")
	if err == nil {
		t.Fatal("expected error for nonexistent GUID")
	}

	se, ok := err.(*errors.SignalError)
	if !ok {
		t.Fatalf("expected *errors.SignalError, got %T", err)
	}
	if se.Code != errors.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", se.Code)
	}
}

func TestDeleteWrongAccount(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "uuid-owner", 1, testEnvelope("guid-wrong")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := store.Delete(ctx, "uuid-other", "guid-wrong")
	if err == nil {
		t.Fatal("expected error for wrong account UUID")
	}

	se, ok := err.(*errors.SignalError)
	if !ok {
		t.Fatalf("expected *errors.SignalError, got %T", err)
	}
	if se.Code != errors.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", se.Code)
	}
}

func TestDeleteMiddleMessage(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-a")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-b")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-c")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.Delete(ctx, "dest-uuid", "guid-b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages after deleting middle, got %d", len(msgs))
	}
	if msgs[0].ServerGUID != "guid-a" {
		t.Fatalf("expected first message guid-a, got %q", msgs[0].ServerGUID)
	}
	if msgs[1].ServerGUID != "guid-c" {
		t.Fatalf("expected second message guid-c, got %q", msgs[1].ServerGUID)
	}
}

func TestDeleteForDevice(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := store.Insert(ctx, "dest-uuid", 2, testEnvelope("guid-3")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteForDevice(ctx, "dest-uuid", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs1, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs1) != 0 {
		t.Fatalf("expected 0 messages for device 1, got %d", len(msgs1))
	}

	// Device 2 should be unaffected.
	msgs2, err := store.GetMessagesForDevice(ctx, "dest-uuid", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs2) != 1 {
		t.Fatalf("expected 1 message for device 2, got %d", len(msgs2))
	}
}

func TestDeleteForDeviceCleansGUIDIndex(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-indexed")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteForDevice(ctx, "dest-uuid", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GUID index should be cleaned up.
	store.mu.RLock()
	_, exists := store.byGUID["guid-indexed"]
	store.mu.RUnlock()
	if exists {
		t.Fatal("expected GUID index to be cleaned up after device delete")
	}
}

func TestDeleteForDeviceNonexistent(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	err := store.DeleteForDevice(ctx, "nonexistent", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteForAccount(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "uuid-del", 1, testEnvelope("guid-1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := store.Insert(ctx, "uuid-del", 2, testEnvelope("guid-2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := store.Insert(ctx, "uuid-other", 1, testEnvelope("guid-3")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteForAccount(ctx, "uuid-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs1, _ := store.GetMessagesForDevice(ctx, "uuid-del", 1)
	msgs2, _ := store.GetMessagesForDevice(ctx, "uuid-del", 2)
	if len(msgs1) != 0 || len(msgs2) != 0 {
		t.Fatal("expected all messages for account to be deleted")
	}

	// Other account should be unaffected.
	msgsOther, _ := store.GetMessagesForDevice(ctx, "uuid-other", 1)
	if len(msgsOther) != 1 {
		t.Fatalf("expected 1 message for uuid-other, got %d", len(msgsOther))
	}
}

func TestDeleteForAccountCleansGUIDIndex(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	if _, err := store.Insert(ctx, "uuid-del", 1, testEnvelope("guid-acct")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteForAccount(ctx, "uuid-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	store.mu.RLock()
	_, exists := store.byGUID["guid-acct"]
	store.mu.RUnlock()
	if exists {
		t.Fatal("expected GUID index to be cleaned up after account delete")
	}
}

func TestDeleteForAccountNonexistent(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	err := store.DeleteForAccount(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteForAccountWithEmptyGUID(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	env := testEnvelope("")
	if _, err := store.Insert(ctx, "uuid-eg", 1, env); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := store.DeleteForAccount(ctx, "uuid-eg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCloneEnvelope(t *testing.T) {
	original := testEnvelope("guid-clone")
	clone := cloneEnvelope(original)

	if clone.ServerGUID != original.ServerGUID {
		t.Fatalf("expected ServerGUID %q, got %q", original.ServerGUID, clone.ServerGUID)
	}
	if clone.Type != original.Type {
		t.Fatalf("expected Type %d, got %d", original.Type, clone.Type)
	}

	clone.Content[0] = 0xFF
	if original.Content[0] == 0xFF {
		t.Fatal("clone mutation affected original Content")
	}

	clone.ReportSpamToken[0] = 0xAA
	if original.ReportSpamToken[0] == 0xAA {
		t.Fatal("clone mutation affected original ReportSpamToken")
	}
}

func TestCloneEnvelopeNilFields(t *testing.T) {
	original := &messages.Envelope{
		Type:            messages.EnvelopeTypeReceipt,
		ServerGUID:      "guid-nil",
		Content:         nil,
		ReportSpamToken: nil,
	}
	clone := cloneEnvelope(original)
	if clone.Content != nil {
		t.Fatal("expected nil Content on clone")
	}
	if clone.ReportSpamToken != nil {
		t.Fatal("expected nil ReportSpamToken on clone")
	}
}

func TestCloneEnvelopePreservesScalarFields(t *testing.T) {
	original := &messages.Envelope{
		ID:                42,
		Type:              messages.EnvelopeTypeUnidentifiedSender,
		SourceUUID:        "src",
		SourceDevice:      3,
		DestinationUUID:   "dst",
		DestinationDevice: 7,
		Timestamp:         1111,
		ServerTimestamp:   2222,
		ServerGUID:        "guid-scalar",
		Urgent:            true,
		Story:             true,
		Content:           []byte("c"),
		ReportSpamToken:   []byte("s"),
	}
	clone := cloneEnvelope(original)

	if clone.ID != 42 {
		t.Fatalf("expected ID 42, got %d", clone.ID)
	}
	if clone.Type != messages.EnvelopeTypeUnidentifiedSender {
		t.Fatalf("expected Type %d, got %d", messages.EnvelopeTypeUnidentifiedSender, clone.Type)
	}
	if clone.SourceUUID != "src" {
		t.Fatalf("expected SourceUUID %q, got %q", "src", clone.SourceUUID)
	}
	if clone.SourceDevice != 3 {
		t.Fatalf("expected SourceDevice 3, got %d", clone.SourceDevice)
	}
	if !clone.Urgent || !clone.Story {
		t.Fatal("expected Urgent and Story to be true")
	}
}

func TestDeviceKeyStruct(t *testing.T) {
	k1 := deviceKey{uuid: "uuid-1", deviceID: 1}
	k2 := deviceKey{uuid: "uuid-1", deviceID: 1}
	k3 := deviceKey{uuid: "uuid-1", deviceID: 2}

	if k1 != k2 {
		t.Fatal("expected equal device keys to be comparable")
	}
	if k1 == k3 {
		t.Fatal("expected different device keys to not be equal")
	}
}

func TestDeviceKeyDifferentUUID(t *testing.T) {
	k1 := deviceKey{uuid: "uuid-a", deviceID: 1}
	k2 := deviceKey{uuid: "uuid-b", deviceID: 1}

	if k1 == k2 {
		t.Fatal("expected different UUIDs to produce different keys")
	}
}

func TestMessageStoreConcurrentInsert(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	const n = 50

	ids := make([]uint64, n)
	mu := sync.Mutex{}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			guid := "guid-conc-" + string(rune('A'+idx%26)) + string(rune('0'+idx/26))
			id, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope(guid))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			mu.Lock()
			ids[idx] = id
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// All IDs should be unique.
	seen := make(map[uint64]bool)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate ID: %d", id)
		}
		seen[id] = true
	}
}

func TestMessageStoreConcurrentInsertAndRead(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			guid := "guid-cr-" + string(rune('A'+idx))
			_, _ = store.Insert(ctx, "dest-uuid", 1, testEnvelope(guid))
		}(i)
		go func() {
			defer wg.Done()
			_, _ = store.GetMessagesForDevice(ctx, "dest-uuid", 1)
		}()
	}
	wg.Wait()
}

func TestInsertAndDeleteMultipleMessages(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	guids := []string{"guid-m1", "guid-m2", "guid-m3", "guid-m4", "guid-m5"}
	for _, guid := range guids {
		if _, err := store.Insert(ctx, "dest-uuid", 1, testEnvelope(guid)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Delete first and last.
	if err := store.Delete(ctx, "dest-uuid", "guid-m1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.Delete(ctx, "dest-uuid", "guid-m5"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, err := store.GetMessagesForDevice(ctx, "dest-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}

	expected := []string{"guid-m2", "guid-m3", "guid-m4"}
	for i, msg := range msgs {
		if msg.ServerGUID != expected[i] {
			t.Fatalf("expected GUID %q at index %d, got %q", expected[i], i, msg.ServerGUID)
		}
	}
}

func TestInsertPreservesContent(t *testing.T) {
	store := NewMemoryMessageStore()
	ctx := context.Background()

	env := &messages.Envelope{
		Type:            messages.EnvelopeTypePrekeyBundle,
		Content:         []byte{0x01, 0x02, 0x03},
		ServerGUID:      "guid-content",
		ReportSpamToken: []byte{0xAA, 0xBB},
	}

	if _, err := store.Insert(ctx, "dest", 1, env); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msgs, err := store.GetMessagesForDevice(ctx, "dest", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(msgs[0].Content, []byte{0x01, 0x02, 0x03}) {
		t.Fatal("Content not preserved")
	}
	if !bytes.Equal(msgs[0].ReportSpamToken, []byte{0xAA, 0xBB}) {
		t.Fatal("ReportSpamToken not preserved")
	}
}
