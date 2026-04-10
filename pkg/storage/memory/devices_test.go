package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/devices"
)

// --- NewMemoryProvisioningStore tests ---

func TestNewMemoryProvisioningStore(t *testing.T) {
	store := NewMemoryProvisioningStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.sessions == nil {
		t.Fatal("expected sessions map to be initialized")
	}
}

func TestNewMemoryProvisioningStoreEmptyMap(t *testing.T) {
	store := NewMemoryProvisioningStore()
	if len(store.sessions) != 0 {
		t.Fatalf("expected empty sessions map, got %d entries", len(store.sessions))
	}
}

// --- StoreSession tests ---

func TestProvisioningStore_StoreSession(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	session := &devices.ProvisioningSession{
		Code:      "test-code",
		UUID:      "test-uuid",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	err := store.StoreSession(ctx, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSession(ctx, "test-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Code != "test-code" {
		t.Fatalf("expected Code %q, got %q", "test-code", got.Code)
	}
	if got.UUID != "test-uuid" {
		t.Fatalf("expected UUID %q, got %q", "test-uuid", got.UUID)
	}
}

func TestProvisioningStore_StoreSessionOverwrite(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	session1 := &devices.ProvisioningSession{
		Code:      "code-1",
		UUID:      "uuid-1",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, session1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session2 := &devices.ProvisioningSession{
		Code:      "code-1",
		UUID:      "uuid-2",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	if err := store.StoreSession(ctx, session2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSession(ctx, "code-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-2" {
		t.Fatalf("expected UUID %q after overwrite, got %q", "uuid-2", got.UUID)
	}
}

func TestProvisioningStore_StoreSessionDeepCopy(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	session := &devices.ProvisioningSession{
		Code:      "code-dc",
		UUID:      "uuid-dc",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate original.
	session.UUID = "mutated-uuid"

	got, err := store.GetSession(ctx, "code-dc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID == "mutated-uuid" {
		t.Fatal("mutation of original affected stored data")
	}
}

func TestProvisioningStore_StoreSessionMultiple(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		code := "code-" + string(rune('a'+i))
		session := &devices.ProvisioningSession{
			Code:      code,
			UUID:      "uuid-" + string(rune('a'+i)),
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		if err := store.StoreSession(ctx, session); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if len(store.sessions) != 5 {
		t.Fatalf("expected 5 sessions, got %d", len(store.sessions))
	}
}

// --- GetSession tests ---

func TestProvisioningStore_GetSession(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	session := &devices.ProvisioningSession{
		Code:      "get-code",
		UUID:      "get-uuid",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSession(ctx, "get-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Code != "get-code" {
		t.Fatalf("expected Code %q, got %q", "get-code", got.Code)
	}
	if got.UUID != "get-uuid" {
		t.Fatalf("expected UUID %q, got %q", "get-uuid", got.UUID)
	}
	if got.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero ExpiresAt")
	}
}

func TestProvisioningStore_GetSessionNotFound(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	_, err := store.GetSession(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}

	invErr, ok := err.(*devices.InvalidProvisioningCodeError)
	if !ok {
		t.Fatalf("expected *InvalidProvisioningCodeError, got %T", err)
	}
	if invErr.Code != "nonexistent" {
		t.Fatalf("expected Code %q, got %q", "nonexistent", invErr.Code)
	}
}

func TestProvisioningStore_GetSessionDeepCopy(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	session := &devices.ProvisioningSession{
		Code:      "code-gdc",
		UUID:      "uuid-gdc",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSession(ctx, "code-gdc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate returned value.
	got.UUID = "mutated"

	got2, err := store.GetSession(ctx, "code-gdc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.UUID == "mutated" {
		t.Fatal("mutation of returned value affected stored data")
	}
}

func TestProvisioningStore_GetSessionPreservesExpiration(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	expires := time.Now().Add(7 * time.Minute)
	session := &devices.ProvisioningSession{
		Code:      "code-exp",
		UUID:      "uuid-exp",
		ExpiresAt: expires,
	}
	if err := store.StoreSession(ctx, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSession(ctx, "code-exp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Fatalf("expected ExpiresAt %v, got %v", expires, got.ExpiresAt)
	}
}

// --- DeleteSession tests ---

func TestProvisioningStore_DeleteSession(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	session := &devices.ProvisioningSession{
		Code:      "del-code",
		UUID:      "del-uuid",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := store.DeleteSession(ctx, "del-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = store.GetSession(ctx, "del-code")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestProvisioningStore_DeleteSessionIdempotent(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	// Delete a session that does not exist. Should not error.
	err := store.DeleteSession(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("expected no error for idempotent delete, got: %v", err)
	}
}

func TestProvisioningStore_DeleteSessionDoesNotAffectOthers(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	s1 := &devices.ProvisioningSession{Code: "code-1", UUID: "uuid-1", ExpiresAt: time.Now().Add(10 * time.Minute)}
	s2 := &devices.ProvisioningSession{Code: "code-2", UUID: "uuid-2", ExpiresAt: time.Now().Add(10 * time.Minute)}

	if err := store.StoreSession(ctx, s1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreSession(ctx, s2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteSession(ctx, "code-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// code-2 should still exist.
	got, err := store.GetSession(ctx, "code-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-2" {
		t.Fatalf("expected UUID %q, got %q", "uuid-2", got.UUID)
	}
}

func TestProvisioningStore_DeleteSessionThenReuse(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	session := &devices.ProvisioningSession{
		Code:      "reuse-code",
		UUID:      "uuid-1",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, session); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.DeleteSession(ctx, "reuse-code"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Re-store with same code but different UUID.
	session2 := &devices.ProvisioningSession{
		Code:      "reuse-code",
		UUID:      "uuid-2",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, session2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSession(ctx, "reuse-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-2" {
		t.Fatalf("expected UUID %q, got %q", "uuid-2", got.UUID)
	}
}

// --- Concurrency tests ---

func TestProvisioningStoreConcurrentStoreAndGet(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			code := "code-conc-" + string(rune('A'+idx))
			session := &devices.ProvisioningSession{
				Code:      code,
				UUID:      "uuid-conc-" + string(rune('A'+idx)),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			}
			_ = store.StoreSession(ctx, session)
		}(i)
		go func(idx int) {
			defer wg.Done()
			code := "code-conc-" + string(rune('A'+idx))
			_, _ = store.GetSession(ctx, code)
		}(i)
	}
	wg.Wait()
}

func TestProvisioningStoreConcurrentStoreAndDelete(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	// Pre-populate.
	for i := 0; i < 10; i++ {
		code := "code-cd-" + string(rune('A'+i))
		session := &devices.ProvisioningSession{
			Code:      code,
			UUID:      "uuid-cd-" + string(rune('A'+i)),
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		if err := store.StoreSession(ctx, session); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			code := "code-cd-" + string(rune('A'+idx))
			_ = store.DeleteSession(ctx, code)
		}(i)
		go func(idx int) {
			defer wg.Done()
			code := "code-cd-new-" + string(rune('A'+idx))
			session := &devices.ProvisioningSession{
				Code:      code,
				UUID:      "uuid-cd-new-" + string(rune('A'+idx)),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			}
			_ = store.StoreSession(ctx, session)
		}(i)
	}
	wg.Wait()
}

// --- cloneSession / MutationIsolation tests ---

// TestMemoryProvisioningStore_MutationIsolation verifies that cloneSession
// produces a true deep copy so that mutating the original struct after a
// StoreSession call does not corrupt the stored data. It also checks the
// symmetric direction: mutating the pointer returned by GetSession must not
// affect the data returned by a subsequent GetSession call.
func TestMemoryProvisioningStore_MutationIsolation(t *testing.T) {
	store := NewMemoryProvisioningStore()
	ctx := context.Background()

	original := &devices.ProvisioningSession{
		Code:      "iso-code",
		UUID:      "original-uuid",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.StoreSession(ctx, original); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the original pointer AFTER storing.
	original.UUID = "mutated-after-store"

	// The store must still hold the value at the time of the StoreSession call.
	retrieved, err := store.GetSession(ctx, "iso-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if retrieved.UUID != "original-uuid" {
		t.Errorf("expected stored UUID %q, got %q (mutation of original leaked into store)", "original-uuid", retrieved.UUID)
	}

	// Mutating the retrieved pointer must not affect a second retrieval.
	retrieved.UUID = "mutated-retrieved"

	retrieved2, err := store.GetSession(ctx, "iso-code")
	if err != nil {
		t.Fatalf("unexpected error on second get: %v", err)
	}
	if retrieved2.UUID != "original-uuid" {
		t.Errorf("expected stored UUID %q, got %q (mutation of returned value leaked into store)", "original-uuid", retrieved2.UUID)
	}
}

// --- Interface satisfaction ---

func TestMemoryProvisioningStoreImplementsInterface(t *testing.T) {
	var _ devices.ProvisioningStore = (*MemoryProvisioningStore)(nil)
}

func TestMemoryProvisioningStoreInterfaceNonNil(t *testing.T) {
	var store devices.ProvisioningStore = NewMemoryProvisioningStore()
	_ = store
}
