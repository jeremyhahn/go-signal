package keys

import (
	"context"
	"testing"
)

// TestPreKeyStore_Interface verifies the mockPreKeyStore satisfies the PreKeyStore interface.
func TestPreKeyStore_InterfaceSatisfaction(t *testing.T) {
	var _ PreKeyStore = (*mockPreKeyStore)(nil)
}

func TestPreKeyStore_StoreAndTakeECPreKeys(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	preKeys := []*PreKey{
		{KeyID: 1, PublicKey: []byte{0x01}},
		{KeyID: 2, PublicKey: []byte{0x02}},
	}
	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, preKeys); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pk, err := store.TakeEC(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.KeyID != 1 {
		t.Errorf("expected KeyID 1, got %d", pk.KeyID)
	}

	pk2, err := store.TakeEC(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk2.KeyID != 2 {
		t.Errorf("expected KeyID 2, got %d", pk2.KeyID)
	}

	_, err = store.TakeEC(ctx, "uuid-1", 1)
	if err == nil {
		t.Fatal("expected error when no EC keys remain")
	}
}

func TestPreKeyStore_StoreAndTakeKEMPreKeys(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	preKeys := []*KEMSignedPreKey{
		{KeyID: 10, PublicKey: []byte{0x10}, Signature: []byte{0x11}},
	}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, preKeys); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pk, err := store.TakeKEM(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.KeyID != 10 {
		t.Errorf("expected KeyID 10, got %d", pk.KeyID)
	}

	_, err = store.TakeKEM(ctx, "uuid-1", 1)
	if err == nil {
		t.Fatal("expected error when no KEM keys remain")
	}
}

func TestPreKeyStore_StoreAndGetSignedPreKey(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	spk := &SignedPreKey{KeyID: 5, PublicKey: []byte{0x05}, Signature: []byte{0x06}}
	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, spk); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KeyID != 5 {
		t.Errorf("expected KeyID 5, got %d", got.KeyID)
	}
}

func TestPreKeyStore_GetSignedPreKey_NotFound(t *testing.T) {
	store := newMockPreKeyStore()
	_, err := store.GetSignedPreKey(context.Background(), "nonexistent", 1)
	if err == nil {
		t.Fatal("expected error for nonexistent signed pre-key")
	}
}

func TestPreKeyStore_GetPreKeyCount(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*PreKey{{KeyID: 1}, {KeyID: 2}}); err != nil {
		t.Fatalf("failed to store EC pre-keys: %v", err)
	}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, []*KEMSignedPreKey{{KeyID: 10}}); err != nil {
		t.Fatalf("failed to store KEM pre-keys: %v", err)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 2 {
		t.Errorf("expected ECCount 2, got %d", state.ECCount)
	}
	if state.KEMCount != 1 {
		t.Errorf("expected KEMCount 1, got %d", state.KEMCount)
	}
}

func TestPreKeyStore_GetPreKeyCount_Empty(t *testing.T) {
	store := newMockPreKeyStore()
	state, err := store.GetPreKeyCount(context.Background(), "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 0 || state.KEMCount != 0 {
		t.Errorf("expected zero counts, got EC=%d KEM=%d", state.ECCount, state.KEMCount)
	}
}

func TestPreKeyStore_DeleteAllForDevice(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*PreKey{{KeyID: 1}}); err != nil {
		t.Fatalf("failed to store EC pre-keys: %v", err)
	}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, []*KEMSignedPreKey{{KeyID: 10}}); err != nil {
		t.Fatalf("failed to store KEM pre-keys: %v", err)
	}
	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, &SignedPreKey{KeyID: 5}); err != nil {
		t.Fatalf("failed to store signed pre-key: %v", err)
	}

	if err := store.DeleteAllForDevice(ctx, "uuid-1", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, _ := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if state.ECCount != 0 || state.KEMCount != 0 {
		t.Errorf("expected zero counts after delete, got EC=%d KEM=%d", state.ECCount, state.KEMCount)
	}
	_, err := store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err == nil {
		t.Error("expected error getting signed pre-key after delete")
	}
}

func TestPreKeyStore_DeleteAllForDevice_Nonexistent(t *testing.T) {
	store := newMockPreKeyStore()
	err := store.DeleteAllForDevice(context.Background(), "nonexistent", 1)
	if err != nil {
		t.Fatalf("delete of nonexistent device should not error, got %v", err)
	}
}

func TestPreKeyStore_DeleteAllForAccount(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*PreKey{{KeyID: 1}}); err != nil {
		t.Fatalf("failed to store EC pre-keys for device 1: %v", err)
	}
	if err := store.StoreECPreKeys(ctx, "uuid-1", 2, []*PreKey{{KeyID: 2}}); err != nil {
		t.Fatalf("failed to store EC pre-keys for device 2: %v", err)
	}
	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, &SignedPreKey{KeyID: 5}); err != nil {
		t.Fatalf("failed to store signed pre-key: %v", err)
	}

	if err := store.DeleteAllForAccount(ctx, "uuid-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, _ := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if state.ECCount != 0 {
		t.Errorf("expected zero EC count for device 1 after account delete, got %d", state.ECCount)
	}
	state2, _ := store.GetPreKeyCount(ctx, "uuid-1", 2)
	if state2.ECCount != 0 {
		t.Errorf("expected zero EC count for device 2 after account delete, got %d", state2.ECCount)
	}
}

func TestPreKeyStore_DeleteAllForAccount_Nonexistent(t *testing.T) {
	store := newMockPreKeyStore()
	err := store.DeleteAllForAccount(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("delete of nonexistent account should not error, got %v", err)
	}
}

func TestPreKeyStore_IsolationBetweenDevices(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*PreKey{{KeyID: 1}}); err != nil {
		t.Fatalf("failed to store EC pre-keys for device 1: %v", err)
	}
	if err := store.StoreECPreKeys(ctx, "uuid-1", 2, []*PreKey{{KeyID: 2}}); err != nil {
		t.Fatalf("failed to store EC pre-keys for device 2: %v", err)
	}

	pk, err := store.TakeEC(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.KeyID != 1 {
		t.Errorf("expected KeyID 1 for device 1, got %d", pk.KeyID)
	}

	pk2, err := store.TakeEC(ctx, "uuid-1", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk2.KeyID != 2 {
		t.Errorf("expected KeyID 2 for device 2, got %d", pk2.KeyID)
	}
}

func TestPreKeyStore_IsolationBetweenAccounts(t *testing.T) {
	store := newMockPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-A", 1, []*PreKey{{KeyID: 100}}); err != nil {
		t.Fatalf("failed to store EC pre-keys for uuid-A: %v", err)
	}
	if err := store.StoreECPreKeys(ctx, "uuid-B", 1, []*PreKey{{KeyID: 200}}); err != nil {
		t.Fatalf("failed to store EC pre-keys for uuid-B: %v", err)
	}

	pkA, _ := store.TakeEC(ctx, "uuid-A", 1)
	pkB, _ := store.TakeEC(ctx, "uuid-B", 1)

	if pkA.KeyID != 100 {
		t.Errorf("expected KeyID 100 for uuid-A, got %d", pkA.KeyID)
	}
	if pkB.KeyID != 200 {
		t.Errorf("expected KeyID 200 for uuid-B, got %d", pkB.KeyID)
	}
}
