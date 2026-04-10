package memory

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

func testPreKey(id uint64) *keys.PreKey {
	return &keys.PreKey{
		KeyID:     id,
		PublicKey: []byte{byte(id), 0x01, 0x02},
	}
}

func testSignedPreKey(id uint64) *keys.SignedPreKey {
	return &keys.SignedPreKey{
		KeyID:     id,
		PublicKey: []byte{byte(id), 0x10, 0x20},
		Signature: []byte{byte(id), 0x30, 0x40},
	}
}

func testKEMPreKey(id uint64) *keys.KEMSignedPreKey {
	return &keys.KEMSignedPreKey{
		KeyID:     id,
		PublicKey: []byte{byte(id), 0x50, 0x60},
		Signature: []byte{byte(id), 0x70, 0x80},
	}
}

func TestNewMemoryPreKeyStore(t *testing.T) {
	store := NewMemoryPreKeyStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.ecKeys == nil || store.kemKeys == nil || store.signedKeys == nil {
		t.Fatal("expected all internal maps to be initialized")
	}
}

func TestNewMemoryPreKeyStoreEmptyMaps(t *testing.T) {
	store := NewMemoryPreKeyStore()
	if len(store.ecKeys) != 0 || len(store.kemKeys) != 0 || len(store.signedKeys) != 0 {
		t.Fatal("expected all maps to be empty initially")
	}
}

func TestStoreECPreKeys(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	preKeys := []*keys.PreKey{testPreKey(1), testPreKey(2), testPreKey(3)}
	err := store.StoreECPreKeys(ctx, "uuid-1", 1, preKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 3 {
		t.Fatalf("expected 3 EC keys, got %d", state.ECCount)
	}
}

func TestStoreECPreKeysAppends(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*keys.PreKey{testPreKey(1)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*keys.PreKey{testPreKey(2)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 2 {
		t.Fatalf("expected 2 EC keys after append, got %d", state.ECCount)
	}
}

func TestStoreECPreKeysDeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	pk := testPreKey(1)
	if err := store.StoreECPreKeys(ctx, "uuid-dc", 1, []*keys.PreKey{pk}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate original.
	pk.PublicKey[0] = 0xFF

	taken, err := store.TakeEC(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if taken.PublicKey[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
}

func TestStoreKEMPreKeys(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	kemKeys := []*keys.KEMSignedPreKey{testKEMPreKey(10), testKEMPreKey(11)}
	err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, kemKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.KEMCount != 2 {
		t.Fatalf("expected 2 KEM keys, got %d", state.KEMCount)
	}
}

func TestStoreKEMPreKeysAppends(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, []*keys.KEMSignedPreKey{testKEMPreKey(1)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, []*keys.KEMSignedPreKey{testKEMPreKey(2)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.KEMCount != 2 {
		t.Fatalf("expected 2 KEM keys after append, got %d", state.KEMCount)
	}
}

func TestStoreKEMPreKeysDeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	kpk := testKEMPreKey(1)
	if err := store.StoreKEMPreKeys(ctx, "uuid-dc", 1, []*keys.KEMSignedPreKey{kpk}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	kpk.PublicKey[0] = 0xFF

	taken, err := store.TakeKEM(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if taken.PublicKey[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
}

func TestStoreSignedPreKey(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	spk := testSignedPreKey(100)
	err := store.StoreSignedPreKey(ctx, "uuid-1", 1, spk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KeyID != 100 {
		t.Fatalf("expected KeyID 100, got %d", got.KeyID)
	}
}

func TestStoreSignedPreKeyOverwrites(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, testSignedPreKey(100)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, testSignedPreKey(200)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KeyID != 200 {
		t.Fatalf("expected KeyID 200 after overwrite, got %d", got.KeyID)
	}
}

func TestStoreSignedPreKeyDeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	spk := testSignedPreKey(100)
	if err := store.StoreSignedPreKey(ctx, "uuid-dc", 1, spk); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spk.PublicKey[0] = 0xFF

	got, err := store.GetSignedPreKey(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PublicKey[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
}

func TestTakeEC(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	preKeys := []*keys.PreKey{testPreKey(1), testPreKey(2), testPreKey(3)}
	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, preKeys); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	taken, err := store.TakeEC(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if taken.KeyID != 1 {
		t.Fatalf("expected KeyID 1, got %d", taken.KeyID)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 2 {
		t.Fatalf("expected 2 remaining EC keys, got %d", state.ECCount)
	}
}

func TestTakeECEmpty(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	_, err := store.TakeEC(ctx, "uuid-nonexistent", 1)
	if err == nil {
		t.Fatal("expected error for empty EC keys")
	}

	se, ok := err.(*errors.SignalError)
	if !ok {
		t.Fatalf("expected *errors.SignalError, got %T", err)
	}
	if se.Code != errors.ErrPreKeyNotAvailable {
		t.Fatalf("expected ErrPreKeyNotAvailable, got %v", se.Code)
	}
}

func TestTakeECDeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-dc", 1, []*keys.PreKey{testPreKey(1), testPreKey(2)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	taken, err := store.TakeEC(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	taken.PublicKey[0] = 0xFF

	// Next take should be unaffected.
	taken2, err := store.TakeEC(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if taken2.PublicKey[0] == 0xFF {
		t.Fatal("mutation of taken key affected remaining stored data")
	}
}

func TestTakeECDrainsAllKeys(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-drain", 1, []*keys.PreKey{testPreKey(1), testPreKey(2)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := 0; i < 2; i++ {
		_, err := store.TakeEC(ctx, "uuid-drain", 1)
		if err != nil {
			t.Fatalf("unexpected error on take %d: %v", i, err)
		}
	}

	_, err := store.TakeEC(ctx, "uuid-drain", 1)
	if err == nil {
		t.Fatal("expected error after draining all EC keys")
	}
}

func TestTakeKEM(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	kemKeys := []*keys.KEMSignedPreKey{testKEMPreKey(10), testKEMPreKey(11)}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, kemKeys); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	taken, err := store.TakeKEM(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if taken.KeyID != 10 {
		t.Fatalf("expected KeyID 10, got %d", taken.KeyID)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.KEMCount != 1 {
		t.Fatalf("expected 1 remaining KEM key, got %d", state.KEMCount)
	}
}

func TestTakeKEMEmpty(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	_, err := store.TakeKEM(ctx, "uuid-nonexistent", 1)
	if err == nil {
		t.Fatal("expected error for empty KEM keys")
	}

	se, ok := err.(*errors.SignalError)
	if !ok {
		t.Fatalf("expected *errors.SignalError, got %T", err)
	}
	if se.Code != errors.ErrPreKeyNotAvailable {
		t.Fatalf("expected ErrPreKeyNotAvailable, got %v", se.Code)
	}
}

func TestTakeKEMDeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreKEMPreKeys(ctx, "uuid-dc", 1, []*keys.KEMSignedPreKey{testKEMPreKey(1), testKEMPreKey(2)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	taken, err := store.TakeKEM(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	taken.PublicKey[0] = 0xFF

	taken2, err := store.TakeKEM(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if taken2.PublicKey[0] == 0xFF {
		t.Fatal("mutation of taken KEM key affected remaining stored data")
	}
}

func TestGetSignedPreKey(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	spk := testSignedPreKey(100)
	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, spk); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KeyID != 100 {
		t.Fatalf("expected KeyID 100, got %d", got.KeyID)
	}
	if !bytes.Equal(got.PublicKey, spk.PublicKey) {
		t.Fatal("PublicKey mismatch")
	}
	if !bytes.Equal(got.Signature, spk.Signature) {
		t.Fatal("Signature mismatch")
	}
}

func TestGetSignedPreKeyNotFound(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	_, err := store.GetSignedPreKey(ctx, "uuid-missing", 1)
	if err == nil {
		t.Fatal("expected error for missing signed pre-key")
	}

	se, ok := err.(*errors.SignalError)
	if !ok {
		t.Fatalf("expected *errors.SignalError, got %T", err)
	}
	if se.Code != errors.ErrPreKeyNotAvailable {
		t.Fatalf("expected ErrPreKeyNotAvailable, got %v", se.Code)
	}
}

func TestGetSignedPreKeyDeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, testSignedPreKey(100)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got.PublicKey[0] = 0xFF

	got2, err := store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.PublicKey[0] == 0xFF {
		t.Fatal("mutation of returned value affected stored data")
	}
}

func TestGetPreKeyCount(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*keys.PreKey{testPreKey(1), testPreKey(2)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, []*keys.KEMSignedPreKey{testKEMPreKey(10)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 2 {
		t.Fatalf("expected ECCount 2, got %d", state.ECCount)
	}
	if state.KEMCount != 1 {
		t.Fatalf("expected KEMCount 1, got %d", state.KEMCount)
	}
}

func TestGetPreKeyCountEmpty(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	state, err := store.GetPreKeyCount(ctx, "uuid-empty", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 0 {
		t.Fatalf("expected ECCount 0, got %d", state.ECCount)
	}
	if state.KEMCount != 0 {
		t.Fatalf("expected KEMCount 0, got %d", state.KEMCount)
	}
}

func TestDeleteAllForDevice(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*keys.PreKey{testPreKey(1)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, []*keys.KEMSignedPreKey{testKEMPreKey(10)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, testSignedPreKey(100)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Also store keys for device 2 to ensure they are unaffected.
	if err := store.StoreECPreKeys(ctx, "uuid-1", 2, []*keys.PreKey{testPreKey(5)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteAllForDevice(ctx, "uuid-1", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 0 || state.KEMCount != 0 {
		t.Fatalf("expected 0 keys after delete, got EC=%d KEM=%d", state.ECCount, state.KEMCount)
	}

	_, err = store.GetSignedPreKey(ctx, "uuid-1", 1)
	if err == nil {
		t.Fatal("expected error for signed pre-key after device delete")
	}

	// Device 2 should be unaffected.
	state2, err := store.GetPreKeyCount(ctx, "uuid-1", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state2.ECCount != 1 {
		t.Fatalf("expected 1 EC key for device 2, got %d", state2.ECCount)
	}
}

func TestDeleteAllForDeviceNonexistent(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	// Should not error for nonexistent device.
	err := store.DeleteAllForDevice(ctx, "uuid-missing", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteAllForAccount(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	// Store keys across multiple devices.
	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*keys.PreKey{testPreKey(1)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreECPreKeys(ctx, "uuid-1", 2, []*keys.PreKey{testPreKey(2)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreKEMPreKeys(ctx, "uuid-1", 1, []*keys.KEMSignedPreKey{testKEMPreKey(10)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreSignedPreKey(ctx, "uuid-1", 1, testSignedPreKey(100)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Store keys for a different account.
	if err := store.StoreECPreKeys(ctx, "uuid-2", 1, []*keys.PreKey{testPreKey(99)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteAllForAccount(ctx, "uuid-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All device keys for uuid-1 should be gone.
	state, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 0 || state.KEMCount != 0 {
		t.Fatalf("expected 0 keys for device 1, got EC=%d KEM=%d", state.ECCount, state.KEMCount)
	}

	state2, err := store.GetPreKeyCount(ctx, "uuid-1", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state2.ECCount != 0 {
		t.Fatalf("expected 0 keys for device 2, got %d", state2.ECCount)
	}

	// uuid-2 should be unaffected.
	state3, err := store.GetPreKeyCount(ctx, "uuid-2", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state3.ECCount != 1 {
		t.Fatalf("expected 1 EC key for uuid-2, got %d", state3.ECCount)
	}
}

func TestDeleteAllForAccountNonexistent(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	err := store.DeleteAllForAccount(ctx, "uuid-missing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClonePreKey(t *testing.T) {
	original := testPreKey(42)
	clone := clonePreKey(original)

	if clone.KeyID != original.KeyID {
		t.Fatalf("expected KeyID %d, got %d", original.KeyID, clone.KeyID)
	}

	clone.PublicKey[0] = 0xFF
	if original.PublicKey[0] == 0xFF {
		t.Fatal("clone mutation affected original")
	}
}

func TestClonePreKeyFieldValues(t *testing.T) {
	original := &keys.PreKey{KeyID: 999, PublicKey: []byte{0xAA, 0xBB}}
	clone := clonePreKey(original)

	if clone.KeyID != 999 {
		t.Fatalf("expected KeyID 999, got %d", clone.KeyID)
	}
	if !bytes.Equal(clone.PublicKey, []byte{0xAA, 0xBB}) {
		t.Fatalf("expected PublicKey match, got %v", clone.PublicKey)
	}
}

func TestCloneSignedPreKey(t *testing.T) {
	original := testSignedPreKey(50)
	clone := cloneSignedPreKey(original)

	clone.PublicKey[0] = 0xFF
	if original.PublicKey[0] == 0xFF {
		t.Fatal("clone mutation affected original PublicKey")
	}

	clone.Signature[0] = 0xAA
	if original.Signature[0] == 0xAA {
		t.Fatal("clone mutation affected original Signature")
	}
}

func TestCloneSignedPreKeyFieldValues(t *testing.T) {
	original := &keys.SignedPreKey{KeyID: 777, PublicKey: []byte{1}, Signature: []byte{2}}
	clone := cloneSignedPreKey(original)
	if clone.KeyID != 777 {
		t.Fatalf("expected KeyID 777, got %d", clone.KeyID)
	}
}

func TestCloneKEMPreKey(t *testing.T) {
	original := testKEMPreKey(60)
	clone := cloneKEMPreKey(original)

	clone.PublicKey[0] = 0xFF
	if original.PublicKey[0] == 0xFF {
		t.Fatal("clone mutation affected original PublicKey")
	}

	clone.Signature[0] = 0xAA
	if original.Signature[0] == 0xAA {
		t.Fatal("clone mutation affected original Signature")
	}
}

func TestCloneKEMPreKeyFieldValues(t *testing.T) {
	original := &keys.KEMSignedPreKey{KeyID: 888, PublicKey: []byte{3}, Signature: []byte{4}}
	clone := cloneKEMPreKey(original)
	if clone.KeyID != 888 {
		t.Fatalf("expected KeyID 888, got %d", clone.KeyID)
	}
}

func TestPreKeyStoreDifferentDevices(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-1", 1, []*keys.PreKey{testPreKey(1)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreECPreKeys(ctx, "uuid-1", 2, []*keys.PreKey{testPreKey(2), testPreKey(3)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state1, err := store.GetPreKeyCount(ctx, "uuid-1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state1.ECCount != 1 {
		t.Fatalf("expected 1 EC key for device 1, got %d", state1.ECCount)
	}

	state2, err := store.GetPreKeyCount(ctx, "uuid-1", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state2.ECCount != 2 {
		t.Fatalf("expected 2 EC keys for device 2, got %d", state2.ECCount)
	}
}

func TestPreKeyStoreDifferentAccounts(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreECPreKeys(ctx, "uuid-a", 1, []*keys.PreKey{testPreKey(1)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreECPreKeys(ctx, "uuid-b", 1, []*keys.PreKey{testPreKey(2), testPreKey(3)}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stateA, _ := store.GetPreKeyCount(ctx, "uuid-a", 1)
	stateB, _ := store.GetPreKeyCount(ctx, "uuid-b", 1)

	if stateA.ECCount != 1 {
		t.Fatalf("expected 1 EC key for uuid-a, got %d", stateA.ECCount)
	}
	if stateB.ECCount != 2 {
		t.Fatalf("expected 2 EC keys for uuid-b, got %d", stateB.ECCount)
	}
}

func TestPreKeyStoreConcurrency(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	const n = 30

	for i := 0; i < n; i++ {
		wg.Add(3)
		go func(idx int) {
			defer wg.Done()
			_ = store.StoreECPreKeys(ctx, "uuid-conc", 1, []*keys.PreKey{testPreKey(uint64(idx))})
		}(i)
		go func(idx int) {
			defer wg.Done()
			_ = store.StoreKEMPreKeys(ctx, "uuid-conc", 1, []*keys.KEMSignedPreKey{testKEMPreKey(uint64(idx))})
		}(i)
		go func(idx int) {
			defer wg.Done()
			_ = store.StoreSignedPreKey(ctx, "uuid-conc", 1, testSignedPreKey(uint64(idx)))
		}(i)
	}
	wg.Wait()

	state, err := store.GetPreKeyCount(ctx, "uuid-conc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != n {
		t.Fatalf("expected %d EC keys, got %d", n, state.ECCount)
	}
	if state.KEMCount != n {
		t.Fatalf("expected %d KEM keys, got %d", n, state.KEMCount)
	}
}

func TestPreKeyStoreConcurrentTakeAndStore(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	// Pre-populate.
	pks := make([]*keys.PreKey, 100)
	for i := range pks {
		pks[i] = testPreKey(uint64(i))
	}
	if err := store.StoreECPreKeys(ctx, "uuid-ct", 1, pks); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = store.TakeEC(ctx, "uuid-ct", 1)
		}()
		go func(idx int) {
			defer wg.Done()
			_ = store.StoreECPreKeys(ctx, "uuid-ct", 1, []*keys.PreKey{testPreKey(uint64(200 + idx))})
		}(i)
	}
	wg.Wait()
}

func TestStoreKEMLastResortPreKey(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	kpk := testKEMPreKey(42)
	err := store.StoreKEMLastResortPreKey(ctx, "uuid-lr", 1, kpk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetKEMLastResortPreKey(ctx, "uuid-lr", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KeyID != 42 {
		t.Fatalf("expected KeyID 42, got %d", got.KeyID)
	}
	if !got.IsLastResort {
		t.Fatal("expected IsLastResort to be true")
	}
}

func TestStoreKEMLastResortPreKey_Overwrite(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreKEMLastResortPreKey(ctx, "uuid-lr", 1, testKEMPreKey(10)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.StoreKEMLastResortPreKey(ctx, "uuid-lr", 1, testKEMPreKey(20)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetKEMLastResortPreKey(ctx, "uuid-lr", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KeyID != 20 {
		t.Fatalf("expected KeyID 20 after overwrite, got %d", got.KeyID)
	}
}

func TestStoreKEMLastResortPreKey_DeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	kpk := testKEMPreKey(42)
	if err := store.StoreKEMLastResortPreKey(ctx, "uuid-dc", 1, kpk); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the original.
	kpk.PublicKey[0] = 0xFF

	got, err := store.GetKEMLastResortPreKey(ctx, "uuid-dc", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.PublicKey[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
}

func TestGetKEMLastResortPreKey(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	kpk := testKEMPreKey(99)
	if err := store.StoreKEMLastResortPreKey(ctx, "uuid-get", 1, kpk); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetKEMLastResortPreKey(ctx, "uuid-get", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.KeyID != 99 {
		t.Fatalf("expected KeyID 99, got %d", got.KeyID)
	}
	if !bytes.Equal(got.PublicKey, kpk.PublicKey) {
		t.Fatal("PublicKey mismatch")
	}
	if !bytes.Equal(got.Signature, kpk.Signature) {
		t.Fatal("Signature mismatch")
	}
}

func TestGetKEMLastResortPreKey_NotFound(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	_, err := store.GetKEMLastResortPreKey(ctx, "uuid-missing", 1)
	if err == nil {
		t.Fatal("expected error for missing last-resort key")
	}

	se, ok := err.(*errors.SignalError)
	if !ok {
		t.Fatalf("expected *errors.SignalError, got %T", err)
	}
	if se.Code != errors.ErrPreKeyNotAvailable {
		t.Fatalf("expected ErrPreKeyNotAvailable, got %v", se.Code)
	}
}

func TestGetKEMLastResortPreKey_DeepCopy(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreKEMLastResortPreKey(ctx, "uuid-dc2", 1, testKEMPreKey(55)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetKEMLastResortPreKey(ctx, "uuid-dc2", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got.PublicKey[0] = 0xFF

	got2, err := store.GetKEMLastResortPreKey(ctx, "uuid-dc2", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.PublicKey[0] == 0xFF {
		t.Fatal("mutation of returned value affected stored data")
	}
}

func TestGetPreKeyCount_IncludesLastResort(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	// No last resort initially.
	state, err := store.GetPreKeyCount(ctx, "uuid-lr-count", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.HasLastResort {
		t.Fatal("expected HasLastResort false before storing")
	}

	// Store last resort.
	if err := store.StoreKEMLastResortPreKey(ctx, "uuid-lr-count", 1, testKEMPreKey(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state, err = store.GetPreKeyCount(ctx, "uuid-lr-count", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !state.HasLastResort {
		t.Fatal("expected HasLastResort true after storing")
	}
}

func TestDeleteAllForDevice_IncludesLastResort(t *testing.T) {
	store := NewMemoryPreKeyStore()
	ctx := context.Background()

	if err := store.StoreKEMLastResortPreKey(ctx, "uuid-del-lr", 1, testKEMPreKey(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.DeleteAllForDevice(ctx, "uuid-del-lr", 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := store.GetKEMLastResortPreKey(ctx, "uuid-del-lr", 1)
	if err == nil {
		t.Fatal("expected error after deleting device keys including last resort")
	}
}
