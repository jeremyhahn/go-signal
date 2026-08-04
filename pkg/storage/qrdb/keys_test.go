package qrdb

import (
	"context"
	"errors"
	"testing"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

func TestPreKeyStore_StoreAndTakeEC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	pks := []*keys.PreKey{
		{KeyID: 1, PublicKey: []byte("pk-1")},
		{KeyID: 2, PublicKey: []byte("pk-2")},
		{KeyID: 3, PublicKey: []byte("pk-3")},
	}
	if err := s.StoreECPreKeys(ctx, "u1", 1, pks); err != nil {
		t.Fatalf("StoreECPreKeys: %v", err)
	}

	// Take should consume keys in ascending ID order.
	taken, err := s.TakeEC(ctx, "u1", 1)
	if err != nil {
		t.Fatalf("TakeEC: %v", err)
	}
	if taken == nil || taken.KeyID != 1 {
		t.Fatalf("expected KeyID=1, got %+v", taken)
	}

	// Count reflects consumption.
	state, err := s.GetPreKeyCount(ctx, "u1", 1)
	if err != nil || state.ECCount != 2 {
		t.Fatalf("expected 2 EC keys remaining, got %d", state.ECCount)
	}
}

func TestPreKeyStore_TakeEC_Empty_ReturnsPreKeyNotAvailable(t *testing.T) {
	t.Parallel()
	s := NewPreKeyStore(NewFakeKVStore())
	taken, err := s.TakeEC(context.Background(), "u1", 1)
	if taken != nil {
		t.Fatalf("expected nil key on empty queue, got %+v", taken)
	}
	var se *signalerrors.SignalError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SignalError, got: %v", err)
	}
	if se.Code != signalerrors.ErrPreKeyNotAvailable {
		t.Fatalf("expected ErrPreKeyNotAvailable, got code %d", se.Code)
	}
}

func TestPreKeyStore_StoreECPreKeys_ReplacesBatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	first := []*keys.PreKey{{KeyID: 1}, {KeyID: 2}}
	if err := s.StoreECPreKeys(ctx, "u1", 1, first); err != nil {
		t.Fatal(err)
	}

	replacement := []*keys.PreKey{{KeyID: 10}}
	if err := s.StoreECPreKeys(ctx, "u1", 1, replacement); err != nil {
		t.Fatal(err)
	}

	state, _ := s.GetPreKeyCount(ctx, "u1", 1)
	if state.ECCount != 1 {
		t.Fatalf("expected batch replacement to leave 1 key, got %d", state.ECCount)
	}
	taken, _ := s.TakeEC(ctx, "u1", 1)
	if taken.KeyID != 10 {
		t.Fatalf("expected KeyID=10, got %d", taken.KeyID)
	}
}

func TestPreKeyStore_KEMFlow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	kems := []*keys.KEMSignedPreKey{{KeyID: 1, PublicKey: []byte("pk")}}
	if err := s.StoreKEMPreKeys(ctx, "u1", 1, kems); err != nil {
		t.Fatalf("StoreKEMPreKeys: %v", err)
	}
	taken, err := s.TakeKEM(ctx, "u1", 1)
	if err != nil || taken == nil || taken.KeyID != 1 {
		t.Fatalf("TakeKEM: err=%v got=%+v", err, taken)
	}

	// Exhausted: TakeKEM returns ErrPreKeyNotAvailable.
	empty, err := s.TakeKEM(ctx, "u1", 1)
	if empty != nil {
		t.Fatalf("expected nil key on exhausted queue, got %+v", empty)
	}
	var se *signalerrors.SignalError
	if !errors.As(err, &se) {
		t.Fatalf("expected *SignalError on exhausted TakeKEM, got: %v", err)
	}
	if se.Code != signalerrors.ErrPreKeyNotAvailable {
		t.Fatalf("expected ErrPreKeyNotAvailable, got code %d", se.Code)
	}
}

func TestPreKeyStore_LastResortKEMLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	lr := &keys.KEMSignedPreKey{KeyID: 99, IsLastResort: true, PublicKey: []byte("lr")}
	if err := s.StoreKEMLastResortPreKey(ctx, "u1", 1, lr); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey: %v", err)
	}

	// Get does not consume.
	got, err := s.GetKEMLastResortPreKey(ctx, "u1", 1)
	if err != nil || got == nil || !got.IsLastResort {
		t.Fatalf("GetKEMLastResortPreKey: err=%v got=%+v", err, got)
	}

	// Still present after Get.
	state, _ := s.GetPreKeyCount(ctx, "u1", 1)
	if !state.HasLastResort {
		t.Fatal("last-resort should remain after non-consuming Get")
	}
}

func TestPreKeyStore_LastResortKEMMissing(t *testing.T) {
	t.Parallel()
	s := NewPreKeyStore(NewFakeKVStore())
	_, err := s.GetKEMLastResortPreKey(context.Background(), "u1", 1)
	if err == nil {
		t.Fatal("expected error for missing last-resort key")
	}
}

func TestPreKeyStore_StoreLastResort_Nil(t *testing.T) {
	t.Parallel()
	s := NewPreKeyStore(NewFakeKVStore())
	if err := s.StoreKEMLastResortPreKey(context.Background(), "u1", 1, nil); err == nil {
		t.Fatal("expected error for nil last-resort key")
	}
}

func TestPreKeyStore_SignedPreKeyLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	spk := &keys.SignedPreKey{KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig")}
	if err := s.StoreSignedPreKey(ctx, "u1", 1, spk); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}
	got, err := s.GetSignedPreKey(ctx, "u1", 1)
	if err != nil || got.KeyID != 1 {
		t.Fatalf("GetSignedPreKey: err=%v got=%+v", err, got)
	}
}

func TestPreKeyStore_StoreSignedPreKey_Nil(t *testing.T) {
	t.Parallel()
	s := NewPreKeyStore(NewFakeKVStore())
	if err := s.StoreSignedPreKey(context.Background(), "u1", 1, nil); err == nil {
		t.Fatal("expected error for nil signed pre-key")
	}
}

func TestPreKeyStore_GetSignedPreKey_Missing(t *testing.T) {
	t.Parallel()
	s := NewPreKeyStore(NewFakeKVStore())
	_, err := s.GetSignedPreKey(context.Background(), "u1", 1)
	if err == nil {
		t.Fatal("expected error for missing signed pre-key")
	}
}

func TestPreKeyStore_DeleteAllForDevice(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	_ = s.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 1}})
	_ = s.StoreECPreKeys(ctx, "u1", 2, []*keys.PreKey{{KeyID: 1}})

	if err := s.DeleteAllForDevice(ctx, "u1", 1); err != nil {
		t.Fatal(err)
	}

	s1, _ := s.GetPreKeyCount(ctx, "u1", 1)
	if s1.ECCount != 0 {
		t.Fatalf("device 1 should be empty, got %d", s1.ECCount)
	}
	s2, _ := s.GetPreKeyCount(ctx, "u1", 2)
	if s2.ECCount != 1 {
		t.Fatalf("device 2 should retain, got %d", s2.ECCount)
	}
}

func TestPreKeyStore_DeleteAllForAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	_ = s.StoreECPreKeys(ctx, "u1", 1, []*keys.PreKey{{KeyID: 1}})
	_ = s.StoreSignedPreKey(ctx, "u1", 1, &keys.SignedPreKey{KeyID: 1})
	_ = s.StoreECPreKeys(ctx, "u2", 1, []*keys.PreKey{{KeyID: 1}})

	if err := s.DeleteAllForAccount(ctx, "u1"); err != nil {
		t.Fatal(err)
	}

	s1, _ := s.GetPreKeyCount(ctx, "u1", 1)
	if s1.ECCount != 0 {
		t.Fatalf("u1 should be empty, got %+v", s1)
	}
	s2, _ := s.GetPreKeyCount(ctx, "u2", 1)
	if s2.ECCount != 1 {
		t.Fatalf("u2 should be retained, got %+v", s2)
	}
}

func TestPreKeyStore_ListAccountUUIDs_Empty(t *testing.T) {
	t.Parallel()
	s := NewPreKeyStore(NewFakeKVStore())
	uuids, err := s.ListAccountUUIDs(context.Background())
	if err != nil {
		t.Fatalf("ListAccountUUIDs: %v", err)
	}
	if len(uuids) != 0 {
		t.Errorf("ListAccountUUIDs: expected 0, got %d", len(uuids))
	}
}

func TestPreKeyStore_ListAccountUUIDs_ReturnsUUIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewPreKeyStore(NewFakeKVStore())

	_ = s.StoreECPreKeys(ctx, "list-u1", 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk")}})
	_ = s.StoreECPreKeys(ctx, "list-u2", 1, []*keys.PreKey{{KeyID: 2, PublicKey: []byte("pk")}})

	uuids, err := s.ListAccountUUIDs(ctx)
	if err != nil {
		t.Fatalf("ListAccountUUIDs: %v", err)
	}
	if len(uuids) != 2 {
		t.Errorf("ListAccountUUIDs: expected 2, got %d: %v", len(uuids), uuids)
	}
}
