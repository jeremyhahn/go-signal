package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/jeremyhahn/go-signal/pkg/keys"
)

func newPreKeyStore(t *testing.T) (*PreKeyStore, *Client) {
	t.Helper()
	c := newTestClient(t)
	return NewPreKeyStore(c.Pool()), c
}

// --- EC one-time pre-keys ---

func TestPreKeys_StoreEC_TakeEC_Roundtrip(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	preKeys := []*keys.PreKey{
		{KeyID: 1, PublicKey: []byte{0x01, 0x02}},
		{KeyID: 2, PublicKey: []byte{0x03, 0x04}},
	}
	if err := s.StoreECPreKeys(ctx, aci, 1, preKeys); err != nil {
		t.Fatalf("StoreECPreKeys: %v", err)
	}

	got, err := s.TakeEC(ctx, aci, 1)
	if err != nil {
		t.Fatalf("TakeEC #1: %v", err)
	}
	if got.KeyID != 1 {
		t.Fatalf("expected KeyID 1, got %d", got.KeyID)
	}

	got2, err := s.TakeEC(ctx, aci, 1)
	if err != nil {
		t.Fatalf("TakeEC #2: %v", err)
	}
	if got2.KeyID != 2 {
		t.Fatalf("expected KeyID 2, got %d", got2.KeyID)
	}
}

func TestPreKeys_TakeEC_Empty_ReturnsNotFound(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	_, err := s.TakeEC(ctx, aci, 1)
	var knf *keys.PreKeyNotFoundError
	if !errors.As(err, &knf) {
		t.Fatalf("expected PreKeyNotFoundError, got %T: %v", err, err)
	}
}

func TestPreKeys_StoreEC_ReplacesExisting(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{
		{KeyID: 10, PublicKey: []byte{0xAA}},
		{KeyID: 11, PublicKey: []byte{0xBB}},
	}); err != nil {
		t.Fatalf("StoreECPreKeys first: %v", err)
	}

	// Replace with a single different key.
	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{
		{KeyID: 99, PublicKey: []byte{0xFF}},
	}); err != nil {
		t.Fatalf("StoreECPreKeys second: %v", err)
	}

	got, err := s.TakeEC(ctx, aci, 1)
	if err != nil {
		t.Fatalf("TakeEC: %v", err)
	}
	if got.KeyID != 99 {
		t.Fatalf("expected KeyID 99 after replace, got %d", got.KeyID)
	}

	// Queue should now be empty.
	_, err = s.TakeEC(ctx, aci, 1)
	var knf *keys.PreKeyNotFoundError
	if !errors.As(err, &knf) {
		t.Fatalf("expected PreKeyNotFoundError after queue empty, got %T: %v", err, err)
	}
}

func TestPreKeys_TakeEC_ConsumesLowestKeyIDFirst(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	// Insert out of numeric order to confirm MIN semantics, not insertion order.
	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{
		{KeyID: 50, PublicKey: []byte{0x50}},
		{KeyID: 10, PublicKey: []byte{0x10}},
		{KeyID: 30, PublicKey: []byte{0x30}},
	}); err != nil {
		t.Fatalf("StoreECPreKeys: %v", err)
	}

	ids := make([]uint64, 3)
	for i := range ids {
		pk, err := s.TakeEC(ctx, aci, 1)
		if err != nil {
			t.Fatalf("TakeEC #%d: %v", i, err)
		}
		ids[i] = pk.KeyID
	}
	want := []uint64{10, 30, 50}
	for i, w := range want {
		if ids[i] != w {
			t.Fatalf("take #%d: got KeyID %d, want %d", i, ids[i], w)
		}
	}
}

// --- KEM one-time pre-keys ---

func TestPreKeys_StoreKEM_TakeKEM_Roundtrip(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	preKeys := []*keys.KEMSignedPreKey{
		{KeyID: 100, PublicKey: []byte{0x01}, Signature: []byte{0xA1}},
		{KeyID: 200, PublicKey: []byte{0x02}, Signature: []byte{0xA2}},
	}
	if err := s.StoreKEMPreKeys(ctx, aci, 1, preKeys); err != nil {
		t.Fatalf("StoreKEMPreKeys: %v", err)
	}

	got, err := s.TakeKEM(ctx, aci, 1)
	if err != nil {
		t.Fatalf("TakeKEM #1: %v", err)
	}
	if got.KeyID != 100 {
		t.Fatalf("expected KeyID 100, got %d", got.KeyID)
	}

	got2, err := s.TakeKEM(ctx, aci, 1)
	if err != nil {
		t.Fatalf("TakeKEM #2: %v", err)
	}
	if got2.KeyID != 200 {
		t.Fatalf("expected KeyID 200, got %d", got2.KeyID)
	}
}

func TestPreKeys_TakeKEM_Empty_ReturnsNotFound(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	_, err := s.TakeKEM(ctx, aci, 1)
	var knf *keys.PreKeyNotFoundError
	if !errors.As(err, &knf) {
		t.Fatalf("expected PreKeyNotFoundError, got %T: %v", err, err)
	}
}

func TestPreKeys_StoreKEM_ReplacesExisting(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreKEMPreKeys(ctx, aci, 1, []*keys.KEMSignedPreKey{
		{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x11}},
		{KeyID: 2, PublicKey: []byte{0x02}, Signature: []byte{0x22}},
	}); err != nil {
		t.Fatalf("StoreKEMPreKeys first: %v", err)
	}

	if err := s.StoreKEMPreKeys(ctx, aci, 1, []*keys.KEMSignedPreKey{
		{KeyID: 77, PublicKey: []byte{0x77}, Signature: []byte{0x78}},
	}); err != nil {
		t.Fatalf("StoreKEMPreKeys second: %v", err)
	}

	got, err := s.TakeKEM(ctx, aci, 1)
	if err != nil {
		t.Fatalf("TakeKEM: %v", err)
	}
	if got.KeyID != 77 {
		t.Fatalf("expected KeyID 77 after replace, got %d", got.KeyID)
	}
}

// --- KEM last-resort pre-key ---

func TestPreKeys_StoreKEMLastResort_Get_Roundtrip(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	lrKey := &keys.KEMSignedPreKey{KeyID: 999, PublicKey: []byte{0xDE, 0xAD}, Signature: []byte{0xBE, 0xEF}}
	if err := s.StoreKEMLastResortPreKey(ctx, aci, 1, lrKey); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey: %v", err)
	}

	got, err := s.GetKEMLastResortPreKey(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetKEMLastResortPreKey: %v", err)
	}
	if got.KeyID != 999 {
		t.Fatalf("expected KeyID 999, got %d", got.KeyID)
	}
	if !got.IsLastResort {
		t.Fatal("expected IsLastResort=true")
	}
}

func TestPreKeys_GetKEMLastResort_DoesNotConsume(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	lrKey := &keys.KEMSignedPreKey{KeyID: 42, PublicKey: []byte{0x42}, Signature: []byte{0x43}}
	if err := s.StoreKEMLastResortPreKey(ctx, aci, 1, lrKey); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey: %v", err)
	}

	for i := 0; i < 3; i++ {
		got, err := s.GetKEMLastResortPreKey(ctx, aci, 1)
		if err != nil {
			t.Fatalf("GetKEMLastResortPreKey call %d: %v", i, err)
		}
		if got.KeyID != 42 {
			t.Fatalf("call %d: expected KeyID 42, got %d", i, got.KeyID)
		}
	}
}

func TestPreKeys_StoreKEMLastResort_Upsert(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreKEMLastResortPreKey(ctx, aci, 1, &keys.KEMSignedPreKey{
		KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x11},
	}); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey first: %v", err)
	}

	if err := s.StoreKEMLastResortPreKey(ctx, aci, 1, &keys.KEMSignedPreKey{
		KeyID: 2, PublicKey: []byte{0x02}, Signature: []byte{0x22},
	}); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey second: %v", err)
	}

	got, err := s.GetKEMLastResortPreKey(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetKEMLastResortPreKey: %v", err)
	}
	if got.KeyID != 2 {
		t.Fatalf("expected KeyID 2 after upsert, got %d", got.KeyID)
	}
}

func TestPreKeys_GetKEMLastResort_Missing_ReturnsNotFound(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	_, err := s.GetKEMLastResortPreKey(ctx, aci, 1)
	var knf *keys.PreKeyNotFoundError
	if !errors.As(err, &knf) {
		t.Fatalf("expected PreKeyNotFoundError, got %T: %v", err, err)
	}
}

// --- Signed pre-key ---

func TestPreKeys_StoreSignedPreKey_Get_Roundtrip(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	spk := &keys.SignedPreKey{KeyID: 7, PublicKey: []byte{0x07}, Signature: []byte{0x70}}
	if err := s.StoreSignedPreKey(ctx, aci, 1, spk); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}

	got, err := s.GetSignedPreKey(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetSignedPreKey: %v", err)
	}
	if got.KeyID != 7 {
		t.Fatalf("expected KeyID 7, got %d", got.KeyID)
	}
}

func TestPreKeys_StoreSignedPreKey_Replaces(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreSignedPreKey(ctx, aci, 1, &keys.SignedPreKey{
		KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x11},
	}); err != nil {
		t.Fatalf("StoreSignedPreKey first: %v", err)
	}

	if err := s.StoreSignedPreKey(ctx, aci, 1, &keys.SignedPreKey{
		KeyID: 2, PublicKey: []byte{0x02}, Signature: []byte{0x22},
	}); err != nil {
		t.Fatalf("StoreSignedPreKey second: %v", err)
	}

	got, err := s.GetSignedPreKey(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetSignedPreKey: %v", err)
	}
	if got.KeyID != 2 {
		t.Fatalf("expected KeyID 2 after replace, got %d", got.KeyID)
	}
}

func TestPreKeys_GetSignedPreKey_Missing_ReturnsNotFound(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	_, err := s.GetSignedPreKey(ctx, aci, 1)
	var knf *keys.PreKeyNotFoundError
	if !errors.As(err, &knf) {
		t.Fatalf("expected PreKeyNotFoundError, got %T: %v", err, err)
	}
}

// --- GetPreKeyCount ---

func TestPreKeys_GetPreKeyCount_ReturnsCorrectCounts(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{
		{KeyID: 1, PublicKey: []byte{0x01}},
		{KeyID: 2, PublicKey: []byte{0x02}},
		{KeyID: 3, PublicKey: []byte{0x03}},
	}); err != nil {
		t.Fatalf("StoreECPreKeys: %v", err)
	}
	if err := s.StoreKEMPreKeys(ctx, aci, 1, []*keys.KEMSignedPreKey{
		{KeyID: 10, PublicKey: []byte{0x10}, Signature: []byte{0x11}},
	}); err != nil {
		t.Fatalf("StoreKEMPreKeys: %v", err)
	}
	if err := s.StoreKEMLastResortPreKey(ctx, aci, 1, &keys.KEMSignedPreKey{
		KeyID: 999, PublicKey: []byte{0xFF}, Signature: []byte{0xFE},
	}); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey: %v", err)
	}

	state, err := s.GetPreKeyCount(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount: %v", err)
	}
	if state.ECCount != 3 {
		t.Fatalf("ECCount: got %d, want 3", state.ECCount)
	}
	if state.KEMCount != 1 {
		t.Fatalf("KEMCount: got %d, want 1", state.KEMCount)
	}
	if !state.HasLastResort {
		t.Fatal("HasLastResort: got false, want true")
	}
}

func TestPreKeys_GetPreKeyCount_Empty(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	state, err := s.GetPreKeyCount(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount: %v", err)
	}
	if state.ECCount != 0 || state.KEMCount != 0 || state.HasLastResort {
		t.Fatalf("expected zero state, got %+v", state)
	}
}

// --- DeleteAllForDevice ---

func TestPreKeys_DeleteAllForDevice_ClearsAllKeyTypes(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte{0x01}}}); err != nil {
		t.Fatalf("StoreECPreKeys: %v", err)
	}
	if err := s.StoreKEMPreKeys(ctx, aci, 1, []*keys.KEMSignedPreKey{{KeyID: 10, PublicKey: []byte{0x10}, Signature: []byte{0x11}}}); err != nil {
		t.Fatalf("StoreKEMPreKeys: %v", err)
	}
	if err := s.StoreSignedPreKey(ctx, aci, 1, &keys.SignedPreKey{KeyID: 5, PublicKey: []byte{0x05}, Signature: []byte{0x06}}); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}
	if err := s.StoreKEMLastResortPreKey(ctx, aci, 1, &keys.KEMSignedPreKey{KeyID: 999, PublicKey: []byte{0xFF}, Signature: []byte{0xFE}}); err != nil {
		t.Fatalf("StoreKEMLastResortPreKey: %v", err)
	}

	if err := s.DeleteAllForDevice(ctx, aci, 1); err != nil {
		t.Fatalf("DeleteAllForDevice: %v", err)
	}

	state, err := s.GetPreKeyCount(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount after delete: %v", err)
	}
	if state.ECCount != 0 || state.KEMCount != 0 || state.HasLastResort {
		t.Fatalf("expected zero state after delete, got %+v", state)
	}

	var knf *keys.PreKeyNotFoundError

	_, err = s.GetSignedPreKey(ctx, aci, 1)
	if !errors.As(err, &knf) {
		t.Fatalf("expected PreKeyNotFoundError for signed after delete, got %T: %v", err, err)
	}

	_, err = s.GetKEMLastResortPreKey(ctx, aci, 1)
	if !errors.As(err, &knf) {
		t.Fatalf("expected PreKeyNotFoundError for last-resort after delete, got %T: %v", err, err)
	}
}

func TestPreKeys_DeleteAllForDevice_LeavesOtherDevices(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	for _, dev := range []uint64{1, 2} {
		if err := s.StoreECPreKeys(ctx, aci, dev, []*keys.PreKey{
			{KeyID: dev, PublicKey: []byte{byte(dev)}},
		}); err != nil {
			t.Fatalf("StoreECPreKeys device %d: %v", dev, err)
		}
	}

	if err := s.DeleteAllForDevice(ctx, aci, 1); err != nil {
		t.Fatalf("DeleteAllForDevice(1): %v", err)
	}

	state1, _ := s.GetPreKeyCount(ctx, aci, 1)
	if state1.ECCount != 0 {
		t.Fatalf("device 1 ECCount should be 0, got %d", state1.ECCount)
	}

	state2, _ := s.GetPreKeyCount(ctx, aci, 2)
	if state2.ECCount != 1 {
		t.Fatalf("device 2 ECCount should be 1, got %d", state2.ECCount)
	}
}

// --- DeleteAllForAccount ---

func TestPreKeys_DeleteAllForAccount_ClearsAllDevices(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	for _, dev := range []uint64{1, 2, 3} {
		if err := s.StoreECPreKeys(ctx, aci, dev, []*keys.PreKey{
			{KeyID: dev, PublicKey: []byte{byte(dev)}},
		}); err != nil {
			t.Fatalf("StoreECPreKeys device %d: %v", dev, err)
		}
	}

	if err := s.DeleteAllForAccount(ctx, aci); err != nil {
		t.Fatalf("DeleteAllForAccount: %v", err)
	}

	for _, dev := range []uint64{1, 2, 3} {
		state, err := s.GetPreKeyCount(ctx, aci, dev)
		if err != nil {
			t.Fatalf("GetPreKeyCount device %d: %v", dev, err)
		}
		if state.ECCount != 0 {
			t.Fatalf("device %d ECCount should be 0 after account delete, got %d", dev, state.ECCount)
		}
	}
}

// TestPreKeys_StoreKEMLastResortPreKey_NilKey exercises the nil guard.
func TestPreKeys_StoreKEMLastResortPreKey_NilKey_ReturnsError(t *testing.T) {
	s, _ := newPreKeyStore(t)

	err := s.StoreKEMLastResortPreKey(context.Background(), uuid.NewString(), 1, nil)
	if err == nil {
		t.Fatal("expected error for nil last-resort key")
	}
}

// TestPreKeys_StoreSignedPreKey_NilKey exercises the nil guard.
func TestPreKeys_StoreSignedPreKey_NilKey_ReturnsError(t *testing.T) {
	s, _ := newPreKeyStore(t)

	err := s.StoreSignedPreKey(context.Background(), uuid.NewString(), 1, nil)
	if err == nil {
		t.Fatal("expected error for nil signed pre-key")
	}
}

// TestPreKeys_StoreECPreKeys_EmptySlice clears existing keys for the device
// without inserting any new ones — exercises the early return after DELETE.
func TestPreKeys_StoreECPreKeys_EmptySlice_ClearsDevice(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{
		{KeyID: 1, PublicKey: []byte{0x01}},
	}); err != nil {
		t.Fatalf("StoreECPreKeys seed: %v", err)
	}

	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{}); err != nil {
		t.Fatalf("StoreECPreKeys empty: %v", err)
	}

	state, err := s.GetPreKeyCount(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount: %v", err)
	}
	if state.ECCount != 0 {
		t.Fatalf("expected ECCount=0 after empty StoreEC, got %d", state.ECCount)
	}
}

// TestPreKeys_StoreKEMPreKeys_EmptySlice clears existing keys for the device
// without inserting any new ones — exercises the early return after DELETE.
func TestPreKeys_StoreKEMPreKeys_EmptySlice_ClearsDevice(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreKEMPreKeys(ctx, aci, 1, []*keys.KEMSignedPreKey{
		{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x11}},
	}); err != nil {
		t.Fatalf("StoreKEMPreKeys seed: %v", err)
	}

	if err := s.StoreKEMPreKeys(ctx, aci, 1, []*keys.KEMSignedPreKey{}); err != nil {
		t.Fatalf("StoreKEMPreKeys empty: %v", err)
	}

	state, err := s.GetPreKeyCount(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount: %v", err)
	}
	if state.KEMCount != 0 {
		t.Fatalf("expected KEMCount=0 after empty StoreKEM, got %d", state.KEMCount)
	}
}

// TestPreKeys_DeleteAllForAccount_NoRows verifies DeleteAllForAccount on an
// account with no pre-keys succeeds without error.
func TestPreKeys_DeleteAllForAccount_NoRows_Succeeds(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.DeleteAllForAccount(ctx, aci); err != nil {
		t.Fatalf("DeleteAllForAccount on empty account: %v", err)
	}
}

// TestPreKeys_StoreECPreKeys_InsideTx exercises the withTxQuerier branch where
// the Querier is already a pgx.Tx (the "borrow existing tx" path).
func TestPreKeys_StoreECPreKeys_InsideTx(t *testing.T) {
	_, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	// Open an outer transaction and pass it as the Querier for the store.
	tx, err := c.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	s := NewPreKeyStore(tx)
	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{
		{KeyID: 5, PublicKey: []byte{0x05}},
	}); err != nil {
		t.Fatalf("StoreECPreKeys inside tx: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Verify the key is visible after commit.
	outerStore := NewPreKeyStore(c.Pool())
	state, err := outerStore.GetPreKeyCount(ctx, aci, 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount after tx commit: %v", err)
	}
	if state.ECCount != 1 {
		t.Fatalf("expected ECCount=1 after tx commit, got %d", state.ECCount)
	}
}

// TestPreKeys_TakeEC_Concurrent verifies that two concurrent TakeEC calls
// consume distinct keys (the atomic DELETE…RETURNING prevents duplication).
func TestPreKeys_TakeEC_Concurrent_ConsumesDistinctKeys(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()
	aci := uuid.NewString()
	seedAccount(t, c, aci)

	if err := s.StoreECPreKeys(ctx, aci, 1, []*keys.PreKey{
		{KeyID: 1, PublicKey: []byte{0x01}},
		{KeyID: 2, PublicKey: []byte{0x02}},
	}); err != nil {
		t.Fatalf("StoreECPreKeys: %v", err)
	}

	results := make(chan uint64, 2)
	for range 2 {
		go func() {
			pk, err := s.TakeEC(ctx, aci, 1)
			if err != nil {
				results <- 0
				return
			}
			results <- pk.KeyID
		}()
	}

	id1 := <-results
	id2 := <-results
	if id1 == id2 {
		t.Fatalf("concurrent TakeEC returned duplicate KeyID %d", id1)
	}
}

func TestPreKeys_StoreECPreKeys_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	err := s.StoreECPreKeys(context.Background(), uuid.NewString(), 1, []*keys.PreKey{
		{KeyID: 1, PublicKey: []byte{0x01}},
	})
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestPreKeys_StoreKEMPreKeys_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	err := s.StoreKEMPreKeys(context.Background(), uuid.NewString(), 1, []*keys.KEMSignedPreKey{
		{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x11}},
	})
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestPreKeys_TakeEC_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	_, err := s.TakeEC(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *keys.PreKeyNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not PreKeyNotFoundError")
	}
}

func TestPreKeys_TakeKEM_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	_, err := s.TakeKEM(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *keys.PreKeyNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not PreKeyNotFoundError")
	}
}

func TestPreKeys_GetSignedPreKey_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	_, err := s.GetSignedPreKey(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *keys.PreKeyNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not PreKeyNotFoundError")
	}
}

func TestPreKeys_GetKEMLastResort_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	_, err := s.GetKEMLastResortPreKey(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *keys.PreKeyNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not PreKeyNotFoundError")
	}
}

func TestPreKeys_StoreKEMLastResortPreKey_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	err := s.StoreKEMLastResortPreKey(context.Background(), uuid.NewString(), 1,
		&keys.KEMSignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x11}})
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestPreKeys_StoreSignedPreKey_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	err := s.StoreSignedPreKey(context.Background(), uuid.NewString(), 1,
		&keys.SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x11}})
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestPreKeys_GetPreKeyCount_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	_, err := s.GetPreKeyCount(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestPreKeys_DeleteAllForDevice_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	err := s.DeleteAllForDevice(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestPreKeys_DeleteAllForAccount_PoolClosed_ReturnsError(t *testing.T) {
	s, c := newPreKeyStore(t)
	c.Close()

	err := s.DeleteAllForAccount(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestPreKeys_DeleteAllForAccount_LeavesOtherAccounts(t *testing.T) {
	s, c := newPreKeyStore(t)
	ctx := context.Background()

	aci1 := uuid.NewString()
	aci2 := uuid.NewString()
	seedAccount(t, c, aci1)
	seedAccount(t, c, aci2)

	if err := s.StoreECPreKeys(ctx, aci1, 1, []*keys.PreKey{{KeyID: 1, PublicKey: []byte{0x01}}}); err != nil {
		t.Fatalf("StoreECPreKeys aci1: %v", err)
	}
	if err := s.StoreECPreKeys(ctx, aci2, 1, []*keys.PreKey{{KeyID: 2, PublicKey: []byte{0x02}}}); err != nil {
		t.Fatalf("StoreECPreKeys aci2: %v", err)
	}

	if err := s.DeleteAllForAccount(ctx, aci1); err != nil {
		t.Fatalf("DeleteAllForAccount(aci1): %v", err)
	}

	state1, _ := s.GetPreKeyCount(ctx, aci1, 1)
	if state1.ECCount != 0 {
		t.Fatalf("aci1 ECCount should be 0, got %d", state1.ECCount)
	}

	state2, _ := s.GetPreKeyCount(ctx, aci2, 1)
	if state2.ECCount != 1 {
		t.Fatalf("aci2 ECCount should be 1, got %d", state2.ECCount)
	}
}

// TestPreKeys_withTxQuerier_NonBeginner exercises the branch in withTxQuerier
// (keys.go:309-311) where the Querier satisfies neither pgx.Tx nor the
// beginner interface that exposes BeginTx. The store wraps a noTxQuerier
// (defined in testhelpers_test.go) which only exposes the four Querier
// methods, so withTxQuerier cannot open a transaction and returns an error.
func TestPreKeys_withTxQuerier_NonBeginner_ReturnsError(t *testing.T) {
	// newTestClient is called only to verify connectivity and run migrations;
	// the test does not need the DB for the actual assertion.
	c := newTestClient(t)
	q := noTxQuerier{c.Pool()}
	s := NewPreKeyStore(q)

	err := s.StoreECPreKeys(context.Background(), uuid.NewString(), 1, []*keys.PreKey{
		{KeyID: 1, PublicKey: []byte{0x01}},
	})
	if err == nil {
		t.Fatal("expected error from non-beginner Querier, got nil")
	}
	const want = "postgres prekeys: querier does not support transactions"
	if !strings.Contains(err.Error(), "querier does not support transactions") {
		t.Fatalf("expected %q in error, got: %v", want, err)
	}
}

// TestPreKeys_withTxQuerier_FnError covers the branch in withTxQuerier
// (keys.go:317-319) where BeginTx succeeds but fn returns an error. The
// function is called directly (same package) with a fn that always fails.
func TestPreKeys_withTxQuerier_FnError(t *testing.T) {
	c := newTestClient(t)
	sentinel := errors.New("injected fn error")

	err := withTxQuerier(context.Background(), c.Pool(), func(_ pgx.Tx) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error propagated from fn, got: %v", err)
	}
}
