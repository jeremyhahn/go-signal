package messages

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	redisv9 "github.com/redis/go-redis/v9"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"

	cacheredis "github.com/jeremyhahn/go-signal/pkg/cache/redis"
)

// newMrmTestCache spins up a miniredis-backed MRMCache for tests. The
// miniredis handle is returned for time-travel and direct hash inspection.
func newMrmTestCache(t *testing.T) (*MRMCache, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cli := cacheredis.NewFromClient(rdb)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewMRMCache(cli, logger), mr
}

func mrmTestServiceID(t *testing.T, lastByte byte) protocol.ServiceId {
	t.Helper()
	var u [16]byte
	u[15] = lastByte
	return protocol.NewServiceId(protocol.ServiceIdKindACI, u)
}

func TestSharedMRMKey_Format(t *testing.T) {
	g, err := uuid.Parse("11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	got := SharedMRMKey(g)
	want := "mrm::{11111111-2222-3333-4444-555555555555}"
	if got != want {
		t.Errorf("SharedMRMKey = %q, want %q", got, want)
	}
}

func TestSharedMRMViewKey_LengthAndFormat(t *testing.T) {
	sid := mrmTestServiceID(t, 0x42)
	key := SharedMRMViewKey(sid, 7)
	if len(key) != 18 {
		t.Fatalf("view key length = %d, want 18", len(key))
	}
	fw := sid.FixedWidthBinary()
	if string(key[:17]) != string(fw[:]) {
		t.Errorf("first 17 bytes don't match ServiceId FixedWidthBinary")
	}
	if key[17] != 7 {
		t.Errorf("device byte = %d, want 7", key[17])
	}
}

func TestMRMCache_InsertGetRoundtrip(t *testing.T) {
	c, _ := newMrmTestCache(t)
	ctx := context.Background()

	g := uuid.New()
	shared := SharedMRMKey(g)
	view := SharedMRMViewKey(mrmTestServiceID(t, 1), 1)
	data := []byte("multi-recipient ciphertext bytes")
	viewBytes := []byte("recipient view bytes")

	if err := c.Insert(ctx, shared, data, map[string][]byte{view: viewBytes}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	gotData, gotView, err := c.Get(ctx, shared, view)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(gotData) != string(data) {
		t.Errorf("data = %q, want %q", gotData, data)
	}
	if string(gotView) != string(viewBytes) {
		t.Errorf("view = %q, want %q", gotView, viewBytes)
	}
}

func TestMRMCache_InsertDuplicateReturnsErrKeyExists(t *testing.T) {
	c, _ := newMrmTestCache(t)
	ctx := context.Background()

	g := uuid.New()
	shared := SharedMRMKey(g)
	views := map[string][]byte{
		SharedMRMViewKey(mrmTestServiceID(t, 1), 1): []byte("v1"),
	}

	if err := c.Insert(ctx, shared, []byte("first"), views); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	err := c.Insert(ctx, shared, []byte("second"), views)
	if !errors.Is(err, ErrMRMKeyExists) {
		t.Fatalf("expected ErrMRMKeyExists, got %v", err)
	}
}

func TestMRMCache_GetDataMissing(t *testing.T) {
	c, _ := newMrmTestCache(t)
	ctx := context.Background()

	_, _, err := c.Get(ctx, SharedMRMKey(uuid.New()), SharedMRMViewKey(mrmTestServiceID(t, 1), 1))
	if !errors.Is(err, ErrMRMDataMissing) {
		t.Errorf("expected ErrMRMDataMissing, got %v", err)
	}
}

func TestMRMCache_GetViewMissing_ReturnsNilView(t *testing.T) {
	c, _ := newMrmTestCache(t)
	ctx := context.Background()

	g := uuid.New()
	shared := SharedMRMKey(g)
	view := SharedMRMViewKey(mrmTestServiceID(t, 1), 1)
	if err := c.Insert(ctx, shared, []byte("data"), map[string][]byte{view: []byte("view")}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	otherView := SharedMRMViewKey(mrmTestServiceID(t, 2), 1)
	gotData, gotView, err := c.Get(ctx, shared, otherView)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(gotData) != "data" {
		t.Errorf("data = %q, want %q", gotData, "data")
	}
	if gotView != nil {
		t.Errorf("expected nil view for missing recipient, got %q", gotView)
	}
}

func TestMRMCache_RemoveRecipientView_LeavesOtherViewsAndData(t *testing.T) {
	c, mr := newMrmTestCache(t)
	ctx := context.Background()

	g := uuid.New()
	shared := SharedMRMKey(g)
	view1 := SharedMRMViewKey(mrmTestServiceID(t, 1), 1)
	view2 := SharedMRMViewKey(mrmTestServiceID(t, 2), 1)
	if err := c.Insert(ctx, shared, []byte("data"), map[string][]byte{
		view1: []byte("v1"),
		view2: []byte("v2"),
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	deleted, err := c.RemoveRecipientView(ctx, []string{shared}, view1)
	if err != nil {
		t.Fatalf("RemoveRecipientView: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted count = %d, want 0 (data + view2 still present)", deleted)
	}

	// view1 gone, data + view2 still in the hash.
	if mr.Exists(shared) != true {
		t.Error("hash should still exist (view2 + data remain)")
	}
	if dat := mr.HGet(shared, mrmDataField); dat != "data" {
		t.Errorf("data = %q, want %q", dat, "data")
	}
	if v2 := mr.HGet(shared, view2); v2 != "v2" {
		t.Errorf("view2 = %q, want %q", v2, "v2")
	}
}

func TestMRMCache_RemoveRecipientView_DeletesKeyWhenOnlyDataRemains(t *testing.T) {
	c, mr := newMrmTestCache(t)
	ctx := context.Background()

	g := uuid.New()
	shared := SharedMRMKey(g)
	view := SharedMRMViewKey(mrmTestServiceID(t, 1), 1)
	if err := c.Insert(ctx, shared, []byte("data"), map[string][]byte{view: []byte("v1")}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	deleted, err := c.RemoveRecipientView(ctx, []string{shared}, view)
	if err != nil {
		t.Fatalf("RemoveRecipientView: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted count = %d, want 1", deleted)
	}
	if mr.Exists(shared) {
		t.Error("hash should have been DEL'd once only `data` remained")
	}
}

func TestMRMCache_RemoveRecipientView_MultipleKeysMixed(t *testing.T) {
	c, mr := newMrmTestCache(t)
	ctx := context.Background()

	view := SharedMRMViewKey(mrmTestServiceID(t, 1), 1)

	// shared1 has only this one view + data → will be fully deleted.
	shared1 := SharedMRMKey(uuid.New())
	if err := c.Insert(ctx, shared1, []byte("data1"), map[string][]byte{view: []byte("v1")}); err != nil {
		t.Fatal(err)
	}

	// shared2 has this view + a second view + data → will retain data + v2.
	shared2 := SharedMRMKey(uuid.New())
	otherView := SharedMRMViewKey(mrmTestServiceID(t, 2), 1)
	if err := c.Insert(ctx, shared2, []byte("data2"), map[string][]byte{
		view:      []byte("v1"),
		otherView: []byte("v2"),
	}); err != nil {
		t.Fatal(err)
	}

	deleted, err := c.RemoveRecipientView(ctx, []string{shared1, shared2}, view)
	if err != nil {
		t.Fatalf("RemoveRecipientView: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted count = %d, want 1 (only shared1 fully removed)", deleted)
	}
	if mr.Exists(shared1) {
		t.Error("shared1 should have been DEL'd")
	}
	if !mr.Exists(shared2) {
		t.Error("shared2 should still exist")
	}
}

func TestMRMCache_RemoveRecipientView_EmptyKeysIsNoop(t *testing.T) {
	c, _ := newMrmTestCache(t)
	deleted, err := c.RemoveRecipientView(context.Background(), nil, "v")
	if err != nil {
		t.Fatalf("RemoveRecipientView: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted count = %d, want 0", deleted)
	}
}

func TestMRMCache_TTLAppliedOnInsert(t *testing.T) {
	c, mr := newMrmTestCache(t)
	ctx := context.Background()

	g := uuid.New()
	shared := SharedMRMKey(g)
	if err := c.Insert(ctx, shared, []byte("data"), nil); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got := mr.TTL(shared)
	want := time.Duration(MRMTTLSeconds) * time.Second
	if got != want {
		t.Errorf("TTL = %v, want %v", got, want)
	}
}
