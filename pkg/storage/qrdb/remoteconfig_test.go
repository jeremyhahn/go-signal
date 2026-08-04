package qrdb

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
)

func TestQrdbRemoteConfigStore_Validation(t *testing.T) {
	s := NewRemoteConfigStore(NewFakeKVStore())
	if err := s.Put(context.Background(), remoteconfig.Config{}); err == nil {
		t.Error("expected error for empty Name")
	}
	if err := s.Put(context.Background(), remoteconfig.Config{Name: "x", Percentage: -1}); err == nil {
		t.Error("expected error for negative Percentage")
	}
	if err := s.Put(context.Background(), remoteconfig.Config{Name: "x", Percentage: 101}); err == nil {
		t.Error("expected error for Percentage > 100")
	}
}

func TestQrdbRemoteConfigStore_PutGetRoundTrip(t *testing.T) {
	s := NewRemoteConfigStore(NewFakeKVStore())
	ctx := context.Background()

	in := remoteconfig.Config{
		Name:         "global.calling",
		Percentage:   42,
		UUIDs:        map[string]struct{}{"u1": {}, "u2": {}},
		Value:        "on",
		DefaultValue: "off",
		HashKey:      "calling-v2",
	}
	if err := s.Put(ctx, in); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rows, err := s.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	got := rows[0]
	if got.Name != in.Name || got.Percentage != in.Percentage ||
		got.Value != in.Value || got.DefaultValue != in.DefaultValue ||
		got.HashKey != in.HashKey {
		t.Errorf("scalar drift: %+v", got)
	}
	if len(got.UUIDs) != 2 || got.UUIDs["u1"] != struct{}{} || got.UUIDs["u2"] != struct{}{} {
		t.Errorf("UUIDs drift: %v", got.UUIDs)
	}
}

func TestQrdbRemoteConfigStore_PutReplacesRow(t *testing.T) {
	s := NewRemoteConfigStore(NewFakeKVStore())
	ctx := context.Background()
	_ = s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 10, Value: "v1"})
	_ = s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 80, Value: "v2"})

	rows, _ := s.GetAll(ctx)
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	if rows[0].Percentage != 80 || rows[0].Value != "v2" {
		t.Errorf("upsert did not replace: %+v", rows[0])
	}
}

func TestQrdbRemoteConfigStore_GetAllSorted(t *testing.T) {
	s := NewRemoteConfigStore(NewFakeKVStore())
	ctx := context.Background()
	for _, n := range []string{"zeta", "alpha", "mu"} {
		_ = s.Put(ctx, remoteconfig.Config{Name: n, Percentage: 0})
	}
	rows, _ := s.GetAll(ctx)
	want := []string{"alpha", "mu", "zeta"}
	for i, w := range want {
		if rows[i].Name != w {
			t.Errorf("rows[%d] = %q, want %q", i, rows[i].Name, w)
		}
	}
}

func TestQrdbRemoteConfigStore_DeleteRemovesRow(t *testing.T) {
	s := NewRemoteConfigStore(NewFakeKVStore())
	ctx := context.Background()
	_ = s.Put(ctx, remoteconfig.Config{Name: "doomed", Percentage: 50})
	if err := s.Delete(ctx, "doomed"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	rows, _ := s.GetAll(ctx)
	if len(rows) != 0 {
		t.Errorf("expected 0 rows, got %d", len(rows))
	}
}

func TestQrdbRemoteConfigStore_DeleteMissingIsIdempotent(t *testing.T) {
	s := NewRemoteConfigStore(NewFakeKVStore())
	if err := s.Delete(context.Background(), "absent"); err != nil {
		t.Errorf("Delete missing returned %v, want nil", err)
	}
	if err := s.Delete(context.Background(), ""); err != nil {
		t.Errorf("Delete empty returned %v, want nil", err)
	}
}

func TestQrdbRemoteConfigStore_EmptyUUIDsRoundTrip(t *testing.T) {
	s := NewRemoteConfigStore(NewFakeKVStore())
	ctx := context.Background()
	_ = s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 0})
	rows, _ := s.GetAll(ctx)
	if rows[0].UUIDs != nil {
		t.Errorf("empty UUIDs should round-trip as nil, got %v", rows[0].UUIDs)
	}
}
