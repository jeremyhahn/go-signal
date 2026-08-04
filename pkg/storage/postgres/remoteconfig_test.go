package postgres

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
)

func TestRemoteConfigStore_Validation(t *testing.T) {
	s := &RemoteConfigStore{}
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

func TestRemoteConfigStore_PutGetRoundTrip(t *testing.T) {
	c := newTestClient(t)
	s := NewRemoteConfigStore(c)
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
		t.Errorf("scalar drift: got %+v", got)
	}
	if len(got.UUIDs) != 2 || got.UUIDs["u1"] != struct{}{} || got.UUIDs["u2"] != struct{}{} {
		t.Errorf("UUIDs drift: %v", got.UUIDs)
	}
}

func TestRemoteConfigStore_PutReplacesExistingRow(t *testing.T) {
	c := newTestClient(t)
	s := NewRemoteConfigStore(c)
	ctx := context.Background()

	_ = s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 10, Value: "v1"})
	_ = s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 80, Value: "v2"})

	rows, _ := s.GetAll(ctx)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Percentage != 80 || rows[0].Value != "v2" {
		t.Errorf("upsert did not replace: %+v", rows[0])
	}
}

func TestRemoteConfigStore_GetAllSortedByName(t *testing.T) {
	c := newTestClient(t)
	s := NewRemoteConfigStore(c)
	ctx := context.Background()

	for _, name := range []string{"zeta", "alpha", "mu"} {
		_ = s.Put(ctx, remoteconfig.Config{Name: name, Percentage: 0})
	}
	rows, _ := s.GetAll(ctx)
	got := []string{rows[0].Name, rows[1].Name, rows[2].Name}
	want := []string{"alpha", "mu", "zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rows[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRemoteConfigStore_DeleteRemovesRow(t *testing.T) {
	c := newTestClient(t)
	s := NewRemoteConfigStore(c)
	ctx := context.Background()

	_ = s.Put(ctx, remoteconfig.Config{Name: "doomed", Percentage: 50})
	if err := s.Delete(ctx, "doomed"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	rows, _ := s.GetAll(ctx)
	if len(rows) != 0 {
		t.Errorf("expected 0 rows post-Delete, got %d", len(rows))
	}
}

func TestRemoteConfigStore_DeleteMissingIsIdempotent(t *testing.T) {
	c := newTestClient(t)
	s := NewRemoteConfigStore(c)
	if err := s.Delete(context.Background(), "absent"); err != nil {
		t.Errorf("Delete of missing row returned %v, want nil", err)
	}
	if err := s.Delete(context.Background(), ""); err != nil {
		t.Errorf("Delete of empty name returned %v, want nil", err)
	}
}

func TestRemoteConfigStore_EmptyUUIDsRoundTrip(t *testing.T) {
	c := newTestClient(t)
	s := NewRemoteConfigStore(c)
	ctx := context.Background()

	_ = s.Put(ctx, remoteconfig.Config{Name: "k", Percentage: 0, UUIDs: nil})
	rows, _ := s.GetAll(ctx)
	if rows[0].UUIDs != nil {
		t.Errorf("empty UUIDs should round-trip as nil, got %v", rows[0].UUIDs)
	}
}
