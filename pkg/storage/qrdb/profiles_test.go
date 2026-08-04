package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

func newProfile(uuid, version, name string) *profiles.Profile {
	return &profiles.Profile{
		UUID:    uuid,
		Version: version,
		Name:    []byte(name),
	}
}

func TestProfileStore_Set_GetByVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewProfileStore(NewFakeKVStore())

	if err := s.Set(ctx, newProfile("u1", "v1", "alice")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get(ctx, "u1", "v1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Name) != "alice" {
		t.Fatalf("wrong profile: %+v", got)
	}
}

func TestProfileStore_Set_Invalid(t *testing.T) {
	t.Parallel()
	s := NewProfileStore(NewFakeKVStore())
	if err := s.Set(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil profile")
	}
	if err := s.Set(context.Background(), &profiles.Profile{Version: "v1"}); err == nil {
		t.Fatal("expected error for empty UUID")
	}
	if err := s.Set(context.Background(), &profiles.Profile{UUID: "u1"}); err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestProfileStore_GetLatest_ReflectsMostRecentSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewProfileStore(NewFakeKVStore())

	if err := s.Set(ctx, newProfile("u1", "v1", "first")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, newProfile("u1", "v2", "second")); err != nil {
		t.Fatal(err)
	}

	latest, err := s.GetLatest(ctx, "u1")
	if err != nil {
		t.Fatalf("GetLatest: %v", err)
	}
	if string(latest.Name) != "second" {
		t.Fatalf("GetLatest not the most recent: %+v", latest)
	}
}

func TestProfileStore_Get_Missing_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewProfileStore(NewFakeKVStore())
	_, err := s.Get(context.Background(), "u1", "v1")
	var pnfe *profiles.ProfileNotFoundError
	if !errors.As(err, &pnfe) {
		t.Fatalf("expected ProfileNotFoundError, got %T: %v", err, err)
	}
}

func TestProfileStore_GetLatest_Missing(t *testing.T) {
	t.Parallel()
	s := NewProfileStore(NewFakeKVStore())
	_, err := s.GetLatest(context.Background(), "u1")
	var pnfe *profiles.ProfileNotFoundError
	if !errors.As(err, &pnfe) {
		t.Fatalf("expected ProfileNotFoundError, got %T: %v", err, err)
	}
}

func TestProfileStore_Delete_RemovesAllVersions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewProfileStore(NewFakeKVStore())

	if err := s.Set(ctx, newProfile("u1", "v1", "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, newProfile("u1", "v2", "b")); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(ctx, "u1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.Get(ctx, "u1", "v1"); err == nil {
		t.Fatal("expected v1 to be absent")
	}
	if _, err := s.Get(ctx, "u1", "v2"); err == nil {
		t.Fatal("expected v2 to be absent")
	}
	if _, err := s.GetLatest(ctx, "u1"); err == nil {
		t.Fatal("expected latest mirror to be absent")
	}
}
