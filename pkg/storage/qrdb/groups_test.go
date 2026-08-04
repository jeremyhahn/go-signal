package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/groups"
)

func newGroup(id string) *groups.Group {
	return &groups.Group{
		ID:       id,
		Title:    []byte("encrypted-title"),
		Revision: 1,
	}
}

func TestGroupStore_Create_And_Get(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewGroupStore(NewFakeKVStore())

	if err := s.Create(ctx, newGroup("g1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, "g1")
	if err != nil || got.ID != "g1" {
		t.Fatalf("Get: err=%v got=%+v", err, got)
	}
}

func TestGroupStore_Create_NilOrEmpty_Rejected(t *testing.T) {
	t.Parallel()
	s := NewGroupStore(NewFakeKVStore())
	if err := s.Create(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil group")
	}
	if err := s.Create(context.Background(), &groups.Group{}); err == nil {
		t.Fatal("expected error for empty ID")
	}
}

func TestGroupStore_Create_Duplicate_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewGroupStore(NewFakeKVStore())

	if err := s.Create(ctx, newGroup("g1")); err != nil {
		t.Fatal(err)
	}
	err := s.Create(ctx, newGroup("g1"))
	var aee *groups.GroupAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected GroupAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestGroupStore_Get_Missing(t *testing.T) {
	t.Parallel()
	s := NewGroupStore(NewFakeKVStore())
	_, err := s.Get(context.Background(), "missing")
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError, got %T: %v", err, err)
	}
}

func TestGroupStore_Update_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewGroupStore(NewFakeKVStore())

	g := newGroup("g1")
	if err := s.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	updated := *g
	updated.Revision = 2
	updated.Title = []byte("new-title")
	if err := s.Update(ctx, &updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := s.Get(ctx, "g1")
	if got.Revision != 2 || string(got.Title) != "new-title" {
		t.Fatalf("update did not persist: %+v", got)
	}
}

func TestGroupStore_Update_WrongRevision_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewGroupStore(NewFakeKVStore())

	if err := s.Create(ctx, newGroup("g1")); err != nil {
		t.Fatal(err)
	}
	stale := newGroup("g1")
	stale.Revision = 99
	err := s.Update(ctx, stale)
	var vce *groups.GroupVersionConflictError
	if !errors.As(err, &vce) {
		t.Fatalf("expected GroupVersionConflictError, got %T: %v", err, err)
	}
}

func TestGroupStore_Update_NilOrMissing(t *testing.T) {
	t.Parallel()
	s := NewGroupStore(NewFakeKVStore())
	if err := s.Update(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil group")
	}
	err := s.Update(context.Background(), newGroup("absent"))
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError, got %T: %v", err, err)
	}
}

func TestGroupStore_Delete_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewGroupStore(NewFakeKVStore())

	if err := s.Create(ctx, newGroup("g1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "g1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Get(ctx, "g1")
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError after Delete, got %T: %v", err, err)
	}
}

func TestGroupStore_Delete_Missing(t *testing.T) {
	t.Parallel()
	s := NewGroupStore(NewFakeKVStore())
	err := s.Delete(context.Background(), "absent")
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError, got %T: %v", err, err)
	}
}
