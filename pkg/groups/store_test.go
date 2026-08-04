package groups

import (
	"context"
	"testing"
)

// stubGroupStore is a minimal GroupStore implementation used to verify that
// the interface is satisfied without a concrete dependency.
type stubGroupStore struct {
	createFn func(ctx context.Context, group *Group) error
	getFn    func(ctx context.Context, groupID string) (*Group, error)
	updateFn func(ctx context.Context, group *Group) error
	deleteFn func(ctx context.Context, groupID string) error
}

func (s *stubGroupStore) Create(ctx context.Context, group *Group) error {
	if s.createFn != nil {
		return s.createFn(ctx, group)
	}
	return nil
}

func (s *stubGroupStore) Get(ctx context.Context, groupID string) (*Group, error) {
	if s.getFn != nil {
		return s.getFn(ctx, groupID)
	}
	return &Group{ID: groupID, Revision: 1}, nil
}

func (s *stubGroupStore) Update(ctx context.Context, group *Group) error {
	if s.updateFn != nil {
		return s.updateFn(ctx, group)
	}
	return nil
}

func (s *stubGroupStore) Delete(ctx context.Context, groupID string) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, groupID)
	}
	return nil
}

// Compile-time assertion: stubGroupStore satisfies GroupStore.
var _ GroupStore = (*stubGroupStore)(nil)

func TestGroupStore_StubSatisfiesInterface(t *testing.T) {
	// The compile-time assertion above already verifies interface satisfaction.
	// Confirm the stub is usable without panicking.
	store := &stubGroupStore{}
	if err := store.Create(context.Background(), &Group{ID: "check"}); err != nil {
		t.Fatalf("unexpected error from stub Create: %v", err)
	}
}

func TestGroupStore_StubCreate_ReturnsNilByDefault(t *testing.T) {
	store := &stubGroupStore{}
	err := store.Create(context.Background(), &Group{ID: "g1"})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestGroupStore_StubGet_ReturnsGroup(t *testing.T) {
	store := &stubGroupStore{}
	g, err := store.Get(context.Background(), "g-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ID != "g-abc" {
		t.Errorf("got %q, want %q", g.ID, "g-abc")
	}
}

func TestGroupStore_StubDelete_ReturnsNilByDefault(t *testing.T) {
	store := &stubGroupStore{}
	err := store.Delete(context.Background(), "g1")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestGroupStore_StubUpdate_CallsUpdateFn(t *testing.T) {
	called := false
	store := &stubGroupStore{
		updateFn: func(_ context.Context, group *Group) error {
			called = true
			return nil
		},
	}
	if err := store.Update(context.Background(), &Group{ID: "g1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("expected updateFn to be called")
	}
}
