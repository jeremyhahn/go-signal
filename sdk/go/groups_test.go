package signal

import (
	"context"
	"errors"
	"testing"
)

func TestClient_CreateGroup_Success(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	opts := CreateGroupOptions{
		Name:        "Test Group",
		Description: "A test group",
		Members:     []string{"+15550000001", "+15550000002"},
	}
	group, err := c.CreateGroup(context.Background(), opts)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if group.Name != "Test Group" {
		t.Errorf("Name = %q", group.Name)
	}
	if group.Description != "A test group" {
		t.Errorf("Description = %q", group.Description)
	}
	if len(ms.groups) != 1 {
		t.Errorf("expected 1 group in store, got %d", len(ms.groups))
	}
}

func TestClient_CreateGroup_StoreFails(t *testing.T) {
	ms := &mockStore{saveGroupErr: errors.New("save failed")}
	c := newTestClient(t, "http://localhost", ms)
	_, err := c.CreateGroup(context.Background(), CreateGroupOptions{Name: "Fail"})
	if err == nil {
		t.Fatal("expected error when store fails")
	}
}

func TestClient_ListGroups_Empty(t *testing.T) {
	c := newTestClient(t, "http://localhost", &mockStore{})
	groups, err := c.ListGroups(context.Background())
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}

func TestClient_ListGroups_WithGroups(t *testing.T) {
	ms := &mockStore{
		groups: []Group{
			{ID: "g1", Name: "Group 1"},
			{ID: "g2", Name: "Group 2"},
		},
	}
	c := newTestClient(t, "http://localhost", ms)
	groups, err := c.ListGroups(context.Background())
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestClient_UpdateGroup_Success(t *testing.T) {
	ms := &mockStore{
		groups: []Group{{ID: "g1", Name: "Old Name"}},
	}
	c := newTestClient(t, "http://localhost", ms)
	updated, err := c.UpdateGroup(context.Background(), "g1", CreateGroupOptions{Name: "New Name", Description: "Desc"})
	if err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if updated.Name != "New Name" {
		t.Errorf("Name = %q", updated.Name)
	}
	if updated.Description != "Desc" {
		t.Errorf("Description = %q", updated.Description)
	}
}

func TestClient_UpdateGroup_NotFound(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	_, err := c.UpdateGroup(context.Background(), "nonexistent", CreateGroupOptions{Name: "X"})
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
}

func TestClient_UpdateGroup_NoChanges(t *testing.T) {
	ms := &mockStore{
		groups: []Group{{ID: "g1", Name: "Existing"}},
	}
	c := newTestClient(t, "http://localhost", ms)
	// Empty opts — name/description unchanged.
	updated, err := c.UpdateGroup(context.Background(), "g1", CreateGroupOptions{})
	if err != nil {
		t.Fatalf("UpdateGroup empty opts: %v", err)
	}
	if updated.Name != "Existing" {
		t.Errorf("Name = %q, expected Existing", updated.Name)
	}
}

func TestClient_QuitGroup_Found(t *testing.T) {
	ms := &mockStore{
		groups: []Group{{ID: "g1", Name: "Group 1"}},
	}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.QuitGroup(context.Background(), "g1"); err != nil {
		t.Fatalf("QuitGroup: %v", err)
	}
}

func TestClient_QuitGroup_NotFound(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	// Quitting a non-existent group is a no-op.
	if err := c.QuitGroup(context.Background(), "nobody"); err != nil {
		t.Fatalf("QuitGroup non-existent: %v", err)
	}
}

func TestClient_JoinGroup_Success(t *testing.T) {
	ms := &mockStore{}
	c := newTestClient(t, "http://localhost", ms)
	group, err := c.JoinGroup(context.Background(), "https://signal.group/#link")
	if err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}
	if group == nil {
		t.Fatal("expected non-nil group")
	}
	if len(ms.groups) != 1 {
		t.Errorf("expected 1 group in store, got %d", len(ms.groups))
	}
}

func TestClient_JoinGroup_StoreFails(t *testing.T) {
	ms := &mockStore{saveGroupErr: errors.New("store error")}
	c := newTestClient(t, "http://localhost", ms)
	_, err := c.JoinGroup(context.Background(), "link")
	if err == nil {
		t.Fatal("expected error when store fails")
	}
}
