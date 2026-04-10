package groups

import (
	"context"
	"log/slog"
	"testing"
)

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// adminMember returns a Member with the Administrator role for use in tests.
func adminMember(userID string) Member {
	return Member{
		UserID:       userID,
		Role:         MemberRoleAdministrator,
		ProfileKey:   []byte("profilekey"),
		Presentation: []byte("presentation"),
	}
}

// defaultMember returns a Member with the Default role for use in tests.
func defaultMember(userID string) Member {
	return Member{
		UserID:       userID,
		Role:         MemberRoleDefault,
		ProfileKey:   []byte("profilekey"),
		Presentation: []byte("presentation"),
	}
}

// newTestStore returns a MemoryGroupStore and a GroupsManager backed by it.
func newTestManager(t *testing.T) *GroupsManager {
	t.Helper()
	// Avoid importing the memory package here; use the stubGroupStore backed
	// by a real in-memory map so the manager_test stays within the groups
	// package boundary.
	return NewGroupsManager(newInlineStore(), testLogger())
}

// inlineStore is a simple in-process GroupStore backed by a map.
// It is embedded here to avoid a circular dependency with pkg/storage/memory.
type inlineStore struct {
	groups map[string]*Group
}

func newInlineStore() *inlineStore {
	return &inlineStore{groups: make(map[string]*Group)}
}

func (s *inlineStore) Create(_ context.Context, g *Group) error {
	if _, exists := s.groups[g.ID]; exists {
		return &GroupAlreadyExistsError{GroupID: g.ID}
	}
	clone := *g
	s.groups[g.ID] = &clone
	return nil
}

func (s *inlineStore) Get(_ context.Context, id string) (*Group, error) {
	g, exists := s.groups[id]
	if !exists {
		return nil, &GroupNotFoundError{GroupID: id}
	}
	clone := *g
	return &clone, nil
}

func (s *inlineStore) Update(_ context.Context, g *Group) error {
	existing, exists := s.groups[g.ID]
	if !exists {
		return &GroupNotFoundError{GroupID: g.ID}
	}
	if g.Revision != existing.Revision+1 {
		return &GroupVersionConflictError{
			GroupID:         g.ID,
			ExpectedVersion: existing.Revision + 1,
			ActualVersion:   g.Revision,
		}
	}
	clone := *g
	s.groups[g.ID] = &clone
	return nil
}

func (s *inlineStore) Delete(_ context.Context, id string) error {
	if _, exists := s.groups[id]; !exists {
		return &GroupNotFoundError{GroupID: id}
	}
	delete(s.groups, id)
	return nil
}

// --------------------------------------------------------------------------
// NewGroupsManager
// --------------------------------------------------------------------------

func TestNewGroupsManager_NotNil(t *testing.T) {
	m := NewGroupsManager(newInlineStore(), testLogger())
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewGroupsManager_StoresLogger(t *testing.T) {
	logger := testLogger()
	m := NewGroupsManager(newInlineStore(), logger)
	if m.logger != logger {
		t.Error("logger not stored correctly")
	}
}

// --------------------------------------------------------------------------
// Create
// --------------------------------------------------------------------------

func TestCreate_Success(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{
		ID:      "group-1",
		Members: []Member{adminMember("admin-uuid")},
	}
	g, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ID != "group-1" {
		t.Errorf("got ID %q, want %q", g.ID, "group-1")
	}
	if g.Revision != 1 {
		t.Errorf("got revision %d, want 1", g.Revision)
	}
}

func TestCreate_SetsTimestamps(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{
		ID:      "group-ts",
		Members: []Member{adminMember("admin-uuid")},
	}
	g, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
	if g.UpdatedAt.IsZero() {
		t.Error("expected non-zero UpdatedAt")
	}
}

func TestCreate_EmptyID_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{
		Members: []Member{adminMember("admin-uuid")},
	}
	_, err := m.Create(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty ID")
	}
	if !isInvalidGroupArg(err) {
		t.Errorf("expected *InvalidGroupArgumentError, got %T", err)
	}
}

func TestCreate_NoMembers_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{ID: "g1"}
	_, err := m.Create(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty members")
	}
}

func TestCreate_NoAdmin_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{
		ID:      "g1",
		Members: []Member{defaultMember("user-1")},
	}
	_, err := m.Create(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when no administrator present")
	}
	if !isInvalidGroupArg(err) {
		t.Errorf("expected *InvalidGroupArgumentError, got %T", err)
	}
}

func TestCreate_DuplicateID_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{
		ID:      "dup-group",
		Members: []Member{adminMember("admin-1")},
	}
	if _, err := m.Create(context.Background(), req); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	_, err := m.Create(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for duplicate group ID")
	}
	if _, ok := err.(*GroupAlreadyExistsError); !ok {
		t.Errorf("expected *GroupAlreadyExistsError, got %T", err)
	}
}

func TestCreate_WithPendingMembers(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{
		ID:      "g-pending",
		Members: []Member{adminMember("admin-1")},
		PendingMembers: []PendingMember{
			{ServiceID: "invited-1", Role: MemberRoleDefault},
		},
	}
	g, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.PendingMembers) != 1 {
		t.Errorf("got %d pending members, want 1", len(g.PendingMembers))
	}
}

func TestCreate_WithTitle(t *testing.T) {
	m := newTestManager(t)
	title := []byte("encrypted-title")
	req := CreateGroupRequest{
		ID:      "g-title",
		Members: []Member{adminMember("admin-1")},
		Title:   title,
	}
	g, err := m.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(g.Title) != string(title) {
		t.Errorf("got title %q, want %q", g.Title, title)
	}
}

// --------------------------------------------------------------------------
// Get
// --------------------------------------------------------------------------

func TestGet_ExistingGroup(t *testing.T) {
	m := newTestManager(t)
	req := CreateGroupRequest{
		ID:      "get-group",
		Members: []Member{adminMember("admin-1")},
	}
	if _, err := m.Create(context.Background(), req); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	g, err := m.Get(context.Background(), "get-group")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.ID != "get-group" {
		t.Errorf("got %q, want %q", g.ID, "get-group")
	}
}

func TestGet_NonExistent_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Get(context.Background(), "no-such-group")
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if _, ok := err.(*GroupNotFoundError); !ok {
		t.Errorf("expected *GroupNotFoundError, got %T", err)
	}
}

func TestGet_EmptyID_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Get(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty group ID")
	}
}

// --------------------------------------------------------------------------
// Update
// --------------------------------------------------------------------------

func TestUpdate_ChangesTitle(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID:      "upd-group",
		Members: []Member{adminMember("admin-1")},
		Title:   []byte("old-title"),
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	newTitle := []byte("new-title")
	g, err := m.Update(context.Background(), "upd-group", UpdateGroupRequest{Title: newTitle})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(g.Title) != string(newTitle) {
		t.Errorf("got title %q, want %q", g.Title, newTitle)
	}
}

func TestUpdate_IncrementsRevision(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID:      "rev-group",
		Members: []Member{adminMember("admin-1")},
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	g, err := m.Update(context.Background(), "rev-group", UpdateGroupRequest{Avatar: "cdn-key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.Revision != 2 {
		t.Errorf("got revision %d, want 2", g.Revision)
	}
}

func TestUpdate_AddMember(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID:      "add-member-group",
		Members: []Member{adminMember("admin-1")},
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	g, err := m.Update(context.Background(), "add-member-group", UpdateGroupRequest{
		AddMembers: []Member{defaultMember("member-2")},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.Members) != 2 {
		t.Errorf("got %d members, want 2", len(g.Members))
	}
}

func TestUpdate_RemoveMember(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID: "rm-member-group",
		Members: []Member{
			adminMember("admin-1"),
			defaultMember("member-2"),
		},
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	g, err := m.Update(context.Background(), "rm-member-group", UpdateGroupRequest{
		RemoveMemberIDs: []string{"member-2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.Members) != 1 {
		t.Errorf("got %d members, want 1", len(g.Members))
	}
}

func TestUpdate_NonExistent_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Update(context.Background(), "no-such-group", UpdateGroupRequest{})
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if _, ok := err.(*GroupNotFoundError); !ok {
		t.Errorf("expected *GroupNotFoundError, got %T", err)
	}
}

func TestUpdate_EmptyID_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	_, err := m.Update(context.Background(), "", UpdateGroupRequest{})
	if err == nil {
		t.Fatal("expected error for empty group ID")
	}
}

func TestUpdate_AddPendingMember(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID:      "pend-group",
		Members: []Member{adminMember("admin-1")},
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	g, err := m.Update(context.Background(), "pend-group", UpdateGroupRequest{
		AddPendingMembers: []PendingMember{{ServiceID: "invited-1"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.PendingMembers) != 1 {
		t.Errorf("got %d pending members, want 1", len(g.PendingMembers))
	}
}

func TestUpdate_RemovePendingMember(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID:      "rm-pend-group",
		Members: []Member{adminMember("admin-1")},
		PendingMembers: []PendingMember{
			{ServiceID: "invited-1"},
			{ServiceID: "invited-2"},
		},
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	g, err := m.Update(context.Background(), "rm-pend-group", UpdateGroupRequest{
		RemovePendingMemberIDs: []string{"invited-1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(g.PendingMembers) != 1 {
		t.Errorf("got %d pending members, want 1", len(g.PendingMembers))
	}
	if g.PendingMembers[0].ServiceID != "invited-2" {
		t.Errorf("got %q, want %q", g.PendingMembers[0].ServiceID, "invited-2")
	}
}

func TestUpdate_UpdatesAccessControls(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID:      "ac-group",
		Members: []Member{adminMember("admin-1")},
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	newAC := &GroupAccessControls{
		Attributes:        AccessAdministrator,
		Members:           AccessMember,
		AddFromInviteLink: AccessUnsatisfiable,
	}
	g, err := m.Update(context.Background(), "ac-group", UpdateGroupRequest{AccessControls: newAC})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.AccessControls.Attributes != AccessAdministrator {
		t.Errorf("got %d, want AccessAdministrator", g.AccessControls.Attributes)
	}
}

// --------------------------------------------------------------------------
// Delete
// --------------------------------------------------------------------------

func TestDelete_ExistingGroup(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create(context.Background(), CreateGroupRequest{
		ID:      "del-group",
		Members: []Member{adminMember("admin-1")},
	}); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	if err := m.Delete(context.Background(), "del-group"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := m.Get(context.Background(), "del-group")
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestDelete_NonExistent_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	err := m.Delete(context.Background(), "no-such-group")
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if _, ok := err.(*GroupNotFoundError); !ok {
		t.Errorf("expected *GroupNotFoundError, got %T", err)
	}
}

func TestDelete_EmptyID_ReturnsError(t *testing.T) {
	m := newTestManager(t)
	err := m.Delete(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty group ID")
	}
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

func TestHasAdministrator_TrueWhenAdminPresent(t *testing.T) {
	members := []Member{
		defaultMember("u1"),
		adminMember("u2"),
	}
	if !hasAdministrator(members) {
		t.Error("expected hasAdministrator to return true")
	}
}

func TestHasAdministrator_FalseWhenNone(t *testing.T) {
	members := []Member{defaultMember("u1"), defaultMember("u2")}
	if hasAdministrator(members) {
		t.Error("expected hasAdministrator to return false")
	}
}

func TestCloneBytes_NilInput(t *testing.T) {
	if cloneBytes(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

func TestCloneBytes_DeepCopy(t *testing.T) {
	orig := []byte("hello")
	cp := cloneBytes(orig)
	cp[0] = 'X'
	if orig[0] == 'X' {
		t.Error("cloneBytes did not produce an independent copy")
	}
}

func TestCloneMembers_NilInput(t *testing.T) {
	if cloneMembers(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

func TestCloneMembers_DeepCopy(t *testing.T) {
	orig := []Member{adminMember("admin-1")}
	cp := cloneMembers(orig)
	cp[0].UserID = "modified"
	if orig[0].UserID == "modified" {
		t.Error("cloneMembers did not produce an independent copy")
	}
}

func TestClonePendingMembers_NilInput(t *testing.T) {
	if clonePendingMembers(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

// isInvalidGroupArg returns true if err is a *InvalidGroupArgumentError.
func isInvalidGroupArg(err error) bool {
	_, ok := err.(*InvalidGroupArgumentError)
	return ok
}
