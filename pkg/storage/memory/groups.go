package memory

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/groups"
)

// Compile-time interface satisfaction check.
var _ groups.GroupStore = (*MemoryGroupStore)(nil)

// MemoryGroupStore implements groups.GroupStore with in-memory maps.
// All operations are safe for concurrent use.
type MemoryGroupStore struct {
	mu   sync.RWMutex
	byID map[string]*groups.Group
}

// NewMemoryGroupStore creates a new in-memory group store.
func NewMemoryGroupStore() *MemoryGroupStore {
	return &MemoryGroupStore{
		byID: make(map[string]*groups.Group),
	}
}

// Create persists a new group. Returns *groups.GroupAlreadyExistsError if a
// group with the same ID already exists.
func (s *MemoryGroupStore) Create(_ context.Context, group *groups.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[group.ID]; exists {
		return &groups.GroupAlreadyExistsError{GroupID: group.ID}
	}

	s.byID[group.ID] = cloneGroup(group)
	return nil
}

// Get retrieves the current state of a group by its ID. Returns
// *groups.GroupNotFoundError when the group does not exist.
func (s *MemoryGroupStore) Get(_ context.Context, groupID string) (*groups.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	g, exists := s.byID[groupID]
	if !exists {
		return nil, &groups.GroupNotFoundError{GroupID: groupID}
	}

	return cloneGroup(g), nil
}

// Update persists a modified group state. The incoming group.Revision must be
// exactly one greater than the currently stored revision; otherwise
// *groups.GroupVersionConflictError is returned.
func (s *MemoryGroupStore) Update(_ context.Context, group *groups.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.byID[group.ID]
	if !exists {
		return &groups.GroupNotFoundError{GroupID: group.ID}
	}

	if group.Revision != existing.Revision+1 {
		return &groups.GroupVersionConflictError{
			GroupID:         group.ID,
			ExpectedVersion: existing.Revision + 1,
			ActualVersion:   group.Revision,
		}
	}

	s.byID[group.ID] = cloneGroup(group)
	return nil
}

// Delete removes a group by its ID. Returns *groups.GroupNotFoundError when
// the group does not exist.
func (s *MemoryGroupStore) Delete(_ context.Context, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[groupID]; !exists {
		return &groups.GroupNotFoundError{GroupID: groupID}
	}

	delete(s.byID, groupID)
	return nil
}

// cloneGroup returns a deep copy of a group, isolating the stored record from
// the caller's reference.
func cloneGroup(g *groups.Group) *groups.Group {
	clone := *g

	clone.Title = cloneBytes(g.Title)
	clone.Description = cloneBytes(g.Description)
	clone.InviteLinkPassword = cloneBytes(g.InviteLinkPassword)

	clone.Members = cloneGroupMembers(g.Members)
	clone.PendingMembers = cloneGroupPendingMembers(g.PendingMembers)
	clone.RequestingMembers = cloneGroupRequestingMembers(g.RequestingMembers)

	// time.Time is a value type; the embedded wall / ext / loc fields copy
	// cleanly via the struct copy above, so no explicit handling is required.

	return &clone
}

// cloneGroupMembers returns a deep copy of a Member slice.
func cloneGroupMembers(ms []groups.Member) []groups.Member {
	if ms == nil {
		return nil
	}
	out := make([]groups.Member, len(ms))
	for i, m := range ms {
		out[i] = m
		out[i].ProfileKey = cloneBytes(m.ProfileKey)
		out[i].Presentation = cloneBytes(m.Presentation)
	}
	return out
}

// cloneGroupPendingMembers returns a deep copy of a PendingMember slice.
func cloneGroupPendingMembers(ms []groups.PendingMember) []groups.PendingMember {
	if ms == nil {
		return nil
	}
	out := make([]groups.PendingMember, len(ms))
	copy(out, ms)

	// PendingMember contains only value types (string, MemberRole, time.Time);
	// a shallow copy is sufficient for full isolation.
	return out
}

// cloneGroupRequestingMembers returns a deep copy of a RequestingMember slice.
func cloneGroupRequestingMembers(ms []groups.RequestingMember) []groups.RequestingMember {
	if ms == nil {
		return nil
	}
	out := make([]groups.RequestingMember, len(ms))
	for i, m := range ms {
		out[i] = m
		out[i].ProfileKey = cloneBytes(m.ProfileKey)
	}
	return out
}
