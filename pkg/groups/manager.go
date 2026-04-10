package groups

import (
	"context"
	"log/slog"
	"time"
)

// GroupsManager coordinates Groups v2 lifecycle operations, delegating
// persistence to a GroupStore and enforcing business rules.
type GroupsManager struct {
	store  GroupStore
	logger *slog.Logger
}

// NewGroupsManager creates a new GroupsManager backed by the given store.
func NewGroupsManager(store GroupStore, logger *slog.Logger) *GroupsManager {
	return &GroupsManager{store: store, logger: logger}
}

// Create validates and persists a new group. At least one member with the
// Administrator role is required. The group Revision is initialised to 1 and
// timestamps are set automatically.
func (m *GroupsManager) Create(ctx context.Context, req CreateGroupRequest) (*Group, error) {
	if req.ID == "" {
		return nil, &InvalidGroupArgumentError{Field: "id", Message: "must not be empty"}
	}
	if len(req.Members) == 0 {
		return nil, &InvalidGroupArgumentError{Field: "members", Message: "at least one member is required"}
	}
	if !hasAdministrator(req.Members) {
		return nil, &InvalidGroupArgumentError{Field: "members", Message: "at least one administrator is required"}
	}

	now := time.Now().UTC()
	group := &Group{
		ID:                 req.ID,
		Title:              req.Title,
		Avatar:             req.Avatar,
		Description:        req.Description,
		Members:            cloneMembers(req.Members),
		PendingMembers:     clonePendingMembers(req.PendingMembers),
		RequestingMembers:  nil,
		AccessControls:     req.AccessControls,
		InviteLinkPassword: cloneBytes(req.InviteLinkPassword),
		Revision:           1,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := m.store.Create(ctx, group); err != nil {
		return nil, err
	}

	m.logger.InfoContext(ctx, "group created", slog.String("group_id", group.ID))

	return group, nil
}

// Get retrieves the current state of a group by its ID.
func (m *GroupsManager) Get(ctx context.Context, groupID string) (*Group, error) {
	if groupID == "" {
		return nil, &InvalidGroupArgumentError{Field: "groupID", Message: "must not be empty"}
	}
	return m.store.Get(ctx, groupID)
}

// Update applies a partial update to an existing group. Only non-nil / non-zero
// fields in req are applied. The Revision is incremented automatically.
func (m *GroupsManager) Update(ctx context.Context, groupID string, req UpdateGroupRequest) (*Group, error) {
	if groupID == "" {
		return nil, &InvalidGroupArgumentError{Field: "groupID", Message: "must not be empty"}
	}

	group, err := m.store.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}

	applyGroupUpdate(group, req)
	group.Revision++
	group.UpdatedAt = time.Now().UTC()

	if err := m.store.Update(ctx, group); err != nil {
		return nil, err
	}

	m.logger.InfoContext(ctx, "group updated",
		slog.String("group_id", group.ID),
		slog.Uint64("revision", uint64(group.Revision)),
	)

	return group, nil
}

// Delete removes a group by its ID.
func (m *GroupsManager) Delete(ctx context.Context, groupID string) error {
	if groupID == "" {
		return &InvalidGroupArgumentError{Field: "groupID", Message: "must not be empty"}
	}
	if err := m.store.Delete(ctx, groupID); err != nil {
		return err
	}
	m.logger.InfoContext(ctx, "group deleted", slog.String("group_id", groupID))
	return nil
}

// applyGroupUpdate merges non-nil / non-zero UpdateGroupRequest fields into
// the target group.
func applyGroupUpdate(g *Group, req UpdateGroupRequest) {
	if req.Title != nil {
		g.Title = cloneBytes(req.Title)
	}
	if req.Avatar != "" {
		g.Avatar = req.Avatar
	}
	if req.Description != nil {
		g.Description = cloneBytes(req.Description)
	}
	if req.AccessControls != nil {
		g.AccessControls = *req.AccessControls
	}
	if req.InviteLinkPassword != nil {
		g.InviteLinkPassword = cloneBytes(req.InviteLinkPassword)
	}

	// Add new full members (skip duplicates).
	if len(req.AddMembers) > 0 {
		existing := memberSet(g.Members)
		for _, m := range req.AddMembers {
			if !existing[m.UserID] {
				g.Members = append(g.Members, cloneMember(m))
				existing[m.UserID] = true
			}
		}
	}

	// Remove departing full members.
	if len(req.RemoveMemberIDs) > 0 {
		remove := stringSet(req.RemoveMemberIDs)
		filtered := g.Members[:0]
		for _, m := range g.Members {
			if !remove[m.UserID] {
				filtered = append(filtered, m)
			}
		}
		g.Members = filtered
	}

	// Add new pending members (skip duplicates).
	if len(req.AddPendingMembers) > 0 {
		existingPending := pendingMemberSet(g.PendingMembers)
		for _, pm := range req.AddPendingMembers {
			if !existingPending[pm.ServiceID] {
				g.PendingMembers = append(g.PendingMembers, clonePendingMember(pm))
				existingPending[pm.ServiceID] = true
			}
		}
	}

	// Remove withdrawn pending members.
	if len(req.RemovePendingMemberIDs) > 0 {
		remove := stringSet(req.RemovePendingMemberIDs)
		filtered := g.PendingMembers[:0]
		for _, pm := range g.PendingMembers {
			if !remove[pm.ServiceID] {
				filtered = append(filtered, pm)
			}
		}
		g.PendingMembers = filtered
	}
}

// hasAdministrator returns true if at least one member in the list has the
// Administrator role.
func hasAdministrator(members []Member) bool {
	for i := range members {
		if members[i].Role == MemberRoleAdministrator {
			return true
		}
	}
	return false
}

// memberSet builds a set of member UserIDs for O(1) lookup.
func memberSet(members []Member) map[string]bool {
	s := make(map[string]bool, len(members))
	for i := range members {
		s[members[i].UserID] = true
	}
	return s
}

// pendingMemberSet builds a set of pending member ServiceIDs for O(1) lookup.
func pendingMemberSet(members []PendingMember) map[string]bool {
	s := make(map[string]bool, len(members))
	for i := range members {
		s[members[i].ServiceID] = true
	}
	return s
}

// stringSet converts a slice of strings into a lookup set.
func stringSet(ss []string) map[string]bool {
	s := make(map[string]bool, len(ss))
	for _, v := range ss {
		s[v] = true
	}
	return s
}

// cloneBytes returns a copy of b, or nil when b is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// cloneMember returns a deep copy of a Member.
func cloneMember(m Member) Member {
	m.ProfileKey = cloneBytes(m.ProfileKey)
	m.Presentation = cloneBytes(m.Presentation)
	return m
}

// cloneMembers returns a deep copy of a Member slice.
func cloneMembers(members []Member) []Member {
	if members == nil {
		return nil
	}
	out := make([]Member, len(members))
	for i, m := range members {
		out[i] = cloneMember(m)
	}
	return out
}

// clonePendingMember returns a deep copy of a PendingMember.
func clonePendingMember(pm PendingMember) PendingMember {
	return pm
}

// clonePendingMembers returns a deep copy of a PendingMember slice.
func clonePendingMembers(members []PendingMember) []PendingMember {
	if members == nil {
		return nil
	}
	out := make([]PendingMember, len(members))
	copy(out, members)
	return out
}
