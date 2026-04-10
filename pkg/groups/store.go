package groups

import "context"

// GroupStore defines the persistence interface for Signal Groups v2 group
// state. Implementations must be safe for concurrent use.
type GroupStore interface {
	// Create persists a new group. Returns *GroupAlreadyExistsError if a
	// group with the same ID already exists.
	Create(ctx context.Context, group *Group) error

	// Get retrieves the current state of a group by its ID. Returns
	// *GroupNotFoundError if the group does not exist.
	Get(ctx context.Context, groupID string) (*Group, error)

	// Update persists a modified group state. The incoming group.Revision
	// must be exactly one greater than the currently stored revision;
	// otherwise *GroupVersionConflictError is returned.
	Update(ctx context.Context, group *Group) error

	// Delete removes a group and all associated state by its ID. Returns
	// *GroupNotFoundError if the group does not exist.
	Delete(ctx context.Context, groupID string) error
}
