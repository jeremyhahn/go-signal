package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/groups"
)

// Compile-time interface satisfaction check.
var _ groups.GroupStore = (*GroupStore)(nil)

// GroupStore is a Postgres-backed implementation of groups.GroupStore with
// optimistic locking on Group.Revision.
//
// Schema: groups(id TEXT PRIMARY KEY, revision BIGINT, data JSONB,
// created_at, updated_at). The full Group struct is serialized to JSONB; the
// promoted `revision` column is the authoritative lock field and is kept in
// sync with Group.Revision on every write.
type GroupStore struct {
	q Querier
}

// NewGroupStore constructs a GroupStore backed by the given Querier.
func NewGroupStore(q Querier) *GroupStore {
	return &GroupStore{q: q}
}

// Create persists a new group. Returns *groups.GroupAlreadyExistsError when a
// group with the same ID already exists.
func (s *GroupStore) Create(ctx context.Context, g *groups.Group) error {
	if g == nil {
		return &groups.InvalidGroupArgumentError{Field: "group", Message: "nil group"}
	}
	if g.ID == "" {
		return &groups.InvalidGroupArgumentError{Field: "id", Message: "empty ID"}
	}

	data, err := json.Marshal(g)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres groups: marshal", err)
	}

	_, err = s.q.Exec(ctx, `
		INSERT INTO groups (id, revision, data, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())`,
		g.ID,
		g.Revision,
		data,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return &groups.GroupAlreadyExistsError{GroupID: g.ID}
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres groups: insert", err)
	}
	return nil
}

// Get retrieves the current state of a group by its ID.
func (s *GroupStore) Get(ctx context.Context, groupID string) (*groups.Group, error) {
	var raw []byte
	err := s.q.QueryRow(ctx,
		`SELECT data FROM groups WHERE id = $1`, groupID,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &groups.GroupNotFoundError{GroupID: groupID}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres groups: get", err)
	}
	var g groups.Group
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres groups: unmarshal", err)
	}
	return &g, nil
}

// Update persists a modified group state with optimistic locking. The incoming
// group.Revision must be exactly one greater than the currently stored
// revision. Zero rows updated: a follow-up SELECT distinguishes a missing
// group from a version conflict so the correct typed error is returned.
func (s *GroupStore) Update(ctx context.Context, g *groups.Group) error {
	if g == nil {
		return &groups.InvalidGroupArgumentError{Field: "group", Message: "nil group"}
	}

	data, err := json.Marshal(g)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres groups: marshal", err)
	}

	// revision column is the lock predicate: we only match the row whose
	// stored revision is exactly one less than the incoming revision.
	tag, err := s.q.Exec(ctx, `
		UPDATE groups
		SET revision   = $2,
		    data       = $3,
		    updated_at = NOW()
		WHERE id = $1 AND revision = $2 - 1`,
		g.ID,
		g.Revision,
		data,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres groups: update", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// Zero rows: either the group is absent or the revision didn't match.
	current, err := s.Get(ctx, g.ID)
	if err != nil {
		// Re-surfaces *GroupNotFoundError when the group is gone.
		return err
	}
	return &groups.GroupVersionConflictError{
		GroupID:         g.ID,
		ExpectedVersion: current.Revision + 1,
		ActualVersion:   g.Revision,
	}
}

// Delete removes a group by ID. Returns *groups.GroupNotFoundError when the
// group does not exist.
func (s *GroupStore) Delete(ctx context.Context, groupID string) error {
	tag, err := s.q.Exec(ctx,
		`DELETE FROM groups WHERE id = $1`, groupID,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres groups: delete", err)
	}
	if tag.RowsAffected() == 0 {
		return &groups.GroupNotFoundError{GroupID: groupID}
	}
	return nil
}
