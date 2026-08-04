package qrdb

import (
	"context"
	"encoding/json"
	"errors"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/groups"
)

// Key layout: group:{id} → JSON-serialized Group.
const groupKeyPrefix = "group:"

var _ groups.GroupStore = (*GroupStore)(nil)

// GroupStore is a qrdb-backed implementation of groups.GroupStore with
// optimistic locking on Group.Revision.
type GroupStore struct {
	kv KVStore
}

// NewGroupStore returns a GroupStore that persists to kv.
func NewGroupStore(kv KVStore) *GroupStore { return &GroupStore{kv: kv} }

func groupKey(id string) string { return groupKeyPrefix + id }

// Create persists a new group. Returns *groups.GroupAlreadyExistsError when
// a group with the same ID is already present.
func (s *GroupStore) Create(ctx context.Context, g *groups.Group) error {
	if g == nil {
		return &groups.InvalidGroupArgumentError{Field: "group", Message: "nil group"}
	}
	if g.ID == "" {
		return &groups.InvalidGroupArgumentError{Field: "id", Message: "empty ID"}
	}

	exists, err := s.kv.Exists(ctx, groupKey(g.ID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: exists", err)
	}
	if exists {
		return &groups.GroupAlreadyExistsError{GroupID: g.ID}
	}

	data, err := json.Marshal(g)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: marshal", err)
	}
	if err := s.kv.Put(ctx, groupKey(g.ID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: put", err)
	}
	return nil
}

// Get retrieves a group by ID.
func (s *GroupStore) Get(ctx context.Context, groupID string) (*groups.Group, error) {
	data, err := getOrNotFound(ctx, s.kv, groupKey(groupID))
	if errors.Is(err, ErrNotFound) {
		return nil, &groups.GroupNotFoundError{GroupID: groupID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: get", err)
	}

	var g groups.Group
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: unmarshal", err)
	}
	return &g, nil
}

// Update persists a modified group, enforcing optimistic locking on
// Group.Revision. The incoming revision must be exactly one greater than
// the stored revision.
func (s *GroupStore) Update(ctx context.Context, g *groups.Group) error {
	if g == nil {
		return &groups.InvalidGroupArgumentError{Field: "group", Message: "nil group"}
	}

	existing, err := s.Get(ctx, g.ID)
	if err != nil {
		return err
	}
	if g.Revision != existing.Revision+1 {
		return &groups.GroupVersionConflictError{
			GroupID:         g.ID,
			ExpectedVersion: existing.Revision + 1,
			ActualVersion:   g.Revision,
		}
	}

	data, err := json.Marshal(g)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: marshal", err)
	}
	if err := s.kv.Put(ctx, groupKey(g.ID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: put", err)
	}
	return nil
}

// Delete removes a group.
func (s *GroupStore) Delete(ctx context.Context, groupID string) error {
	exists, err := s.kv.Exists(ctx, groupKey(groupID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: exists", err)
	}
	if !exists {
		return &groups.GroupNotFoundError{GroupID: groupID}
	}
	if err := s.kv.Delete(ctx, groupKey(groupID)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb groups: delete", err)
	}
	return nil
}
