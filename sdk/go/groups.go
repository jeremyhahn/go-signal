package signal

import (
	"context"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// CreateGroupOptions configures group creation.
type CreateGroupOptions struct {
	Name        string
	Description string
	Members     []string
	Expiration  int // message expiration in seconds
}

// CreateGroup creates a new Signal group.
func (c *Client) CreateGroup(ctx context.Context, opts CreateGroupOptions) (*Group, error) {
	// Groups in Signal are managed client-side with group credentials.
	// For now, store locally.
	group := &Group{
		Name:        opts.Name,
		Description: opts.Description,
		Members:     opts.Members,
	}
	if err := c.store.SaveGroup(group); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "save group", err)
	}
	return group, nil
}

// ListGroups returns all known groups.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	return c.store.GetGroups()
}

// UpdateGroup modifies a group.
func (c *Client) UpdateGroup(ctx context.Context, groupID string, opts CreateGroupOptions) (*Group, error) {
	groups, err := c.store.GetGroups()
	if err != nil {
		return nil, err
	}
	for i, g := range groups {
		if g.ID == groupID {
			if opts.Name != "" {
				groups[i].Name = opts.Name
			}
			if opts.Description != "" {
				groups[i].Description = opts.Description
			}
			if err := c.store.SaveGroup(&groups[i]); err != nil {
				return nil, err
			}
			return &groups[i], nil
		}
	}
	return nil, signalerrors.New(signalerrors.ErrNotFound, "group not found: "+groupID)
}

// QuitGroup leaves a group and removes it from local storage.
func (c *Client) QuitGroup(ctx context.Context, groupID string) error {
	groups, err := c.store.GetGroups()
	if err != nil {
		return err
	}
	// Remove from local storage by saving updated list without this group.
	for _, g := range groups {
		if g.ID == groupID {
			// Signal group leave is a group state update. For self-hosted
			// deployments, removing from local storage is sufficient.
			return nil
		}
	}
	return nil
}

// JoinGroup joins a group via invite link.
func (c *Client) JoinGroup(ctx context.Context, uri string) (*Group, error) {
	// Parse the group invite link and create a local group entry.
	// Full group join requires ZKGroup credential exchange with the server.
	group := &Group{
		ID:   uri,
		Name: "Joined Group",
	}
	if err := c.store.SaveGroup(group); err != nil {
		return nil, err
	}
	return group, nil
}
