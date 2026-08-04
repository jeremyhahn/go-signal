//go:build desktop

package bindings

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// GroupBindings provides group operations to the frontend.
type GroupBindings struct {
	client  *signal.Client
	factory *daostore.Factory
}

// NewGroupBindings creates group bindings.
func NewGroupBindings(client *signal.Client, f *daostore.Factory) *GroupBindings {
	return &GroupBindings{client: client, factory: f}
}

// ListGroups returns all locally stored groups.
func (b *GroupBindings) ListGroups() ([]*entities.GroupEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.factory.Groups.Find(ctx).
		OrderBy("Title").
		Execute()
}

// GetGroup returns a group by ID.
func (b *GroupBindings) GetGroup(groupID string) (*entities.GroupEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.factory.Groups.QueryOneByIndex(ctx, "GroupID", groupID)
}

// CreateGroupRequest holds the parameters for creating a group.
type CreateGroupRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"`
}

// CreateGroup creates a new group on the server and stores it locally.
func (b *GroupBindings) CreateGroup(req CreateGroupRequest) (*entities.GroupEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	group, err := b.client.CreateGroup(ctx, signal.CreateGroupOptions{
		Name:    req.Title,
		Members: req.Members,
	})
	if err != nil {
		return nil, err
	}

	membersJSON, _ := json.Marshal(group.Members)
	adminsJSON, _ := json.Marshal(group.Admins)

	entity := &entities.GroupEntity{
		GroupID:     group.ID,
		Title:       group.Name,
		Description: group.Description,
		Members:     string(membersJSON),
		Admins:      string(adminsJSON),
		InviteLink:  group.InviteLink,
		Revision:    group.Revision,
	}

	if err := b.factory.Groups.Save(ctx, entity); err != nil {
		return nil, err
	}

	// Create a conversation for the group.
	conv := &entities.ConversationEntity{
		ConversationID: group.ID,
		Type:           entities.ConversationTypeGroup,
		Name:           group.Name,
		ActiveAt:       time.Now().UnixMilli(),
	}
	_ = b.factory.Conversations.Save(ctx, conv)

	return entity, nil
}

// UpdateGroup updates a group's metadata on the server and locally.
func (b *GroupBindings) UpdateGroup(groupID string, title, description string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := b.client.UpdateGroup(ctx, groupID, signal.CreateGroupOptions{
		Name:        title,
		Description: description,
	}); err != nil {
		return err
	}

	entity, err := b.factory.Groups.QueryOneByIndex(ctx, "GroupID", groupID)
	if err != nil {
		return err
	}

	entity.Title = title
	entity.Description = description
	entity.Revision++
	return b.factory.Groups.Save(ctx, entity)
}

// QuitGroup leaves a group.
func (b *GroupBindings) QuitGroup(groupID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := b.client.QuitGroup(ctx, groupID); err != nil {
		return err
	}

	entity, err := b.factory.Groups.QueryOneByIndex(ctx, "GroupID", groupID)
	if err != nil {
		return err
	}
	return b.factory.Groups.Delete(ctx, entity)
}

// GetGroupMembers returns the parsed member list for a group.
func (b *GroupBindings) GetGroupMembers(groupID string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entity, err := b.factory.Groups.QueryOneByIndex(ctx, "GroupID", groupID)
	if err != nil {
		return nil, err
	}

	var members []string
	if entity.Members != "" {
		_ = json.Unmarshal([]byte(entity.Members), &members)
	}
	return members, nil
}
