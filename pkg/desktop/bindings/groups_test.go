//go:build desktop

package bindings

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// seedGroup saves a GroupEntity directly to the DAO and returns it.
func seedGroup(t *testing.T, b *GroupBindings, groupID, title string, members []string) *entities.GroupEntity {
	t.Helper()
	membersJSON, _ := json.Marshal(members)
	g := &entities.GroupEntity{
		GroupID: groupID,
		Title:   title,
		Members: string(membersJSON),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, b.factory.Groups.Save(ctx, g))
	return g
}

// TestNewGroupBindings verifies construction.
func TestNewGroupBindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		require.NotNil(t, b)
	})
}

// TestGroupBindings_ListGroups tests listing all local groups.
func TestGroupBindings_ListGroups(t *testing.T) {
	t.Run("EmptyStore", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		groups, err := b.ListGroups()
		require.NoError(t, err)
		assert.Empty(t, groups)
	})
	t.Run("ReturnsAllGroups", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		seedGroup(t, b, "grp-1", "Alpha", nil)
		seedGroup(t, b, "grp-2", "Beta", nil)

		groups, err := b.ListGroups()
		require.NoError(t, err)
		assert.Len(t, groups, 2)
	})
}

// TestGroupBindings_GetGroup tests lookup by group ID.
func TestGroupBindings_GetGroup(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		seedGroup(t, b, "grp-found", "Founders", nil)

		got, err := b.GetGroup("grp-found")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "grp-found", got.GroupID)
		assert.Equal(t, "Founders", got.Title)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		_, err := b.GetGroup("grp-missing")
		require.Error(t, err)
	})
}

// TestGroupBindings_CreateGroup tests server-and-local group creation.
func TestGroupBindings_CreateGroup(t *testing.T) {
	t.Run("CreatesGroupAndConversation", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		entity, err := b.CreateGroup(CreateGroupRequest{
			Title:   "Alpha Squad",
			Members: []string{"uuid-m1", "uuid-m2"},
		})
		require.NoError(t, err)
		require.NotNil(t, entity)
		assert.Equal(t, "Alpha Squad", entity.Title)
	})
	t.Run("EmptyTitle", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		entity, err := b.CreateGroup(CreateGroupRequest{Members: []string{"uuid-x"}})
		require.NoError(t, err)
		require.NotNil(t, entity)
	})
}

// TestGroupBindings_UpdateGroup tests updating a group's metadata.
func TestGroupBindings_UpdateGroup(t *testing.T) {
	t.Run("ErrorWhenGroupNotInClientStore", func(t *testing.T) {
		// stubBindStore.GetGroups returns nil → client.UpdateGroup returns "group not found".
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		err := b.UpdateGroup("grp-ghost", "New Name", "New Desc")
		require.Error(t, err)
	})
	t.Run("UpdatesLocalGroupWhenClientSucceeds", func(t *testing.T) {
		// Client store knows about the group → client.UpdateGroup succeeds.
		existingGroup := signal.Group{ID: "grp-upd", Name: "Old Name"}
		client := newBindClientWithGroups(t, []signal.Group{existingGroup})
		factory := newTestBindFactory(t)
		b := NewGroupBindings(client, factory)

		// Seed the group in the DAO factory so QueryOneByIndex finds it.
		seedGroup(t, b, "grp-upd", "Old Name", nil)

		err := b.UpdateGroup("grp-upd", "New Name", "Updated Desc")
		require.NoError(t, err)

		updated, err := b.GetGroup("grp-upd")
		require.NoError(t, err)
		assert.Equal(t, "New Name", updated.Title)
	})
}

// TestGroupBindings_QuitGroup tests leaving a group.
func TestGroupBindings_QuitGroup(t *testing.T) {
	t.Run("DeletesGroupFromDAO", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		seedGroup(t, b, "grp-leave", "Leaving", nil)

		require.NoError(t, b.QuitGroup("grp-leave"))

		_, err := b.GetGroup("grp-leave")
		require.Error(t, err)
	})
	t.Run("NotFoundInDAOReturnsError", func(t *testing.T) {
		// client.QuitGroup is a no-op regardless; DAO query must fail.
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		err := b.QuitGroup("grp-missing")
		require.Error(t, err)
	})
}

// TestGroupBindings_GetGroupMembers tests parsing the member list JSON.
func TestGroupBindings_GetGroupMembers(t *testing.T) {
	t.Run("ReturnsMembers", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		members := []string{"uuid-a", "uuid-b", "uuid-c"}
		seedGroup(t, b, "grp-members", "Team", members)

		got, err := b.GetGroupMembers("grp-members")
		require.NoError(t, err)
		assert.ElementsMatch(t, members, got)
	})
	t.Run("EmptyMembersString", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		// Seed group with no members JSON.
		ctx := context.Background()
		g := &entities.GroupEntity{GroupID: "grp-empty", Title: "Empty"}
		require.NoError(t, b.factory.Groups.Save(ctx, g))

		members, err := b.GetGroupMembers("grp-empty")
		require.NoError(t, err)
		assert.Empty(t, members)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewGroupBindings(newBindClient(t), newTestBindFactory(t))
		_, err := b.GetGroupMembers("grp-ghost")
		require.Error(t, err)
	})
}
