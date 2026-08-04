//go:build desktop

package bindings

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewReactionBindings verifies construction.
func TestNewReactionBindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		require.NotNil(t, b)
	})
}

// TestReactionBindings_GetReactions tests querying reactions for a message.
func TestReactionBindings_GetReactions(t *testing.T) {
	t.Run("EmptyForUnknownMessage", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		reactions, err := b.GetReactions("msg-unknown")
		require.NoError(t, err)
		assert.Empty(t, reactions)
	})
	t.Run("ReturnsReactionsForMessage", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		require.NoError(t, b.SaveReaction("msg-001", "author-a", "👍"))
		require.NoError(t, b.SaveReaction("msg-001", "author-b", "❤️"))

		reactions, err := b.GetReactions("msg-001")
		require.NoError(t, err)
		assert.Len(t, reactions, 2)
	})
}

// TestReactionBindings_SaveReaction tests saving new reactions and updating existing ones.
func TestReactionBindings_SaveReaction(t *testing.T) {
	t.Run("SavesNewReaction", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		err := b.SaveReaction("msg-abc", "user-001", "👍")
		require.NoError(t, err)

		reactions, err := b.GetReactions("msg-abc")
		require.NoError(t, err)
		assert.Len(t, reactions, 1)
		assert.Equal(t, "👍", reactions[0].Emoji)
	})
	t.Run("UpdatesExistingReaction", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		require.NoError(t, b.SaveReaction("msg-xyz", "user-002", "👍"))
		// Same author sends a different emoji — should update, not duplicate.
		require.NoError(t, b.SaveReaction("msg-xyz", "user-002", "❤️"))

		reactions, err := b.GetReactions("msg-xyz")
		require.NoError(t, err)
		assert.Len(t, reactions, 1)
		assert.Equal(t, "❤️", reactions[0].Emoji)
	})
	t.Run("MultipleAuthorsOnSameMessage", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		require.NoError(t, b.SaveReaction("msg-multi", "user-a", "😂"))
		require.NoError(t, b.SaveReaction("msg-multi", "user-b", "😮"))

		reactions, err := b.GetReactions("msg-multi")
		require.NoError(t, err)
		assert.Len(t, reactions, 2)
	})
}

// TestReactionBindings_RemoveReaction tests removing a reaction.
func TestReactionBindings_RemoveReaction(t *testing.T) {
	t.Run("RemovesExistingReaction", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		require.NoError(t, b.SaveReaction("msg-del", "user-x", "👎"))

		require.NoError(t, b.RemoveReaction("msg-del", "user-x"))
		reactions, err := b.GetReactions("msg-del")
		require.NoError(t, err)
		assert.Empty(t, reactions)
	})
	t.Run("RemoveNonexistentIsNoop", func(t *testing.T) {
		b := NewReactionBindings(newTestBindFactory(t))
		// No error expected when the reaction does not exist.
		err := b.RemoveReaction("msg-missing", "user-ghost")
		require.NoError(t, err)
	})
}
