//go:build desktop

package bindings

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// seedConversation saves a conversation entity and returns it.
func seedConversation(t *testing.T, b *ConversationBindings, convID string) *entities.ConversationEntity {
	t.Helper()
	conv := &entities.ConversationEntity{
		ConversationID: convID,
		Type:           entities.ConversationTypeDirect,
		Name:           convID,
		ActiveAt:       time.Now().UnixMilli(),
		UnreadCount:    0,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, b.conversations.Save(ctx, conv))
	return conv
}

// TestNewConversationBindings verifies construction.
func TestNewConversationBindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		require.NotNil(t, b)
	})
}

// TestConversationBindings_GetConversations tests listing all conversations.
func TestConversationBindings_GetConversations(t *testing.T) {
	t.Run("EmptyStore", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		convs, err := b.GetConversations()
		require.NoError(t, err)
		assert.Empty(t, convs)
	})
	t.Run("ReturnsAllConversations", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-1")
		seedConversation(t, b, "conv-2")

		convs, err := b.GetConversations()
		require.NoError(t, err)
		assert.Len(t, convs, 2)
	})
}

// TestConversationBindings_GetConversation tests lookup by ID.
func TestConversationBindings_GetConversation(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-abc")
		got, err := b.GetConversation("conv-abc")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "conv-abc", got.ConversationID)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		_, err := b.GetConversation("missing")
		require.Error(t, err)
	})
}

// TestConversationBindings_PinConversation tests toggling pinned state.
func TestConversationBindings_PinConversation(t *testing.T) {
	t.Run("PinsThenUnpins", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-pin")

		require.NoError(t, b.PinConversation("conv-pin", true))
		conv, err := b.GetConversation("conv-pin")
		require.NoError(t, err)
		assert.True(t, conv.IsPinned)

		require.NoError(t, b.PinConversation("conv-pin", false))
		conv, err = b.GetConversation("conv-pin")
		require.NoError(t, err)
		assert.False(t, conv.IsPinned)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		err := b.PinConversation("missing", true)
		require.Error(t, err)
	})
}

// TestConversationBindings_ArchiveConversation tests toggling archive state.
func TestConversationBindings_ArchiveConversation(t *testing.T) {
	t.Run("Archives", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-arch")
		require.NoError(t, b.ArchiveConversation("conv-arch", true))
		conv, err := b.GetConversation("conv-arch")
		require.NoError(t, err)
		assert.True(t, conv.IsArchived)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		err := b.ArchiveConversation("missing", true)
		require.Error(t, err)
	})
}

// TestConversationBindings_MuteConversation tests mute state updates.
func TestConversationBindings_MuteConversation(t *testing.T) {
	t.Run("MutesWithExpiry", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-mute")
		until := time.Now().Add(1 * time.Hour).UnixMilli()
		require.NoError(t, b.MuteConversation("conv-mute", true, until))
		conv, err := b.GetConversation("conv-mute")
		require.NoError(t, err)
		assert.True(t, conv.IsMuted)
		assert.Equal(t, until, conv.MutedUntil)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		err := b.MuteConversation("missing", true, 0)
		require.Error(t, err)
	})
}

// TestConversationBindings_SetExpirationTimer tests timer updates.
func TestConversationBindings_SetExpirationTimer(t *testing.T) {
	t.Run("SetsTimer", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-timer")
		require.NoError(t, b.SetExpirationTimer("conv-timer", 3600))
		conv, err := b.GetConversation("conv-timer")
		require.NoError(t, err)
		assert.Equal(t, 3600, conv.ExpirationTimer)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		err := b.SetExpirationTimer("missing", 60)
		require.Error(t, err)
	})
}

// TestConversationBindings_SaveDraft tests draft persistence.
func TestConversationBindings_SaveDraft(t *testing.T) {
	t.Run("SavesDraft", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-draft")
		require.NoError(t, b.SaveDraft("conv-draft", "Hello, world"))
		conv, err := b.GetConversation("conv-draft")
		require.NoError(t, err)
		assert.Equal(t, "Hello, world", conv.Draft)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		err := b.SaveDraft("missing", "text")
		require.Error(t, err)
	})
}

// seedMessage saves a MessageEntity directly to the conversation bindings messages DAO.
func seedMessage(t *testing.T, b *ConversationBindings, convID string, ts int64, isRead bool) {
	t.Helper()
	msg := &entities.MessageEntity{
		GUID:           "guid-" + fmt.Sprintf("%d", ts),
		ConversationID: convID,
		Timestamp:      ts,
		Body:           "body",
		IsRead:         isRead,
	}
	ctx := context.Background()
	require.NoError(t, b.messages.Save(ctx, msg))
}

// TestConversationBindings_GetMessages tests message retrieval.
func TestConversationBindings_GetMessages(t *testing.T) {
	t.Run("EmptyForNewConversation", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		msgs, err := b.GetMessages("conv-no-msgs", 10, 0)
		require.NoError(t, err)
		assert.Empty(t, msgs)
	})
	t.Run("LimitZeroReturnsAll", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		msgs, err := b.GetMessages("conv-x", 0, 0)
		require.NoError(t, err)
		assert.Empty(t, msgs)
	})
	t.Run("BeforeTimestampFilters", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedMessage(t, b, "conv-ts", 1000, true)
		seedMessage(t, b, "conv-ts", 2000, true)
		seedMessage(t, b, "conv-ts", 3000, true)
		// beforeTimestamp=2500 should return messages with Timestamp < 2500.
		msgs, err := b.GetMessages("conv-ts", 10, 2500)
		require.NoError(t, err)
		for _, m := range msgs {
			assert.Less(t, m.Timestamp, int64(2500))
		}
	})
}

// TestConversationBindings_SearchMessages tests full-text search fallback.
func TestConversationBindings_SearchMessages(t *testing.T) {
	t.Run("EmptyStoreReturnsEmpty", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		msgs, err := b.SearchMessages("hello", 10)
		require.NoError(t, err)
		assert.Empty(t, msgs)
	})
	t.Run("ZeroLimitReturnsAll", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		msgs, err := b.SearchMessages("test", 0)
		require.NoError(t, err)
		assert.Empty(t, msgs)
	})
}

// TestConversationBindings_MarkConversationRead tests unread counter reset.
func TestConversationBindings_MarkConversationRead(t *testing.T) {
	t.Run("ResetsUnreadCount", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		// Seed conversation with unread count.
		conv := seedConversation(t, b, "conv-read")
		ctx := context.Background()
		conv.UnreadCount = 5
		require.NoError(t, b.conversations.Save(ctx, conv))

		require.NoError(t, b.MarkConversationRead("conv-read"))
		updated, err := b.GetConversation("conv-read")
		require.NoError(t, err)
		assert.Equal(t, 0, updated.UnreadCount)
	})
	t.Run("MarksUnreadMessagesAsRead", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		conv := seedConversation(t, b, "conv-mread")
		ctx := context.Background()
		conv.UnreadCount = 2
		require.NoError(t, b.conversations.Save(ctx, conv))

		// Seed two unread messages for this conversation.
		seedMessage(t, b, "conv-mread", 100, false)
		seedMessage(t, b, "conv-mread", 200, false)

		require.NoError(t, b.MarkConversationRead("conv-mread"))

		updated, err := b.GetConversation("conv-mread")
		require.NoError(t, err)
		assert.Equal(t, 0, updated.UnreadCount)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		err := b.MarkConversationRead("missing")
		require.Error(t, err)
	})
}

// TestConversationBindings_DeleteConversation tests deletion.
func TestConversationBindings_DeleteConversation(t *testing.T) {
	t.Run("DeletesConversation", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-del")
		require.NoError(t, b.DeleteConversation("conv-del"))
		_, err := b.GetConversation("conv-del")
		require.Error(t, err)
	})
	t.Run("DeletesConversationWithMessages", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		seedConversation(t, b, "conv-del-msgs")
		seedMessage(t, b, "conv-del-msgs", 1000, true)
		seedMessage(t, b, "conv-del-msgs", 2000, false)

		require.NoError(t, b.DeleteConversation("conv-del-msgs"))
		_, err := b.GetConversation("conv-del-msgs")
		require.Error(t, err)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewConversationBindings(newTestBindFactory(t))
		err := b.DeleteConversation("missing")
		require.Error(t, err)
	})
}
