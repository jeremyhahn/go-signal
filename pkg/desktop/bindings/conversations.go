//go:build desktop

package bindings

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// ConversationBindings provides conversation operations to the frontend.
type ConversationBindings struct {
	conversations dao.GenericDAO[*entities.ConversationEntity]
	messages      dao.GenericDAO[*entities.MessageEntity]
}

// NewConversationBindings creates conversation bindings from the DAO factory.
func NewConversationBindings(f *daostore.Factory) *ConversationBindings {
	return &ConversationBindings{
		conversations: f.Conversations,
		messages:      f.Messages,
	}
}

// GetConversations returns all conversations sorted by last activity.
func (b *ConversationBindings) GetConversations() ([]*entities.ConversationEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.conversations.Find(ctx).
		OrderBy("ActiveAt", dao.SortDescending).
		Execute()
}

// GetConversation returns a single conversation by ID.
func (b *ConversationBindings) GetConversation(conversationID string) (*entities.ConversationEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
}

// PinConversation toggles the pinned state of a conversation.
func (b *ConversationBindings) PinConversation(conversationID string, pinned bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conv, err := b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
	if err != nil {
		return err
	}
	conv.IsPinned = pinned
	return b.conversations.Save(ctx, conv)
}

// ArchiveConversation toggles the archived state.
func (b *ConversationBindings) ArchiveConversation(conversationID string, archived bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conv, err := b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
	if err != nil {
		return err
	}
	conv.IsArchived = archived
	return b.conversations.Save(ctx, conv)
}

// MuteConversation sets the mute state with an optional expiry timestamp.
func (b *ConversationBindings) MuteConversation(conversationID string, muted bool, mutedUntil int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conv, err := b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
	if err != nil {
		return err
	}
	conv.IsMuted = muted
	conv.MutedUntil = mutedUntil
	return b.conversations.Save(ctx, conv)
}

// SetExpirationTimer sets the disappearing message timer for a conversation.
func (b *ConversationBindings) SetExpirationTimer(conversationID string, seconds int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conv, err := b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
	if err != nil {
		return err
	}
	conv.ExpirationTimer = seconds
	return b.conversations.Save(ctx, conv)
}

// SaveDraft saves a draft message for a conversation.
func (b *ConversationBindings) SaveDraft(conversationID, text string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conv, err := b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
	if err != nil {
		return err
	}
	conv.Draft = text
	return b.conversations.Save(ctx, conv)
}

// MarkConversationRead marks all messages in a conversation as read and
// resets the unread count.
func (b *ConversationBindings) MarkConversationRead(conversationID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Reset unread count on conversation.
	conv, err := b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
	if err != nil {
		return err
	}
	conv.UnreadCount = 0
	if err := b.conversations.Save(ctx, conv); err != nil {
		return err
	}

	// Mark individual messages as read using compound index (ConversationID, IsRead).
	unread, err := b.messages.QueryByCompoundIndex(ctx,
		"messages.ConversationID_IsRead",
		[]interface{}{conversationID, false},
	)
	if err != nil {
		return err
	}
	for _, msg := range unread {
		msg.IsRead = true
		_ = b.messages.Save(ctx, msg)
	}
	return nil
}

// GetMessages returns paginated messages for a conversation, ordered by
// timestamp descending (newest first). Uses compound index (ConversationID, Timestamp).
func (b *ConversationBindings) GetMessages(conversationID string, limit int, beforeTimestamp int64) ([]*entities.MessageEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := b.messages.Find(ctx).
		Where("ConversationID = ?", conversationID).
		OrderBy("Timestamp", dao.SortDescending)

	if beforeTimestamp > 0 {
		query = query.Where("Timestamp < ?", beforeTimestamp)
	}
	if limit > 0 {
		query = query.Limit(limit)
	}

	return query.Execute()
}

// SearchMessages performs full-text search across all message bodies.
func (b *ConversationBindings) SearchMessages(query string, limit int) ([]*entities.MessageEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Search uses prefix matching on the Body field. When qrdb_fts is enabled,
	// the FTS Match() predicate provides full-text search with tokenization.
	results := b.messages.Find(ctx).
		Where("Body PREFIX ?", query)
	if limit > 0 {
		results = results.Limit(limit)
	}
	return results.Execute()
}

// DeleteConversation removes a conversation and all its messages.
func (b *ConversationBindings) DeleteConversation(conversationID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Delete all messages in the conversation.
	msgs, err := b.messages.Find(ctx).
		Where("ConversationID = ?", conversationID).
		Execute()
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		_ = b.messages.Delete(ctx, msg)
	}

	// Delete the conversation.
	conv, err := b.conversations.QueryOneByIndex(ctx, "ConversationID", conversationID)
	if err != nil {
		return err
	}
	return b.conversations.Delete(ctx, conv)
}
