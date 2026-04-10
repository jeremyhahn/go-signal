//go:build desktop

package bindings

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// ReactionBindings provides reaction operations to the frontend.
type ReactionBindings struct {
	factory *daostore.Factory
}

// NewReactionBindings creates reaction bindings.
func NewReactionBindings(f *daostore.Factory) *ReactionBindings {
	return &ReactionBindings{factory: f}
}

// GetReactions returns all reactions for a message.
func (b *ReactionBindings) GetReactions(messageID string) ([]*entities.ReactionEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.factory.Reactions.QueryByIndex(ctx, "MessageID", messageID)
}

// SaveReaction stores a reaction from a remote user. Uses the compound
// unique index (MessageID, AuthorUUID) to enforce one reaction per author.
func (b *ReactionBindings) SaveReaction(messageID, authorUUID, emoji string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check for existing reaction by this author on this message.
	existing, err := b.factory.Reactions.QueryByCompoundIndex(ctx,
		"reactions.MessageID_AuthorUUID",
		[]interface{}{messageID, authorUUID},
	)
	if err == nil && len(existing) > 0 {
		existing[0].Emoji = emoji
		existing[0].ReceivedAt = time.Now().UnixMilli()
		return b.factory.Reactions.Save(ctx, existing[0])
	}

	entity := &entities.ReactionEntity{
		MessageID:  messageID,
		AuthorUUID: authorUUID,
		Emoji:      emoji,
		ReceivedAt: time.Now().UnixMilli(),
	}
	return b.factory.Reactions.Save(ctx, entity)
}

// RemoveReaction removes a reaction.
func (b *ReactionBindings) RemoveReaction(messageID, authorUUID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	existing, err := b.factory.Reactions.QueryByCompoundIndex(ctx,
		"reactions.MessageID_AuthorUUID",
		[]interface{}{messageID, authorUUID},
	)
	if err != nil || len(existing) == 0 {
		return nil
	}
	return b.factory.Reactions.Delete(ctx, existing[0])
}
