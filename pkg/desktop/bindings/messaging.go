//go:build desktop

package bindings

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// MessagingBindings provides message sending and receiving operations.
type MessagingBindings struct {
	client  *signal.Client
	factory *daostore.Factory
}

// NewMessagingBindings creates messaging bindings.
func NewMessagingBindings(client *signal.Client, f *daostore.Factory) *MessagingBindings {
	return &MessagingBindings{client: client, factory: f}
}

// SendMessage sends a text message and persists it locally.
func (b *MessagingBindings) SendMessage(recipient, body string, opts *signal.SendOptions) (*signal.SendResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := b.client.Send(ctx, recipient, body, opts)
	if err != nil {
		return nil, err
	}

	// Persist sent message locally.
	entity := &entities.MessageEntity{
		GUID:           "",
		ConversationID: recipient,
		Timestamp:      result.Timestamp,
		Type:           2, // outgoing
		Body:           body,
		IsRead:         true,
		SendState:      1, // sent
	}
	_ = b.factory.Messages.Save(ctx, entity)

	// Update conversation.
	convs, err := b.factory.Conversations.Find(ctx).
		Where("ConversationID = ?", recipient).
		Execute()
	if err == nil && len(convs) > 0 {
		conv := convs[0]
		conv.LastMessageTimestamp = result.Timestamp
		conv.LastMessageBody = body
		conv.ActiveAt = time.Now().UnixMilli()
		_ = b.factory.Conversations.Save(ctx, conv)
	}

	return result, nil
}

// SendReaction sends an emoji reaction to a message.
func (b *MessagingBindings) SendReaction(recipient, emoji string, targetTimestamp int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.SendReaction(ctx, recipient, signal.Reaction{
		Emoji:     emoji,
		Timestamp: targetTimestamp,
	})
}

// SendTyping sends a typing indicator.
func (b *MessagingBindings) SendTyping(recipient string, started bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.SendTyping(ctx, recipient, started)
}

// SendReadReceipt sends a read receipt for the given message timestamps.
func (b *MessagingBindings) SendReadReceipt(recipient string, timestamps []int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.SendReceipt(ctx, recipient, "read", timestamps)
}

// RemoteDelete requests deletion of a message for all recipients.
func (b *MessagingBindings) RemoteDelete(recipient string, targetTimestamp int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.RemoteDelete(ctx, recipient, targetTimestamp)
}
