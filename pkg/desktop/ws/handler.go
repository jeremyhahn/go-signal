//go:build desktop

package ws

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// DefaultHandler decrypts incoming WebSocket messages, persists them
// to the local DAO store, and prepares them for event bus emission.
type DefaultHandler struct {
	daoFactory *daostore.Factory
}

// NewDefaultHandler creates a message handler backed by the DAO factory.
func NewDefaultHandler(daoFactory *daostore.Factory) *DefaultHandler {
	return &DefaultHandler{daoFactory: daoFactory}
}

// HandleMessage processes an incoming message: persists to the messages
// DAO and updates the conversation's last message metadata.
func (h *DefaultHandler) HandleMessage(msg signal.ReceivedMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Persist the message.
	entity := &entities.MessageEntity{
		GUID:            msg.GUID,
		ConversationID:  msg.Source,
		SourceUUID:      msg.Source,
		SourceDevice:    uint32(msg.SourceDevice),
		Timestamp:       msg.Timestamp,
		ServerTimestamp: msg.ServerTimestamp,
		Type:            1, // incoming
		Body:            msg.Body,
		IsRead:          false,
		SendState:       3, // delivered
	}
	_ = h.daoFactory.Messages.Save(ctx, entity)

	// Update conversation last message.
	convs, err := h.daoFactory.Conversations.Find(ctx).
		Where("ConversationID = ?", msg.Source).
		Execute()
	if err != nil || len(convs) == 0 {
		// Create new conversation.
		conv := &entities.ConversationEntity{
			ConversationID:       msg.Source,
			Type:                 entities.ConversationTypeDirect,
			Name:                 msg.Source,
			UnreadCount:          1,
			LastMessageTimestamp: msg.Timestamp,
			LastMessageBody:      msg.Body,
			ActiveAt:             time.Now().UnixMilli(),
		}
		_ = h.daoFactory.Conversations.Save(ctx, conv)
		return
	}

	// Update existing conversation.
	conv := convs[0]
	conv.LastMessageTimestamp = msg.Timestamp
	conv.LastMessageBody = msg.Body
	conv.UnreadCount++
	conv.ActiveAt = time.Now().UnixMilli()
	_ = h.daoFactory.Conversations.Save(ctx, conv)
}
