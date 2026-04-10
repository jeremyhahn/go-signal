package entities

// ConversationType identifies the kind of conversation.
const (
	ConversationTypeDirect = 1
	ConversationTypeGroup  = 2
	ConversationTypeSelf   = 3
)

// ConversationEntity represents a conversation (1:1, group, or self).
type ConversationEntity struct {
	ID                   uint64 `json:"id"`
	ConversationID       string `json:"conversationId" index:"unique"`
	Type                 int    `json:"type"`
	Name                 string `json:"name"`
	AvatarPath           string `json:"avatarPath,omitempty"`
	UnreadCount          int    `json:"unreadCount"`
	LastMessageTimestamp int64  `json:"lastMessageTimestamp" index:"true"`
	LastMessageBody      string `json:"lastMessageBody,omitempty"`
	IsPinned             bool   `json:"isPinned" index:"true"`
	IsArchived           bool   `json:"isArchived"`
	IsMuted              bool   `json:"isMuted"`
	MutedUntil           int64  `json:"mutedUntil,omitempty"`
	ExpirationTimer      int    `json:"expirationTimer"`
	Draft                string `json:"draft,omitempty"`
	ActiveAt             int64  `json:"activeAt" index:"true"`
}

func (c *ConversationEntity) EntityID() uint64      { return c.ID }
func (c *ConversationEntity) SetEntityID(id uint64)  { c.ID = id }
