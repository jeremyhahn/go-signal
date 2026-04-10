package entities

import "github.com/jeremyhahn/go-qrdb/pkg/index"

// MessageEntity represents a Signal message stored locally.
type MessageEntity struct {
	ID             uint64 `json:"id"`
	GUID           string `json:"guid" index:"true"`
	ConversationID string `json:"conversationId" index:"true"`
	SourceUUID     string `json:"sourceUuid"`
	SourceDevice   uint32 `json:"sourceDevice"`
	Timestamp      int64  `json:"timestamp" index:"true"`
	ServerTimestamp int64  `json:"serverTimestamp"`
	Type           int    `json:"type"`
	Body           string `json:"body"`
	HasAttachments bool   `json:"hasAttachments"`
	QuoteID        string `json:"quoteId,omitempty"`
	QuoteAuthor    string `json:"quoteAuthor,omitempty"`
	QuoteBody      string `json:"quoteBody,omitempty"`
	ExpiresAt      int64  `json:"expiresAt,omitempty"`
	IsRead         bool   `json:"isRead" index:"true"`
	SendState      int    `json:"sendState"`
	EditTimestamp  int64  `json:"editTimestamp,omitempty"`
	IsDeleted      bool   `json:"isDeleted"`
}

func (m *MessageEntity) EntityID() uint64      { return m.ID }
func (m *MessageEntity) SetEntityID(id uint64)  { m.ID = id }

// CompoundIndexes declares multi-field indexes for efficient message queries.
func (m MessageEntity) CompoundIndexes() []index.CompoundIndexDef {
	return []index.CompoundIndexDef{
		{Fields: []string{"ConversationID", "Timestamp"}},
		{Fields: []string{"ConversationID", "IsRead"}},
	}
}
