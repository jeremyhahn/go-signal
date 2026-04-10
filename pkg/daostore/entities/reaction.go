package entities

import "github.com/jeremyhahn/go-qrdb/pkg/index"

// ReactionEntity represents an emoji reaction on a message.
type ReactionEntity struct {
	ID         uint64 `json:"id"`
	MessageID  string `json:"messageId" index:"true"`
	AuthorUUID string `json:"authorUuid" index:"true"`
	Emoji      string `json:"emoji"`
	ReceivedAt int64  `json:"receivedAt"`
}

func (r *ReactionEntity) EntityID() uint64      { return r.ID }
func (r *ReactionEntity) SetEntityID(id uint64)  { r.ID = id }

// CompoundIndexes declares a unique compound index on (MessageID, AuthorUUID)
// since each author can have at most one reaction per message.
func (r ReactionEntity) CompoundIndexes() []index.CompoundIndexDef {
	return []index.CompoundIndexDef{
		{Fields: []string{"MessageID", "AuthorUUID"}, Unique: true},
	}
}
