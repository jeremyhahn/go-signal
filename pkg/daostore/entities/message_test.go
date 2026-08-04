package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {100}} {
		e := &MessageEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestMessageEntity_SetEntityID(t *testing.T) {
	e := &MessageEntity{}
	e.SetEntityID(55)
	assert.Equal(t, uint64(55), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

func TestMessageEntity_CompoundIndexes(t *testing.T) {
	e := MessageEntity{}
	defs := e.CompoundIndexes()
	require.Len(t, defs, 2)
	assert.Equal(t, []string{"ConversationID", "Timestamp"}, defs[0].Fields)
	assert.Equal(t, []string{"ConversationID", "IsRead"}, defs[1].Fields)
}

func TestMessageEntity_CompoundIndexes_Consistent(t *testing.T) {
	e1 := MessageEntity{ConversationID: "c1", Timestamp: 100}
	e2 := MessageEntity{ConversationID: "c2", Timestamp: 200}
	assert.Equal(t, e1.CompoundIndexes(), e2.CompoundIndexes())
}

func TestMessageEntity_Fields(t *testing.T) {
	e := &MessageEntity{
		ID:             1,
		GUID:           "guid-1",
		ConversationID: "conv-1",
		SourceUUID:     "src-uuid",
		Body:           "Hello",
		IsRead:         true,
		IsDeleted:      false,
	}
	assert.Equal(t, uint64(1), e.EntityID())
	assert.Equal(t, "Hello", e.Body)
	assert.True(t, e.IsRead)
}
