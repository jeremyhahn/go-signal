package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReactionEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {9}} {
		e := &ReactionEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestReactionEntity_SetEntityID(t *testing.T) {
	e := &ReactionEntity{}
	e.SetEntityID(3)
	assert.Equal(t, uint64(3), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

func TestReactionEntity_CompoundIndexes(t *testing.T) {
	e := ReactionEntity{}
	defs := e.CompoundIndexes()
	require.Len(t, defs, 1)
	assert.Equal(t, []string{"MessageID", "AuthorUUID"}, defs[0].Fields)
	assert.True(t, defs[0].Unique)
}

func TestReactionEntity_CompoundIndexes_Unique(t *testing.T) {
	// Each author may only react once per message — the compound index must be unique.
	e := ReactionEntity{MessageID: "m1", AuthorUUID: "u1"}
	defs := e.CompoundIndexes()
	for _, d := range defs {
		assert.True(t, d.Unique)
	}
}

func TestReactionEntity_Fields(t *testing.T) {
	e := &ReactionEntity{
		ID:         4,
		MessageID:  "msg-2",
		AuthorUUID: "author-uuid",
		Emoji:      "👍",
		ReceivedAt: 1_700_000_999,
	}
	assert.Equal(t, uint64(4), e.EntityID())
	assert.Equal(t, "👍", e.Emoji)
}
