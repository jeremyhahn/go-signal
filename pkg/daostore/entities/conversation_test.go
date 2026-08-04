package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConversationTypes_Constants(t *testing.T) {
	assert.Equal(t, 1, ConversationTypeDirect)
	assert.Equal(t, 2, ConversationTypeGroup)
	assert.Equal(t, 3, ConversationTypeSelf)
}

func TestConversationEntity_EntityID(t *testing.T) {
	tests := []struct {
		name string
		id   uint64
	}{
		{"zero", 0},
		{"ten", 10},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &ConversationEntity{ID: tc.id}
			assert.Equal(t, tc.id, e.EntityID())
		})
	}
}

func TestConversationEntity_SetEntityID(t *testing.T) {
	tests := []struct {
		name string
		id   uint64
	}{
		{"set_55", 55},
		{"set_max", ^uint64(0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &ConversationEntity{}
			e.SetEntityID(tc.id)
			assert.Equal(t, tc.id, e.ID)
		})
	}
}

func TestConversationEntity_Fields(t *testing.T) {
	e := &ConversationEntity{
		ID:                   2,
		ConversationID:       "conv-xyz",
		Type:                 ConversationTypeDirect,
		Name:                 "Bob",
		UnreadCount:          4,
		LastMessageTimestamp: 1_700_000_000,
		LastMessageBody:      "hello",
		IsPinned:             true,
		IsArchived:           false,
		IsMuted:              true,
		ExpirationTimer:      3600,
	}
	assert.Equal(t, uint64(2), e.EntityID())
	assert.Equal(t, "conv-xyz", e.ConversationID)
	assert.True(t, e.IsPinned)
}
