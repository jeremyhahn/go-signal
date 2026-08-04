package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStickerPackEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {13}} {
		e := &StickerPackEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestStickerPackEntity_SetEntityID(t *testing.T) {
	e := &StickerPackEntity{}
	e.SetEntityID(7)
	assert.Equal(t, uint64(7), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

func TestStickerPackEntity_Fields(t *testing.T) {
	e := &StickerPackEntity{
		ID:      2,
		PackID:  "pack-xyz",
		PackKey: "hex-key",
		URL:     "https://signal.art/addstickers/#pack_id=pack-xyz",
		Title:   "Cute Animals",
	}
	assert.Equal(t, uint64(2), e.EntityID())
	assert.Equal(t, "pack-xyz", e.PackID)
	assert.Equal(t, "Cute Animals", e.Title)
}
