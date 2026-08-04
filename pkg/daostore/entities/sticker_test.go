package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStickerEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {22}} {
		e := &StickerEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestStickerEntity_SetEntityID(t *testing.T) {
	e := &StickerEntity{}
	e.SetEntityID(11)
	assert.Equal(t, uint64(11), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

func TestStickerEntity_CompoundIndexes(t *testing.T) {
	e := StickerEntity{}
	defs := e.CompoundIndexes()
	require.Len(t, defs, 1)
	assert.Equal(t, []string{"PackID", "StickerID"}, defs[0].Fields)
}

func TestStickerEntity_CompoundIndexes_Consistent(t *testing.T) {
	e1 := StickerEntity{PackID: "p1", StickerID: 1}
	e2 := StickerEntity{PackID: "p2", StickerID: 2}
	assert.Equal(t, e1.CompoundIndexes(), e2.CompoundIndexes())
}

func TestStickerEntity_Fields(t *testing.T) {
	e := &StickerEntity{
		ID:          6,
		PackID:      "pack-abc",
		PackKey:     []byte{0xAA, 0xBB},
		StickerID:   3,
		Emoji:       "😎",
		ContentType: "image/webp",
		LocalPath:   "/tmp/sticker.webp",
		Installed:   true,
	}
	assert.Equal(t, uint64(6), e.EntityID())
	assert.True(t, e.Installed)
	assert.Equal(t, "😎", e.Emoji)
}
