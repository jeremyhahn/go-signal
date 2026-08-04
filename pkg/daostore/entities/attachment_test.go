package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttachmentEntity_EntityID(t *testing.T) {
	tests := []struct {
		name string
		id   uint64
	}{
		{"zero", 0},
		{"nonzero", 42},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &AttachmentEntity{ID: tc.id}
			assert.Equal(t, tc.id, e.EntityID())
		})
	}
}

func TestAttachmentEntity_SetEntityID(t *testing.T) {
	tests := []struct {
		name string
		id   uint64
	}{
		{"set_to_1", 1},
		{"set_to_large", 999999},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &AttachmentEntity{}
			e.SetEntityID(tc.id)
			assert.Equal(t, tc.id, e.ID)
		})
	}
}

func TestAttachmentEntity_Fields(t *testing.T) {
	e := &AttachmentEntity{
		ID:            1,
		MessageID:     "msg-abc",
		ContentType:   "image/jpeg",
		FileName:      "photo.jpg",
		Size:          2048,
		LocalPath:     "/tmp/photo.jpg",
		CDNKey:        "cdn-key-1",
		CDNNumber:     3,
		Width:         1280,
		Height:        720,
		ThumbnailPath: "/tmp/thumb.jpg",
		Digest:        []byte{0xde, 0xad},
		Status:        1,
	}
	assert.Equal(t, uint64(1), e.EntityID())
	assert.Equal(t, "msg-abc", e.MessageID)
	assert.Equal(t, int64(2048), e.Size)
}
