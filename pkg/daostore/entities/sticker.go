package entities

import "github.com/jeremyhahn/go-qrdb/pkg/index"

// StickerEntity represents a sticker in a sticker pack.
type StickerEntity struct {
	ID          uint64 `json:"id"`
	PackID      string `json:"packId" index:"true"`
	PackKey     []byte `json:"packKey,omitempty"`
	StickerID   int    `json:"stickerId"`
	Emoji       string `json:"emoji,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	LocalPath   string `json:"localPath,omitempty"`
	Installed   bool   `json:"installed"`
}

func (s *StickerEntity) EntityID() uint64      { return s.ID }
func (s *StickerEntity) SetEntityID(id uint64) { s.ID = id }

// CompoundIndexes declares a compound index on (PackID, StickerID).
func (s StickerEntity) CompoundIndexes() []index.CompoundIndexDef {
	return []index.CompoundIndexDef{
		{Fields: []string{"PackID", "StickerID"}},
	}
}
