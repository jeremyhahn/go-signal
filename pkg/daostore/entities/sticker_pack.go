package entities

// StickerPackEntity records one locally-installed sticker pack. The
// CLI's addStickerPack command persists rows here so getSticker can
// look up the pack key without the operator re-typing it.
type StickerPackEntity struct {
	ID      uint64 `json:"id"`
	PackID  string `json:"packId" index:"true"`
	PackKey string `json:"packKey,omitempty"`
	URL     string `json:"url,omitempty"`
	Title   string `json:"title,omitempty"`
}

func (s *StickerPackEntity) EntityID() uint64      { return s.ID }
func (s *StickerPackEntity) SetEntityID(id uint64) { s.ID = id }
