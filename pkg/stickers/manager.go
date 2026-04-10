package stickers

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// StickersManager manages sticker pack upload form generation.
type StickersManager struct {
	logger *slog.Logger
}

// NewStickersManager creates a new StickersManager.
func NewStickersManager(logger *slog.Logger) *StickersManager {
	return &StickersManager{logger: logger}
}

// GetUploadForm generates a stub upload form with the given number of sticker
// fields. Each field receives a unique key for CDN upload.
func (m *StickersManager) GetUploadForm(ctx context.Context, stickerCount int) (*StickerPackFormUpload, error) {
	if stickerCount < 1 || stickerCount > 201 {
		return nil, &InvalidStickerCountError{Count: stickerCount}
	}

	packId := uuid.NewString()

	manifest := StickerFormField{
		Id:       0,
		Key:      "stickers/" + packId + "/manifest",
		Headers:  map[string]string{},
		Location: "/cdn3/stickers/" + packId + "/manifest",
	}

	stickers := make([]StickerFormField, stickerCount)
	for i := range stickerCount {
		stickerKey := uuid.NewString()
		stickers[i] = StickerFormField{
			Id:       i + 1,
			Key:      "stickers/" + packId + "/" + stickerKey,
			Headers:  map[string]string{},
			Location: "/cdn3/stickers/" + packId + "/" + stickerKey,
		}
	}

	return &StickerPackFormUpload{
		PackId:   packId,
		Manifest: manifest,
		Stickers: stickers,
	}, nil
}
