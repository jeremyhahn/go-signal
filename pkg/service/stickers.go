package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/stickers"
)

// StickersService defines the sticker-pack upload form operations exposed to
// protocol handlers.
type StickersService interface {
	// GetUploadForm returns a pack ID and per-sticker S3 POST form entries
	// for the given number of stickers.
	GetUploadForm(ctx context.Context, accountUUID string, stickerCount int) (*stickers.StickerPackFormUpload, error)
}

// stickersService is the default StickersService backed by a StickersManager.
type stickersService struct {
	manager *stickers.StickersManager
}

// NewStickersService returns a StickersService that delegates to the given
// StickersManager. The manager must not be nil.
func NewStickersService(manager *stickers.StickersManager) StickersService {
	return &stickersService{manager: manager}
}

func (s *stickersService) GetUploadForm(ctx context.Context, accountUUID string, stickerCount int) (*stickers.StickerPackFormUpload, error) {
	return s.manager.GetUploadForm(ctx, accountUUID, stickerCount)
}

// Compile-time assertion: StickersManager must satisfy StickersService.
var _ StickersService = (*stickers.StickersManager)(nil)
