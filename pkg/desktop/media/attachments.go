//go:build desktop

// Package media handles attachment encryption, upload, download, and
// thumbnail generation for the desktop client.
package media

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// AttachmentStatus constants.
const (
	StatusPending    = 0
	StatusDownloaded = 1
	StatusUploaded   = 2
	StatusFailed     = 3
)

// AttachmentManager handles attachment operations.
type AttachmentManager struct {
	factory     *daostore.Factory
	downloadDir string
}

// NewAttachmentManager creates an attachment manager.
func NewAttachmentManager(factory *daostore.Factory, downloadDir string) *AttachmentManager {
	return &AttachmentManager{
		factory:     factory,
		downloadDir: downloadDir,
	}
}

// SaveAttachment creates an attachment record linked to a message.
func (m *AttachmentManager) SaveAttachment(ctx context.Context, messageID, contentType, fileName string, size int64) (*entities.AttachmentEntity, error) {
	entity := &entities.AttachmentEntity{
		MessageID:   messageID,
		ContentType: contentType,
		FileName:    fileName,
		Size:        size,
		Status:      StatusPending,
	}
	if err := m.factory.Attachments.Save(ctx, entity); err != nil {
		return nil, err
	}
	return entity, nil
}

// GetAttachmentsForMessage returns all attachments for a message.
func (m *AttachmentManager) GetAttachmentsForMessage(ctx context.Context, messageID string) ([]*entities.AttachmentEntity, error) {
	return m.factory.Attachments.QueryByIndex(ctx, "MessageID", messageID)
}

// MarkDownloaded updates an attachment's status and local path.
func (m *AttachmentManager) MarkDownloaded(ctx context.Context, attachmentID uint64, localPath string) error {
	entity, err := m.factory.Attachments.Get(ctx, attachmentID)
	if err != nil {
		return err
	}
	entity.Status = StatusDownloaded
	entity.LocalPath = localPath
	return m.factory.Attachments.Save(ctx, entity)
}

// MarkUploaded updates an attachment's status and CDN key.
func (m *AttachmentManager) MarkUploaded(ctx context.Context, attachmentID uint64, cdnKey string, cdnNumber int) error {
	entity, err := m.factory.Attachments.Get(ctx, attachmentID)
	if err != nil {
		return err
	}
	entity.Status = StatusUploaded
	entity.CDNKey = cdnKey
	entity.CDNNumber = cdnNumber
	return m.factory.Attachments.Save(ctx, entity)
}

// EnsureDownloadDir creates the download directory if needed.
func (m *AttachmentManager) EnsureDownloadDir() error {
	return os.MkdirAll(m.downloadDir, 0700)
}

// LocalPath returns the full path for storing a downloaded attachment.
func (m *AttachmentManager) LocalPath(attachmentID uint64, ext string) string {
	return filepath.Join(m.downloadDir, fmt.Sprintf("%d%s", attachmentID, ext))
}

// StickerManager handles sticker pack operations.
type StickerManager struct {
	factory *daostore.Factory
}

// NewStickerManager creates a sticker manager.
func NewStickerManager(factory *daostore.Factory) *StickerManager {
	return &StickerManager{factory: factory}
}

// InstallPack marks a sticker pack as installed.
func (m *StickerManager) InstallPack(ctx context.Context, packID string) error {
	stickers, err := m.factory.Stickers.QueryByIndex(ctx, "PackID", packID)
	if err != nil {
		return err
	}
	for _, s := range stickers {
		s.Installed = true
		if err := m.factory.Stickers.Save(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// GetInstalledPacks returns sticker packs that are installed.
func (m *StickerManager) GetInstalledPacks(ctx context.Context) ([]*entities.StickerEntity, error) {
	return m.factory.Stickers.Find(ctx).
		Where("Installed = ?", true).
		Execute()
}

// GetStickersInPack returns all stickers in a pack.
func (m *StickerManager) GetStickersInPack(ctx context.Context, packID string) ([]*entities.StickerEntity, error) {
	return m.factory.Stickers.QueryByIndex(ctx, "PackID", packID)
}

// SaveSticker saves a sticker entity.
func (m *StickerManager) SaveSticker(ctx context.Context, sticker *entities.StickerEntity) error {
	_ = time.Now() // satisfy import
	return m.factory.Stickers.Save(ctx, sticker)
}
