//go:build desktop

package media

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dberrors "github.com/jeremyhahn/go-qrdb/pkg/errors"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// ---------------------------------------------------------------------------
// In-memory KVStore with index support (shared across all media tests)
// ---------------------------------------------------------------------------

type mediaKVStore struct {
	mu          sync.RWMutex
	data        map[string][]byte
	regIndexes  map[string][]kvstore.EntityIndex
	singleIdx   map[string]map[string][]string
	compoundIdx map[string]map[string][]string
}

func newMediaKVStore() kvstore.KVStore {
	return &mediaKVStore{
		data:        make(map[string][]byte),
		regIndexes:  make(map[string][]kvstore.EntityIndex),
		singleIdx:   make(map[string]map[string][]string),
		compoundIdx: make(map[string]map[string][]string),
	}
}

func (s *mediaKVStore) etFromKey(key string) string {
	if i := strings.Index(key, "/"); i >= 0 {
		return key[:i]
	}
	return ""
}

func (s *mediaKVStore) addIdx(et, key string, value []byte) {
	idxs, ok := s.regIndexes[et]
	if !ok {
		return
	}
	var fields map[string]interface{}
	if json.Unmarshal(value, &fields) != nil {
		return
	}
	for _, idx := range idxs {
		if len(idx.FieldNames) > 0 {
			name := et + "." + strings.Join(idx.FieldNames, "_")
			vals := make([]string, len(idx.JSONFieldNames))
			for i, jn := range idx.JSONFieldNames {
				if v, ok := fields[jn]; ok {
					vals[i] = fmt.Sprint(v)
				}
			}
			enc := strings.Join(vals, "|")
			if s.compoundIdx[name] == nil {
				s.compoundIdx[name] = make(map[string][]string)
			}
			s.compoundIdx[name][enc] = mediaAppendUniq(s.compoundIdx[name][enc], key)
		} else if idx.JSONFieldName != "" {
			name := et + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[name] == nil {
					s.singleIdx[name] = make(map[string][]string)
				}
				s.singleIdx[name][fv] = mediaAppendUniq(s.singleIdx[name][fv], key)
			}
		}
	}
}

func (s *mediaKVStore) removeIdx(et, key string, value []byte) {
	idxs, ok := s.regIndexes[et]
	if !ok {
		return
	}
	var fields map[string]interface{}
	if json.Unmarshal(value, &fields) != nil {
		return
	}
	for _, idx := range idxs {
		if len(idx.FieldNames) > 0 {
			name := et + "." + strings.Join(idx.FieldNames, "_")
			vals := make([]string, len(idx.JSONFieldNames))
			for i, jn := range idx.JSONFieldNames {
				if v, ok := fields[jn]; ok {
					vals[i] = fmt.Sprint(v)
				}
			}
			enc := strings.Join(vals, "|")
			if s.compoundIdx[name] != nil {
				s.compoundIdx[name][enc] = mediaRemoveFrom(s.compoundIdx[name][enc], key)
			}
		} else if idx.JSONFieldName != "" {
			name := et + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[name] != nil {
					s.singleIdx[name][fv] = mediaRemoveFrom(s.singleIdx[name][fv], key)
				}
			}
		}
	}
}

func (s *mediaKVStore) Put(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	et := s.etFromKey(key)
	if et != "" {
		if old, ok := s.data[key]; ok {
			s.removeIdx(et, key, old)
		}
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	s.data[key] = cp
	if et != "" {
		s.addIdx(et, key, cp)
	}
	return nil
}

func (s *mediaKVStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, &dberrors.QRDBError{Code: dberrors.ErrNotFound, Op: "kv.get"}
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (s *mediaKVStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.data[key]; ok {
		if et := s.etFromKey(key); et != "" {
			s.removeIdx(et, key, old)
		}
		delete(s.data, key)
	}
	return nil
}

func (s *mediaKVStore) Scan(_ context.Context, prefix string, fn func(string, []byte) error) error {
	s.mu.RLock()
	var keys []string
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	vals := make(map[string][]byte, len(keys))
	for _, k := range keys {
		v := s.data[k]
		cp := make([]byte, len(v))
		copy(cp, v)
		vals[k] = cp
	}
	s.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		if err := fn(k, vals[k]); err != nil {
			return err
		}
	}
	return nil
}

func (s *mediaKVStore) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (s *mediaKVStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[key]
	return ok, nil
}

func (s *mediaKVStore) RegisterEntityIndexes(et string, idxs []kvstore.EntityIndex) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Registration accumulates, as the kvstore contract requires: the DAO
	// registers single-field and compound indexes in separate calls.
	for _, idx := range idxs {
		name := idx.ResolvedName(et)
		if !slices.ContainsFunc(s.regIndexes[et], func(have kvstore.EntityIndex) bool {
			return have.ResolvedName(et) == name
		}) {
			s.regIndexes[et] = append(s.regIndexes[et], idx)
		}
	}
	return nil
}

func (s *mediaKVStore) QueryIndex(_ context.Context, indexName string, value []byte) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.singleIdx[indexName]
	if !ok {
		return nil, nil
	}
	keys := idx[string(value)]
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = []byte(k)
	}
	return result, nil
}

func (s *mediaKVStore) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

func (s *mediaKVStore) QueryCompoundIndex(_ context.Context, indexName string, values [][]byte) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.compoundIdx[indexName]
	if !ok {
		return nil, nil
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = string(v)
	}
	enc := strings.Join(parts, "|")
	keys := idx[enc]
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = []byte(k)
	}
	return result, nil
}

func (s *mediaKVStore) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

var _ kvstore.KVStore = (*mediaKVStore)(nil)

func mediaAppendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func mediaRemoveFrom(slice []string, s string) []string {
	out := make([]string, 0, len(slice))
	for _, v := range slice {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// newTestFactory builds a daostore.Factory backed by the in-memory KVStore.
func newTestFactory(t *testing.T) *daostore.Factory {
	t.Helper()
	store := newMediaKVStore()
	f, err := daostore.NewFactory(store)
	require.NoError(t, err)
	return f
}

// ---------------------------------------------------------------------------
// AttachmentManager tests
// ---------------------------------------------------------------------------

// TestNewAttachmentManager verifies construction.
func TestNewAttachmentManager(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp/attachments")
		require.NotNil(t, m)
	})
	t.Run("FieldsSet", func(t *testing.T) {
		f := newTestFactory(t)
		m := NewAttachmentManager(f, "/tmp/test")
		assert.Equal(t, "/tmp/test", m.downloadDir)
		assert.Equal(t, f, m.factory)
	})
}

// TestAttachmentManager_SaveAttachment verifies that SaveAttachment creates an entity.
func TestAttachmentManager_SaveAttachment(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		entity, err := m.SaveAttachment(context.Background(), "msg-1", "image/png", "photo.png", 1024)
		require.NoError(t, err)
		require.NotNil(t, entity)
		assert.Equal(t, "msg-1", entity.MessageID)
		assert.Equal(t, "image/png", entity.ContentType)
		assert.Equal(t, "photo.png", entity.FileName)
		assert.Equal(t, int64(1024), entity.Size)
		assert.Equal(t, StatusPending, entity.Status)
	})
	t.Run("DifferentContentTypes", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		e, err := m.SaveAttachment(context.Background(), "msg-2", "video/mp4", "clip.mp4", 2048000)
		require.NoError(t, err)
		assert.Equal(t, "video/mp4", e.ContentType)
	})
}

// TestAttachmentManager_GetAttachmentsForMessage verifies index-based lookup.
func TestAttachmentManager_GetAttachmentsForMessage(t *testing.T) {
	t.Run("ReturnsMatchingAttachments", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		ctx := context.Background()
		_, err := m.SaveAttachment(ctx, "msg-10", "image/jpeg", "a.jpg", 512)
		require.NoError(t, err)
		_, err = m.SaveAttachment(ctx, "msg-10", "image/png", "b.png", 256)
		require.NoError(t, err)

		attachments, err := m.GetAttachmentsForMessage(ctx, "msg-10")
		require.NoError(t, err)
		assert.Len(t, attachments, 2)
	})
	t.Run("EmptyForUnknownMessage", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		attachments, err := m.GetAttachmentsForMessage(context.Background(), "unknown-msg")
		require.NoError(t, err)
		assert.Empty(t, attachments)
	})
}

// TestAttachmentManager_MarkDownloaded verifies status update.
func TestAttachmentManager_MarkDownloaded(t *testing.T) {
	t.Run("UpdatesStatusAndPath", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		ctx := context.Background()
		e, err := m.SaveAttachment(ctx, "msg-20", "image/png", "c.png", 100)
		require.NoError(t, err)

		err = m.MarkDownloaded(ctx, e.ID, "/tmp/c.png")
		require.NoError(t, err)

		// Verify by fetching via QueryByIndex.
		updated, err := m.factory.Attachments.Get(ctx, e.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusDownloaded, updated.Status)
		assert.Equal(t, "/tmp/c.png", updated.LocalPath)
	})
	t.Run("ErrorOnUnknownID", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		err := m.MarkDownloaded(context.Background(), 9999999999, "/tmp/x.png")
		require.Error(t, err)
	})
}

// TestAttachmentManager_MarkUploaded verifies CDN metadata update.
func TestAttachmentManager_MarkUploaded(t *testing.T) {
	t.Run("UpdatesCDNInfo", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		ctx := context.Background()
		e, err := m.SaveAttachment(ctx, "msg-30", "application/pdf", "doc.pdf", 4096)
		require.NoError(t, err)

		err = m.MarkUploaded(ctx, e.ID, "cdn-key-abc", 2)
		require.NoError(t, err)

		updated, err := m.factory.Attachments.Get(ctx, e.ID)
		require.NoError(t, err)
		assert.Equal(t, StatusUploaded, updated.Status)
		assert.Equal(t, "cdn-key-abc", updated.CDNKey)
		assert.Equal(t, 2, updated.CDNNumber)
	})
	t.Run("ErrorOnUnknownID", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/tmp")
		err := m.MarkUploaded(context.Background(), 9999999998, "key", 1)
		require.Error(t, err)
	})
}

// TestAttachmentManager_EnsureDownloadDir verifies directory creation.
func TestAttachmentManager_EnsureDownloadDir(t *testing.T) {
	t.Run("CreatesDirectory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "attachments")
		m := NewAttachmentManager(newTestFactory(t), dir)
		require.NoError(t, m.EnsureDownloadDir())
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})
	t.Run("IdempotentOnExisting", func(t *testing.T) {
		dir := t.TempDir()
		m := NewAttachmentManager(newTestFactory(t), dir)
		require.NoError(t, m.EnsureDownloadDir())
		require.NoError(t, m.EnsureDownloadDir())
	})
}

// TestAttachmentManager_LocalPath verifies the path construction.
func TestAttachmentManager_LocalPath(t *testing.T) {
	t.Run("CorrectFormat", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/downloads")
		p := m.LocalPath(42, ".jpg")
		assert.Equal(t, "/downloads/42.jpg", p)
	})
	t.Run("NoExtension", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/dl")
		p := m.LocalPath(1, "")
		assert.Equal(t, "/dl/1", p)
	})
	t.Run("NestedDir", func(t *testing.T) {
		m := NewAttachmentManager(newTestFactory(t), "/a/b/c")
		p := m.LocalPath(7, ".mp4")
		assert.Equal(t, "/a/b/c/7.mp4", p)
	})
}

// TestStatusConstants verifies the attachment status values.
func TestStatusConstants(t *testing.T) {
	assert.Equal(t, 0, StatusPending)
	assert.Equal(t, 1, StatusDownloaded)
	assert.Equal(t, 2, StatusUploaded)
	assert.Equal(t, 3, StatusFailed)
}

// ---------------------------------------------------------------------------
// StickerManager tests
// ---------------------------------------------------------------------------

// TestNewStickerManager verifies construction.
func TestNewStickerManager(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		require.NotNil(t, m)
	})
}

// TestStickerManager_SaveSticker verifies sticker persistence.
func TestStickerManager_SaveSticker(t *testing.T) {
	t.Run("SavesEntity", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		sticker := &entities.StickerEntity{
			PackID:      "pack-1",
			StickerID:   1,
			Emoji:       "😀",
			ContentType: "image/webp",
		}
		err := m.SaveSticker(context.Background(), sticker)
		require.NoError(t, err)
		assert.NotZero(t, sticker.ID)
	})
	t.Run("MultipleSaves", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		for i := 0; i < 3; i++ {
			s := &entities.StickerEntity{PackID: "pack-x", StickerID: i}
			require.NoError(t, m.SaveSticker(context.Background(), s))
		}
	})
}

// TestStickerManager_GetStickersInPack verifies pack-based lookup.
func TestStickerManager_GetStickersInPack(t *testing.T) {
	t.Run("ReturnsMatchingStickers", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			s := &entities.StickerEntity{PackID: "pack-abc", StickerID: i, Emoji: "🎉"}
			require.NoError(t, m.SaveSticker(ctx, s))
		}
		stickers, err := m.GetStickersInPack(ctx, "pack-abc")
		require.NoError(t, err)
		assert.Len(t, stickers, 3)
	})
	t.Run("EmptyForUnknownPack", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		stickers, err := m.GetStickersInPack(context.Background(), "no-such-pack")
		require.NoError(t, err)
		assert.Empty(t, stickers)
	})
}

// TestStickerManager_InstallPack verifies that stickers are marked installed.
func TestStickerManager_InstallPack(t *testing.T) {
	t.Run("MarksStickersAsInstalled", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			s := &entities.StickerEntity{PackID: "pack-install", StickerID: i}
			require.NoError(t, m.SaveSticker(ctx, s))
		}
		err := m.InstallPack(ctx, "pack-install")
		require.NoError(t, err)

		stickers, err := m.GetStickersInPack(ctx, "pack-install")
		require.NoError(t, err)
		for _, s := range stickers {
			assert.True(t, s.Installed)
		}
	})
	t.Run("NoStickersIsNoop", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		err := m.InstallPack(context.Background(), "empty-pack")
		require.NoError(t, err)
	})
}

// TestStickerManager_GetInstalledPacks verifies filtering by Installed flag.
func TestStickerManager_GetInstalledPacks(t *testing.T) {
	t.Run("ReturnsOnlyInstalled", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		ctx := context.Background()

		s1 := &entities.StickerEntity{PackID: "pack-A", StickerID: 1, Installed: true}
		s2 := &entities.StickerEntity{PackID: "pack-B", StickerID: 2, Installed: false}
		require.NoError(t, m.SaveSticker(ctx, s1))
		require.NoError(t, m.SaveSticker(ctx, s2))

		installed, err := m.GetInstalledPacks(ctx)
		require.NoError(t, err)
		for _, s := range installed {
			assert.True(t, s.Installed)
		}
	})
	t.Run("EmptyWhenNoneInstalled", func(t *testing.T) {
		m := NewStickerManager(newTestFactory(t))
		ctx := context.Background()
		s := &entities.StickerEntity{PackID: "pack-Z", StickerID: 99, Installed: false}
		require.NoError(t, m.SaveSticker(ctx, s))

		installed, err := m.GetInstalledPacks(ctx)
		require.NoError(t, err)
		assert.Empty(t, installed)
	})
}
