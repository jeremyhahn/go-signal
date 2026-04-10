package stickers

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestNewStickersManager_NotNil(t *testing.T) {
	m := NewStickersManager(testLogger())
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewStickersManager_StoresLogger(t *testing.T) {
	logger := testLogger()
	m := NewStickersManager(logger)
	if m.logger != logger {
		t.Error("logger not stored correctly")
	}
}

func TestGetUploadForm_SingleSticker(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if form.PackId == "" {
		t.Fatal("expected non-empty pack ID")
	}
	if len(form.Stickers) != 1 {
		t.Fatalf("got %d stickers, want 1", len(form.Stickers))
	}
	if form.Stickers[0].Id != 1 {
		t.Errorf("sticker ID = %d, want 1", form.Stickers[0].Id)
	}
}

func TestGetUploadForm_MaxStickers(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 201)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(form.Stickers) != 201 {
		t.Fatalf("got %d stickers, want 201", len(form.Stickers))
	}
}

func TestGetUploadForm_ManifestFields(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if form.Manifest.Id != 0 {
		t.Errorf("manifest ID = %d, want 0", form.Manifest.Id)
	}
	if !strings.Contains(form.Manifest.Key, form.PackId) {
		t.Errorf("manifest key %q should contain pack ID %q", form.Manifest.Key, form.PackId)
	}
	if !strings.HasSuffix(form.Manifest.Key, "/manifest") {
		t.Errorf("manifest key %q should end with /manifest", form.Manifest.Key)
	}
	if !strings.Contains(form.Manifest.Location, form.PackId) {
		t.Errorf("manifest location %q should contain pack ID %q", form.Manifest.Location, form.PackId)
	}
	if form.Manifest.Headers == nil {
		t.Error("manifest headers should not be nil")
	}
}

func TestGetUploadForm_StickerFieldsStructure(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, sticker := range form.Stickers {
		if sticker.Id != i+1 {
			t.Errorf("sticker[%d] ID = %d, want %d", i, sticker.Id, i+1)
		}
		if !strings.Contains(sticker.Key, form.PackId) {
			t.Errorf("sticker[%d] key %q should contain pack ID %q", i, sticker.Key, form.PackId)
		}
		if !strings.Contains(sticker.Location, form.PackId) {
			t.Errorf("sticker[%d] location %q should contain pack ID %q", i, sticker.Location, form.PackId)
		}
		if sticker.Headers == nil {
			t.Errorf("sticker[%d] headers should not be nil", i)
		}
	}
}

func TestGetUploadForm_UniqueStickerKeys(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keys := make(map[string]bool, len(form.Stickers))
	for _, s := range form.Stickers {
		if keys[s.Key] {
			t.Fatalf("duplicate sticker key: %s", s.Key)
		}
		keys[s.Key] = true
	}
}

func TestGetUploadForm_UniquePackIds(t *testing.T) {
	m := NewStickersManager(testLogger())
	form1, err := m.GetUploadForm(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	form2, err := m.GetUploadForm(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if form1.PackId == form2.PackId {
		t.Error("expected unique pack IDs across calls")
	}
}

func TestGetUploadForm_ZeroStickers(t *testing.T) {
	m := NewStickersManager(testLogger())
	_, err := m.GetUploadForm(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error for zero stickers")
	}
	var target *InvalidStickerCountError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidStickerCountError, got %T", err)
	}
	if target.Count != 0 {
		t.Errorf("got count %d, want 0", target.Count)
	}
}

func TestGetUploadForm_NegativeStickers(t *testing.T) {
	m := NewStickersManager(testLogger())
	_, err := m.GetUploadForm(context.Background(), -1)
	if err == nil {
		t.Fatal("expected error for negative stickers")
	}
	var target *InvalidStickerCountError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidStickerCountError, got %T", err)
	}
	if target.Count != -1 {
		t.Errorf("got count %d, want -1", target.Count)
	}
}

func TestGetUploadForm_TooManyStickers(t *testing.T) {
	m := NewStickersManager(testLogger())
	_, err := m.GetUploadForm(context.Background(), 202)
	if err == nil {
		t.Fatal("expected error for 202 stickers")
	}
	var target *InvalidStickerCountError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidStickerCountError, got %T", err)
	}
	if target.Count != 202 {
		t.Errorf("got count %d, want 202", target.Count)
	}
}

func TestGetUploadForm_BoundaryLower(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error at lower boundary: %v", err)
	}
	if len(form.Stickers) != 1 {
		t.Errorf("got %d stickers, want 1", len(form.Stickers))
	}
}

func TestGetUploadForm_BoundaryUpper(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 201)
	if err != nil {
		t.Fatalf("unexpected error at upper boundary: %v", err)
	}
	if len(form.Stickers) != 201 {
		t.Errorf("got %d stickers, want 201", len(form.Stickers))
	}
}

func TestGetUploadForm_LocationPrefix(t *testing.T) {
	m := NewStickersManager(testLogger())
	form, err := m.GetUploadForm(context.Background(), 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(form.Manifest.Location, "/cdn3/") {
		t.Errorf("manifest location %q should start with /cdn3/", form.Manifest.Location)
	}
	if !strings.HasPrefix(form.Stickers[0].Location, "/cdn3/") {
		t.Errorf("sticker location %q should start with /cdn3/", form.Stickers[0].Location)
	}
}
