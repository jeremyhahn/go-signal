package stickers

import (
	"testing"
)

func TestStickerPackFormUpload_ZeroValue(t *testing.T) {
	var form StickerPackFormUpload
	if form.PackId != "" {
		t.Errorf("expected empty pack ID, got %q", form.PackId)
	}
	if form.Stickers != nil {
		t.Errorf("expected nil stickers, got %v", form.Stickers)
	}
}

func TestStickerPackFormUpload_Fields(t *testing.T) {
	form := StickerPackFormUpload{
		PackId: "pack-1",
		Manifest: StickerFormField{
			Id:  0,
			Key: "manifest-key",
		},
		Stickers: []StickerFormField{
			{Id: 1, Key: "s1"},
			{Id: 2, Key: "s2"},
		},
	}
	if form.PackId != "pack-1" {
		t.Errorf("got %q, want %q", form.PackId, "pack-1")
	}
	if form.Manifest.Key != "manifest-key" {
		t.Errorf("got %q, want %q", form.Manifest.Key, "manifest-key")
	}
	if len(form.Stickers) != 2 {
		t.Errorf("got %d stickers, want 2", len(form.Stickers))
	}
}

func TestStickerFormField_ZeroValue(t *testing.T) {
	var field StickerFormField
	if field.Id != 0 {
		t.Errorf("expected 0, got %d", field.Id)
	}
	if field.Key != "" {
		t.Errorf("expected empty key, got %q", field.Key)
	}
	if field.Headers != nil {
		t.Errorf("expected nil headers, got %v", field.Headers)
	}
	if field.Location != "" {
		t.Errorf("expected empty location, got %q", field.Location)
	}
}

func TestStickerFormField_AllFields(t *testing.T) {
	field := StickerFormField{
		Id:       42,
		Key:      "stickers/pack/abc",
		Headers:  map[string]string{"Content-Type": "image/webp"},
		Location: "/cdn3/stickers/pack/abc",
	}
	if field.Id != 42 {
		t.Errorf("got ID %d, want 42", field.Id)
	}
	if field.Key != "stickers/pack/abc" {
		t.Errorf("got key %q", field.Key)
	}
	if field.Headers["Content-Type"] != "image/webp" {
		t.Errorf("got header %q", field.Headers["Content-Type"])
	}
	if field.Location != "/cdn3/stickers/pack/abc" {
		t.Errorf("got location %q", field.Location)
	}
}
