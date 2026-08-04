package stickers

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

const happyManifest = `{
  "title": "Test Pack",
  "author": "Tester",
  "cover": {"file": "cover.png", "emoji": "🎉"},
  "stickers": [
    {"file": "s1.png", "emoji": "😀", "contentType": "image/png"},
    {"file": "s2.png", "emoji": "😂"}
  ]
}`

func writeTempPack(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(happyManifest), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	for _, name := range []string{"cover.png", "s1.png", "s2.png"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("png-"+name), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestLoadPack_DirectoryHappyPath(t *testing.T) {
	dir := writeTempPack(t)
	p, err := LoadPack(dir)
	if err != nil {
		t.Fatalf("LoadPack: %v", err)
	}
	if p.Manifest.Title != "Test Pack" || p.Manifest.Author != "Tester" {
		t.Errorf("manifest fields drifted: %+v", p.Manifest)
	}
	if p.Cover == nil || string(p.Cover.Bytes) != "png-cover.png" {
		t.Errorf("cover not loaded: %+v", p.Cover)
	}
	if len(p.Stickers) != 2 {
		t.Fatalf("got %d stickers, want 2", len(p.Stickers))
	}
	if string(p.Stickers[0].Bytes) != "png-s1.png" {
		t.Errorf("sticker[0] bytes drift")
	}
	// Explicit contentType honored
	if p.Stickers[0].ContentType != "image/png" {
		t.Errorf("explicit contentType lost: %q", p.Stickers[0].ContentType)
	}
	// Sniffed contentType present
	if p.Stickers[1].ContentType == "" {
		t.Errorf("missing sniffed contentType")
	}
}

func TestLoadPack_ManifestJSONPath(t *testing.T) {
	dir := writeTempPack(t)
	p, err := LoadPack(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("LoadPack(manifest.json): %v", err)
	}
	if p.Manifest.Title != "Test Pack" {
		t.Errorf("title drift")
	}
}

func TestLoadPack_ZipPath(t *testing.T) {
	dir := writeTempPack(t)
	zipPath := filepath.Join(t.TempDir(), "pack.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(f)
	for _, name := range []string{"manifest.json", "cover.png", "s1.png", "s2.png"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		data, _ := os.ReadFile(filepath.Join(dir, name))
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	_ = zw.Close()
	_ = f.Close()

	p, err := LoadPack(zipPath)
	if err != nil {
		t.Fatalf("LoadPack zip: %v", err)
	}
	if len(p.Stickers) != 2 || p.Cover == nil {
		t.Errorf("zip pack incomplete: %+v", p)
	}
}

func TestLoadPack_MissingManifest_Rejected(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadPack(dir)
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestLoadPack_MalformedManifest_Rejected(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{not json"), 0644)
	_, err := LoadPack(dir)
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestLoadPack_MissingStickerFile_Rejected(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{
		"title": "x", "author": "y",
		"stickers": [{"file": "missing.png"}]
	}`), 0644)
	_, err := LoadPack(dir)
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestLoadPack_EmptyStickers_Rejected(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{
		"title": "x", "author": "y", "stickers": []
	}`), 0644)
	_, err := LoadPack(dir)
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestLoadPack_NonsensePath_Rejected(t *testing.T) {
	_, err := LoadPack("/no/such/path")
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestEncodePackManifest_Shape(t *testing.T) {
	p := &LoadedPack{
		Manifest: JSONManifest{Title: "hi", Author: "me"},
		Stickers: []StickerFile{
			{Bytes: []byte("a"), Emoji: "😀", ContentType: "image/png"},
		},
	}
	wire := EncodePackManifest(p)
	if len(wire) == 0 {
		t.Fatal("encoded manifest is empty")
	}

	// Walk the wire and confirm field numbers / order.
	seen := map[int]int{} // field num → count
	rest := wire
	for len(rest) > 0 {
		num, _, n := protowire.ConsumeField(rest)
		if n < 0 {
			t.Fatalf("parse error: %v", protowire.ParseError(n))
		}
		seen[int(num)]++
		rest = rest[n:]
	}
	if seen[1] != 1 || seen[2] != 1 || seen[4] != 1 {
		t.Errorf("field counts wrong: %+v", seen)
	}
	if seen[3] != 0 {
		t.Errorf("cover encoded despite nil: %+v", seen)
	}
}

func TestEncodePackManifest_StickerIDs(t *testing.T) {
	p := &LoadedPack{
		Manifest: JSONManifest{Title: "t"},
		Stickers: []StickerFile{
			{Bytes: []byte("a"), Emoji: "1"},
			{Bytes: []byte("b"), Emoji: "2"},
			{Bytes: []byte("c"), Emoji: "3"},
		},
	}
	wire := EncodePackManifest(p)

	// Pull out each sticker submessage by looking for field 4.
	var subs [][]byte
	rest := wire
	for len(rest) > 0 {
		num, _, n := protowire.ConsumeField(rest)
		if n < 0 {
			t.Fatalf("parse: %v", protowire.ParseError(n))
		}
		if num == 4 {
			val, vn := protowire.ConsumeBytes(rest[protowire.SizeTag(4):])
			if vn < 0 {
				t.Fatalf("submsg parse: %v", protowire.ParseError(vn))
			}
			subs = append(subs, val)
		}
		rest = rest[n:]
	}
	if len(subs) != 3 {
		t.Fatalf("got %d sticker submessages, want 3", len(subs))
	}
	wantIDs := []uint32{0, 1, 2}
	for i, sub := range subs {
		// Field 1 is the uint32 ID.
		num, _, _ := protowire.ConsumeTag(sub)
		if num != 1 {
			t.Errorf("sub[%d] first field = %d, want 1", i, num)
			continue
		}
		v, _ := protowire.ConsumeVarint(sub[protowire.SizeTag(1):])
		if uint32(v) != wantIDs[i] {
			t.Errorf("sub[%d] id = %d, want %d", i, v, wantIDs[i])
		}
	}
}

func TestLoadPack_ZipSlip_AbsolutePath_Rejected(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "pack.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	zw := zip.NewWriter(f)
	// Absolute-path entry. Should be rejected by safeStickerPath.
	w, _ := zw.Create("/etc/passwd")
	_, _ = w.Write([]byte("root:x:0:0::/root:/bin/sh"))
	_ = zw.Close()
	_ = f.Close()
	_, err = LoadPack(zipPath)
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestLoadPack_ZipSlip_ParentTraversal_Rejected(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "pack.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../../etc/shadow")
	_, _ = w.Write([]byte("shadow"))
	_ = zw.Close()
	_ = f.Close()
	_, err := LoadPack(zipPath)
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestLoadPack_ZipSlip_EmbeddedDotDot_Rejected(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "pack.zip")
	f, _ := os.Create(zipPath)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("a/../../b")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	_ = f.Close()
	_, err := LoadPack(zipPath)
	var inv *PackInvalidError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackInvalidError, got %v", err)
	}
}

func TestSafeStickerPath_AcceptsRelative(t *testing.T) {
	cases := []string{"sticker.png", "subdir/sticker.png", "./manifest.json"}
	for _, c := range cases {
		got, err := safeStickerPath(c)
		if err != nil {
			t.Errorf("safeStickerPath(%q): %v", c, err)
		}
		if got == "" {
			t.Errorf("empty cleaned path for %q", c)
		}
	}
}

func TestSafeStickerPath_Rejects(t *testing.T) {
	for _, c := range []string{"", "/abs", "../up", "a/../../b", "x\x00.png"} {
		if _, err := safeStickerPath(c); err == nil {
			t.Errorf("safeStickerPath(%q) accepted; want error", c)
		}
	}
}

func TestPackInvalidError_ErrorMethod(t *testing.T) {
	e := &PackInvalidError{Reason: "missing cover"}
	got := e.Error()
	if got != "stickers: invalid pack: missing cover" {
		t.Errorf("Error() = %q", got)
	}
}

func TestEncodePackManifest_EncryptDecryptRoundTrip(t *testing.T) {
	p := &LoadedPack{
		Manifest: JSONManifest{Title: "hi", Author: "me"},
		Stickers: []StickerFile{{Bytes: []byte("png"), Emoji: "🚀", ContentType: "image/png"}},
	}
	wire := EncodePackManifest(p)
	key, _ := NewPackKey()
	env, _ := EncryptPackPayload(key, wire)
	out, err := DecryptPackPayload(key, env)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(out, wire) {
		t.Error("manifest envelope round-trip lost data")
	}
}
