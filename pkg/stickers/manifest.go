package stickers

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// maxStickersPerPack mirrors the cap signal-cli enforces in
// org/asamk/signal/manager/util/StickerUtils.java and Signal-Android's
// libsignal-service-java MAXIMUM_STICKERS_PER_PACK (200). Packs
// uploaded beyond this size would be rejected by the existing
// /v1/sticker/pack/form/{count} server endpoint anyway — the cap is
// validated here so manifest authors get an actionable error before
// any encryption work happens.
const maxStickersPerPack = 200

// JSONManifest is the on-disk manifest.json shape Signal's sticker
// pack uploaders publish. Mirrors the documented format used by
// Signal-Android and signal-cli's JsonStickerPack.
type JSONManifest struct {
	Title    string        `json:"title"`
	Author   string        `json:"author"`
	Cover    *JSONSticker  `json:"cover,omitempty"`
	Stickers []JSONSticker `json:"stickers"`
}

// JSONSticker is one entry in the manifest's `stickers` array (or the
// `cover` field).
type JSONSticker struct {
	// File is the relative path of the sticker image inside the pack
	// directory or zip. Required.
	File string `json:"file"`
	// Emoji is the suggested emoji shortcut. Optional.
	Emoji string `json:"emoji,omitempty"`
	// ContentType is the MIME type of the sticker file. When empty
	// the uploader sniffs it from the file's content / extension.
	ContentType string `json:"contentType,omitempty"`
}

// LoadedPack is the parsed contents of a sticker pack source — either
// a directory containing manifest.json or a .zip archive of the same.
type LoadedPack struct {
	// Manifest is the deserialized manifest.json.
	Manifest JSONManifest
	// Cover is the bytes of the cover sticker, or nil when Manifest.Cover
	// is nil. Loaded eagerly so the whole upload can run from memory.
	Cover *StickerFile
	// Stickers are the bytes of the sticker images, in the same order
	// as Manifest.Stickers. Stickers[i].ID == i (zero-indexed); Signal
	// clients reference stickers by this ID.
	Stickers []StickerFile
}

// StickerFile bundles the bytes + content type of a single sticker.
type StickerFile struct {
	Bytes       []byte
	ContentType string
	Emoji       string
}

// LoadPack reads manifest.json + every referenced image file from path.
// path may be:
//   - a directory containing manifest.json + sticker images
//   - a .zip archive containing the same layout
//   - a file ending in `manifest.json` (uses the parent directory as root)
//
// Returns *PackInvalidError when the manifest is missing, malformed,
// or references files that aren't present.
func LoadPack(path string) (*LoadedPack, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, &PackInvalidError{Reason: fmt.Sprintf("stat %s: %v", path, err)}
	}

	switch {
	case info.IsDir():
		return loadPackFromDir(path)
	case strings.EqualFold(filepath.Base(path), "manifest.json"):
		return loadPackFromDir(filepath.Dir(path))
	case strings.HasSuffix(strings.ToLower(path), ".zip"):
		return loadPackFromZip(path)
	default:
		return nil, &PackInvalidError{Reason: "path must be a directory, a manifest.json, or a .zip"}
	}
}

func loadPackFromDir(root string) (*LoadedPack, error) {
	manifestPath := filepath.Join(root, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, &PackInvalidError{Reason: fmt.Sprintf("read manifest.json: %v", err)}
	}
	manifest, err := decodeManifest(data)
	if err != nil {
		return nil, err
	}
	open := func(rel string) ([]byte, error) {
		clean, err := safeStickerPath(rel)
		if err != nil {
			return nil, err
		}
		return os.ReadFile(filepath.Join(root, clean))
	}
	return assemblePack(manifest, open)
}

func loadPackFromZip(path string) (*LoadedPack, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, &PackInvalidError{Reason: fmt.Sprintf("open zip: %v", err)}
	}
	defer func() { _ = zr.Close() }()

	files := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		// Reject zip entries whose name escapes the pack root.
		// This is the zip-slip guard: a malicious .zip cannot
		// place an entry at "../etc/passwd" and have us read it
		// later via a manifest.json reference.
		clean, err := safeStickerPath(f.Name)
		if err != nil {
			return nil, &PackInvalidError{Reason: fmt.Sprintf("zip entry %q: %v", f.Name, err)}
		}
		files[clean] = f
	}

	manifestEntry, ok := files["manifest.json"]
	if !ok {
		return nil, &PackInvalidError{Reason: "zip is missing manifest.json"}
	}
	mr, err := manifestEntry.Open()
	if err != nil {
		return nil, &PackInvalidError{Reason: fmt.Sprintf("open manifest.json: %v", err)}
	}
	data, err := io.ReadAll(mr)
	_ = mr.Close()
	if err != nil {
		return nil, &PackInvalidError{Reason: fmt.Sprintf("read manifest.json: %v", err)}
	}
	manifest, err := decodeManifest(data)
	if err != nil {
		return nil, err
	}
	open := func(rel string) ([]byte, error) {
		clean, err := safeStickerPath(rel)
		if err != nil {
			return nil, err
		}
		f, ok := files[clean]
		if !ok {
			return nil, signalerrors.New(signalerrors.ErrNotFound, "entry "+strconv.Quote(rel)+" not in zip")
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = r.Close() }()
		return io.ReadAll(r)
	}
	return assemblePack(manifest, open)
}

// safeStickerPath validates and canonicalises a file path supplied
// by manifest.json or carried as a zip entry name. Rejects:
//   - empty names
//   - absolute paths (POSIX `/foo` or Windows `C:\foo`)
//   - any traversal — `..` segments or non-canonical forms
//   - leading dot-dot after Clean
//
// Returns the cleaned path on success. Callers join it under their
// trusted root (directory mode) or use it as a map key (zip mode).
func safeStickerPath(rel string) (string, error) {
	if rel == "" {
		return "", signalerrors.New(signalerrors.ErrInvalidArgument, "empty path")
	}
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") {
		return "", signalerrors.New(signalerrors.ErrInvalidArgument, "absolute path not allowed: "+strconv.Quote(rel))
	}
	if strings.ContainsRune(rel, 0) {
		return "", signalerrors.New(signalerrors.ErrInvalidArgument, "path contains NUL byte: "+strconv.Quote(rel))
	}
	cleaned := filepath.ToSlash(filepath.Clean(rel))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return "", signalerrors.New(signalerrors.ErrInvalidArgument, "path escapes pack root: "+strconv.Quote(rel))
	}
	return cleaned, nil
}

func decodeManifest(data []byte) (JSONManifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var m JSONManifest
	if err := dec.Decode(&m); err != nil {
		return JSONManifest{}, &PackInvalidError{Reason: fmt.Sprintf("decode manifest: %v", err)}
	}
	return m, nil
}

// assemblePack validates the manifest and loads every referenced file
// via the supplied open function. Centralizes invariants (non-empty
// stickers, file refs present, no duplicate IDs by position) so dir
// and zip sources stay byte-for-byte identical.
func assemblePack(m JSONManifest, open func(string) ([]byte, error)) (*LoadedPack, error) {
	if len(m.Stickers) == 0 {
		return nil, &PackInvalidError{Reason: "manifest.stickers is empty"}
	}
	if len(m.Stickers) > maxStickersPerPack {
		return nil, &PackInvalidError{Reason: fmt.Sprintf("manifest.stickers exceeds %d entries", maxStickersPerPack)}
	}

	loaded := &LoadedPack{Manifest: m}
	loaded.Stickers = make([]StickerFile, len(m.Stickers))
	for i, s := range m.Stickers {
		f, err := loadStickerFile(s, open)
		if err != nil {
			return nil, &PackInvalidError{Reason: fmt.Sprintf("sticker[%d]: %v", i, err)}
		}
		loaded.Stickers[i] = f
	}
	if m.Cover != nil {
		f, err := loadStickerFile(*m.Cover, open)
		if err != nil {
			return nil, &PackInvalidError{Reason: fmt.Sprintf("cover: %v", err)}
		}
		loaded.Cover = &f
	}
	return loaded, nil
}

func loadStickerFile(s JSONSticker, open func(string) ([]byte, error)) (StickerFile, error) {
	if s.File == "" {
		return StickerFile{}, errors.New("missing file")
	}
	data, err := open(s.File)
	if err != nil {
		return StickerFile{}, err
	}
	ct := s.ContentType
	if ct == "" {
		ct = sniffContentType(s.File, data)
	}
	return StickerFile{Bytes: data, ContentType: ct, Emoji: s.Emoji}, nil
}

func sniffContentType(name string, data []byte) string {
	if ext := strings.ToLower(filepath.Ext(name)); ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			return ct
		}
	}
	return http.DetectContentType(data)
}

// PackInvalidError indicates the sticker pack input on disk is
// malformed in a way the operator can fix (missing manifest, bad JSON,
// referenced file absent, empty stickers, etc.).
type PackInvalidError struct {
	Reason string
}

// Error implements the error interface.
func (e *PackInvalidError) Error() string { return "stickers: invalid pack: " + e.Reason }
