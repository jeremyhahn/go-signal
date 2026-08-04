// Package blob provides [backups.BlobStore] implementations.
//
// The current implementation is a single-root local-filesystem store,
// intended for development and integration tests. Production deployments
// substitute an S3 / GCS / Azure adapter constructed alongside the rest
// of the storage layer in cmd/signald/start.go.
package blob

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-signal/pkg/backups"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// FilesystemStore is a [backups.BlobStore] backed by a single local
// directory tree. All objects live as files under root; keys are
// path-segmented (slashes preserved). Listing is in-memory and bounded
// by the configurable Limit on individual calls.
//
// Suitable for unit tests and single-node dev/self-host deployments where
// "the CDN" is just a directory on disk. Not safe across machine
// boundaries.
type FilesystemStore struct {
	root      string
	cdnNumber int
}

// FilesystemOptions configures a [FilesystemStore].
type FilesystemOptions struct {
	// Root is the directory all blobs are stored under. Created if missing.
	Root string
	// CDNNumber identifies which logical CDN this store represents.
	// Defaults to 3 (the conventional backup-CDN number on Signal).
	CDNNumber int
}

// NewFilesystemStore opens (creating if necessary) a filesystem blob store
// rooted at opts.Root.
func NewFilesystemStore(opts FilesystemOptions) (*FilesystemStore, error) {
	if opts.Root == "" {
		return nil, errors.New("blob filesystem: root is required")
	}
	cdn := opts.CDNNumber
	if cdn == 0 {
		cdn = 3
	}
	if err := os.MkdirAll(opts.Root, 0o750); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: mkdir root", err)
	}
	return &FilesystemStore{root: opts.Root, cdnNumber: cdn}, nil
}

// CDNNumber implements [backups.BlobStore].
func (s *FilesystemStore) CDNNumber() int { return s.cdnNumber }

// pathFor maps a key to an absolute path beneath root. Rejects key segments
// that try to escape root via "..".
func (s *FilesystemStore) pathFor(key string) (string, error) {
	if strings.Contains(key, "..") {
		return "", &backups.InvalidArgumentError{Field: "key", Message: "path-traversal not allowed"}
	}
	return filepath.Join(s.root, key), nil
}

// GenerateUpload implements [backups.BlobStore]. The "upload form" for
// filesystem-backed blobs is a file:// URL the client (i.e. a test) can
// open and write to directly. Real CDNs return a signed PUT URL; the
// shape of the response is identical.
func (s *FilesystemStore) GenerateUpload(_ context.Context, key string) (*backups.UploadDescriptor, error) {
	full, err := s.pathFor(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: mkdir parent", err)
	}
	return &backups.UploadDescriptor{
		CDN:                  s.cdnNumber,
		Key:                  key,
		Headers:              map[string]string{},
		SignedUploadLocation: "file://" + full,
	}, nil
}

// ReadHeaders implements [backups.BlobStore]. Filesystem reads need no
// auth headers; returns an empty map so callers can write to it without
// nil checks.
func (s *FilesystemStore) ReadHeaders(_ context.Context, _ string) (map[string]string, error) {
	return map[string]string{}, nil
}

// Copy implements [backups.BlobStore]. Reads the source object, AES-256-CBC
// encrypts under params.EncryptionKey with a fresh random IV, computes an
// HMAC-SHA256 tag with params.MACKey over (IV || ciphertext), then writes
// IV || ciphertext || tag to destPath. Returns [*SourceNotFoundError] if
// the source is missing and [*InvalidLengthError] if the read returns a
// length different from sourceLength.
func (s *FilesystemStore) Copy(
	_ context.Context,
	_ int, // sourceCDN: ignored — filesystem store treats all CDNs as the same root
	sourceKey string,
	sourceLength int,
	params backups.MediaEncryptionParameters,
	destPath string,
) error {
	sourceAbs, err := s.pathFor(sourceKey)
	if err != nil {
		return err
	}
	plaintext, err := os.ReadFile(sourceAbs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &backups.SourceNotFoundError{SourceKey: sourceKey}
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: read source", err)
	}
	if len(plaintext) != sourceLength {
		return &backups.InvalidLengthError{SourceKey: sourceKey, Expected: sourceLength, Actual: int64(len(plaintext))}
	}

	encrypted, err := encryptAESCBCHMAC(plaintext, params.EncryptionKey, params.MACKey)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: encrypt", err)
	}

	destAbs, err := s.pathFor(destPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destAbs), 0o750); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: mkdir dest parent", err)
	}
	if err := os.WriteFile(destAbs, encrypted, 0o600); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: write dest", err)
	}
	return nil
}

// Delete implements [backups.BlobStore]. Returns the byte length that was
// freed. Missing files return (0, nil) — deletion is idempotent.
func (s *FilesystemStore) Delete(_ context.Context, path string) (int64, error) {
	abs, err := s.pathFor(path)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: stat", err)
	}
	if err := os.Remove(abs); err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: remove", err)
	}
	return info.Size(), nil
}

// List implements [backups.BlobStore]. Walks the prefix directory,
// returning at most limit entries (defaulting to 1000 when zero/negative).
// Cursor is the key of the last entry returned by a previous call; nil
// starts from the beginning.
func (s *FilesystemStore) List(_ context.Context, prefix string, cursor *string, limit int) (*backups.BlobListResult, error) {
	if limit <= 0 {
		limit = 1000
	}
	root, err := s.pathFor(prefix)
	if err != nil {
		return nil, err
	}
	all, err := s.listSorted(root, prefix)
	if err != nil {
		return nil, err
	}
	start := 0
	if cursor != nil {
		start = sort.Search(len(all), func(i int) bool { return all[i].Key > *cursor })
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	out := &backups.BlobListResult{Objects: all[start:end]}
	if end < len(all) {
		last := all[end-1].Key
		out.Cursor = &last
	}
	return out, nil
}

// CalculateBytesUsed implements [backups.BlobStore]. Walks the prefix and
// returns the aggregate byte + object counts.
func (s *FilesystemStore) CalculateBytesUsed(_ context.Context, prefix string) (backups.UsageInfo, error) {
	root, err := s.pathFor(prefix)
	if err != nil {
		return backups.UsageInfo{}, err
	}
	var totalBytes, totalObjects int64
	err = filepath.Walk(root, func(_ string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		totalBytes += info.Size()
		totalObjects++
		return nil
	})
	if err != nil {
		return backups.UsageInfo{}, signalerrors.Wrap(signalerrors.ErrInternal, "blob filesystem: calculate bytes used", err)
	}
	return backups.UsageInfo{BytesUsed: totalBytes, NumObjects: totalObjects}, nil
}

// listSorted walks root and returns every regular file as a BlobListEntry
// (key = path relative to root, with prefix re-attached so callers see the
// same key shape they used to write). Sorted lexicographically so cursor
// pagination is stable.
func (s *FilesystemStore) listSorted(root, prefix string) ([]backups.BlobListEntry, error) {
	var entries []backups.BlobListEntry
	err := filepath.Walk(root, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		entries = append(entries, backups.BlobListEntry{
			Key:    filepath.ToSlash(rel),
			Length: info.Size(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, nil
}

// encryptAESCBCHMAC produces the Signal media-encryption wire format used
// when copying source attachments into a backup: 16-byte random IV +
// AES-256-CBC ciphertext (PKCS#7 padded) + 32-byte HMAC-SHA256 over
// (IV || ciphertext). Mirrors Java MediaEncryptionParameters consumer logic.
func encryptAESCBCHMAC(plaintext, encryptionKey, macKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(padded))
	mode.CryptBlocks(ct, padded)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)
	mac.Write(ct)
	tag := mac.Sum(nil)

	out := make([]byte, 0, len(iv)+len(ct)+len(tag))
	out = append(out, iv...)
	out = append(out, ct...)
	out = append(out, tag...)
	return out, nil
}

// pkcs7Pad appends PKCS#7 padding so the output length is a multiple of
// blockSize. Always adds at least one byte of padding (so a 0-byte input
// gets blockSize bytes of 0x10 padding for AES-128, etc.).
func pkcs7Pad(in []byte, blockSize int) []byte {
	padLen := blockSize - (len(in) % blockSize)
	out := make([]byte, len(in)+padLen)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}
