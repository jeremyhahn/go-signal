package attachments

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// FileStore is a file-system-based implementation of Store. Each attachment
// is stored as a file under a root directory, with the key determining the
// file path.
type FileStore struct {
	rootDir string
}

// NewFileStore creates a new file-based attachment store. The root directory
// is created if it does not exist.
func NewFileStore(rootDir string) (*FileStore, error) {
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "attachments: create root dir", err)
	}
	return &FileStore{rootDir: rootDir}, nil
}

func (s *FileStore) keyPath(key string) string {
	return filepath.Join(s.rootDir, filepath.FromSlash(key))
}

// Put stores an attachment atomically.
func (s *FileStore) Put(_ context.Context, key string, data io.Reader, _ int64) error {
	path := s.keyPath(key)

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "attachments: mkdir", err)
	}

	// Write to temp file, then rename for atomicity.
	b := make([]byte, 8)
	rand.Read(b)
	tmp := path + ".tmp." + hex.EncodeToString(b)

	f, err := os.Create(tmp)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "attachments: create temp", err)
	}

	if _, err := io.Copy(f, data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return signalerrors.Wrap(signalerrors.ErrInternal, "attachments: write", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return signalerrors.Wrap(signalerrors.ErrInternal, "attachments: sync", err)
	}
	_ = f.Close()

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return signalerrors.Wrap(signalerrors.ErrInternal, "attachments: rename", err)
	}

	return nil
}

// Get retrieves an attachment. The caller must close the returned reader.
func (s *FileStore) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	path := s.keyPath(key)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, signalerrors.New(signalerrors.ErrNotFound, "attachment not found: "+key)
		}
		return nil, 0, signalerrors.Wrap(signalerrors.ErrInternal, "attachments: open", err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, signalerrors.Wrap(signalerrors.ErrInternal, "attachments: stat", err)
	}

	return f, info.Size(), nil
}

// Delete removes an attachment.
func (s *FileStore) Delete(_ context.Context, key string) error {
	path := s.keyPath(key)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "attachments: delete", err)
	}
	return nil
}

// Exists reports whether an attachment exists.
func (s *FileStore) Exists(_ context.Context, key string) (bool, error) {
	_, err := os.Stat(s.keyPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "attachments: stat", err)
	}
	return true, nil
}
