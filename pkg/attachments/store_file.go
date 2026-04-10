package attachments

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
		return nil, fmt.Errorf("attachments: create root dir: %w", err)
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
		return fmt.Errorf("attachments: mkdir: %w", err)
	}

	// Write to temp file, then rename for atomicity.
	b := make([]byte, 8)
	rand.Read(b)
	tmp := path + ".tmp." + hex.EncodeToString(b)

	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("attachments: create temp: %w", err)
	}

	if _, err := io.Copy(f, data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("attachments: write: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("attachments: sync: %w", err)
	}
	f.Close()

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("attachments: rename: %w", err)
	}

	return nil
}

// Get retrieves an attachment. The caller must close the returned reader.
func (s *FileStore) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	path := s.keyPath(key)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, fmt.Errorf("attachment not found: %s", key)
		}
		return nil, 0, fmt.Errorf("attachments: open: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("attachments: stat: %w", err)
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
		return fmt.Errorf("attachments: delete: %w", err)
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
		return false, fmt.Errorf("attachments: stat: %w", err)
	}
	return true, nil
}
