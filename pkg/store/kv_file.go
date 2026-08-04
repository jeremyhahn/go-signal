package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// FileKVClient is a thread-safe file-based implementation of KVClient.
// Keys map to file paths under a root directory. Values are stored as raw
// bytes. Writes are atomic (temp + fsync + rename).
type FileKVClient struct {
	mu      sync.RWMutex
	rootDir string
}

// NewFileKVClient returns a new file-based KVClient rooted at the given
// directory. The directory is created if it does not exist.
func NewFileKVClient(rootDir string) (*FileKVClient, error) {
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: create root dir", err)
	}
	return &FileKVClient{rootDir: rootDir}, nil
}

func (f *FileKVClient) keyPath(key string) string {
	// Replace forward slashes in keys with OS path separator for nesting.
	return filepath.Join(f.rootDir, filepath.FromSlash(key))
}

// Put stores a value at the given key atomically.
func (f *FileKVClient) Put(_ context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyPath(key)

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: mkdir", err)
	}

	// Atomic write: temp file → fsync → rename.
	tmp := path + ".tmp." + randSuffix()
	if err := os.WriteFile(tmp, value, 0600); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: write temp", err)
	}

	// fsync the temp file for durability.
	tf, err := os.Open(tmp)
	if err == nil {
		_ = tf.Sync()
		_ = tf.Close()
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: rename", err)
	}

	return nil
}

// Get retrieves the value stored at the given key.
func (f *FileKVClient) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	data, err := os.ReadFile(f.keyPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &KeyNotFoundError{Key: key}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: read", err)
	}
	return data, nil
}

// Delete removes the value stored at the given key.
func (f *FileKVClient) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyPath(key)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return &KeyNotFoundError{Key: key}
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: delete", err)
	}

	// Clean up empty parent directories up to rootDir.
	dir := filepath.Dir(path)
	for dir != f.rootDir && dir != "." {
		if err := os.Remove(dir); err != nil {
			break // Not empty or other error — stop.
		}
		dir = filepath.Dir(dir)
	}

	return nil
}

// DeleteIfPresent atomically removes key and reports whether this call removed
// it. The os.Remove (which fails with ErrNotExist when the key is absent) runs
// under the write lock, so concurrent callers see exactly one true.
func (f *FileKVClient) DeleteIfPresent(_ context.Context, key string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyPath(key)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: delete", err)
	}

	// Clean up empty parent directories up to rootDir.
	dir := filepath.Dir(path)
	for dir != f.rootDir && dir != "." {
		if err := os.Remove(dir); err != nil {
			break // Not empty or other error — stop.
		}
		dir = filepath.Dir(dir)
	}

	return true, nil
}

// List returns all keys that share the given prefix, sorted lexicographically.
func (f *FileKVClient) List(_ context.Context, prefix string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var keys []string
	searchDir := f.rootDir

	err := filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible entries.
		}
		if info.IsDir() {
			return nil
		}
		// Skip temp files from incomplete writes.
		if strings.Contains(filepath.Base(path), ".tmp.") {
			return nil
		}

		rel, err := filepath.Rel(f.rootDir, path)
		if err != nil {
			return nil
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: list", err)
	}

	sort.Strings(keys)
	return keys, nil
}

// Scan iterates over all key-value pairs whose keys share the given prefix in
// sorted order, invoking fn for each pair.
func (f *FileKVClient) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	keys, err := f.List(ctx, prefix)
	if err != nil {
		return err
	}

	for _, key := range keys {
		data, err := f.Get(ctx, key)
		if err != nil {
			// Key may have been deleted between List and Get; skip it.
			// Other errors (permission, IO) are real and propagate.
			var knf *KeyNotFoundError
			if errors.As(err, &knf) {
				continue
			}
			return err
		}
		if err := fn(key, data); err != nil {
			return err
		}
	}
	return nil
}

// Exists reports whether a value is stored at the given key.
func (f *FileKVClient) Exists(_ context.Context, key string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	_, err := os.Stat(f.keyPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "kv_file: stat", err)
	}
	return true, nil
}

func randSuffix() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
