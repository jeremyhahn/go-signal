package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestFileKV creates a FileKVClient rooted in a temporary directory that is
// cleaned up when the test completes.
func newTestFileKV(t *testing.T) *FileKVClient {
	t.Helper()
	dir := t.TempDir()
	kv, err := NewFileKVClient(dir)
	require.NoError(t, err)
	require.NotNil(t, kv)
	return kv
}

// --- Constructor ---

func TestNewFileKVClient_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "subdir")
	kv, err := NewFileKVClient(dir)
	require.NoError(t, err)
	require.NotNil(t, kv)
	info, statErr := os.Stat(dir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

func TestNewFileKVClient_ExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	kv, err := NewFileKVClient(dir)
	require.NoError(t, err)
	require.NotNil(t, kv)
}

func TestNewFileKVClient_ImplementsKVClient(t *testing.T) {
	var _ KVClient = &FileKVClient{}
}

// --- Put ---

func TestFileKV_Put_StoresAndRetrieves(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "key1", []byte("hello")))

	got, err := kv.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)
}

func TestFileKV_Put_Overwrites(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("first")))
	require.NoError(t, kv.Put(ctx, "k", []byte("second")))

	got, err := kv.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("second"), got)
}

func TestFileKV_Put_EmptyValue(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "empty", []byte{}))

	got, err := kv.Get(ctx, "empty")
	require.NoError(t, err)
	assert.Equal(t, []byte{}, got)
}

func TestFileKV_Put_NestedKey(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "accounts/uuid1/profile", []byte("data")))

	got, err := kv.Get(ctx, "accounts/uuid1/profile")
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)
}

func TestFileKV_Put_MultipleKeys(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	pairs := map[string][]byte{
		"a":   []byte("1"),
		"b":   []byte("2"),
		"c/d": []byte("3"),
	}
	for k, v := range pairs {
		require.NoError(t, kv.Put(ctx, k, v))
	}
	for k, v := range pairs {
		got, err := kv.Get(ctx, k)
		require.NoError(t, err)
		assert.Equal(t, v, got, "key=%s", k)
	}
}

// --- Get ---

func TestFileKV_Get_NotFound(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	_, err := kv.Get(ctx, "missing")
	require.Error(t, err)

	var knf *KeyNotFoundError
	require.True(t, errors.As(err, &knf))
	assert.Equal(t, "missing", knf.Key)
}

func TestFileKV_Get_NestedNotFound(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	_, err := kv.Get(ctx, "ns/missing")
	require.Error(t, err)

	var knf *KeyNotFoundError
	require.True(t, errors.As(err, &knf))
}

// --- Delete ---

func TestFileKV_Delete_RemovesKey(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "del", []byte("v")))
	require.NoError(t, kv.Delete(ctx, "del"))

	_, err := kv.Get(ctx, "del")
	var knf *KeyNotFoundError
	require.True(t, errors.As(err, &knf))
}

func TestFileKV_Delete_NotFound(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	err := kv.Delete(ctx, "nonexistent")
	require.Error(t, err)

	var knf *KeyNotFoundError
	require.True(t, errors.As(err, &knf))
	assert.Equal(t, "nonexistent", knf.Key)
}

func TestFileKV_Delete_CleansUpEmptyParentDirs(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	// Create a key nested two levels deep with no siblings.
	require.NoError(t, kv.Put(ctx, "ns/sub/key", []byte("v")))
	require.NoError(t, kv.Delete(ctx, "ns/sub/key"))

	// The intermediate directories should have been removed.
	_, err := os.Stat(filepath.Join(kv.rootDir, "ns", "sub"))
	assert.True(t, os.IsNotExist(err), "expected ns/sub to be removed")
}

func TestFileKV_Delete_DoesNotRemoveDirWithSiblings(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "ns/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "ns/b", []byte("2")))
	require.NoError(t, kv.Delete(ctx, "ns/a"))

	// ns still has ns/b so it should remain.
	info, err := os.Stat(filepath.Join(kv.rootDir, "ns"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	got, err := kv.Get(ctx, "ns/b")
	require.NoError(t, err)
	assert.Equal(t, []byte("2"), got)
}

// --- List ---

func TestFileKV_List_WithPrefix(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "prefix/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "prefix/b", []byte("2")))
	require.NoError(t, kv.Put(ctx, "other/c", []byte("3")))

	keys, err := kv.List(ctx, "prefix/")
	require.NoError(t, err)
	assert.Equal(t, []string{"prefix/a", "prefix/b"}, keys)
}

func TestFileKV_List_EmptyPrefix(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "b", []byte("2")))

	keys, err := kv.List(ctx, "")
	require.NoError(t, err)
	sort.Strings(keys)
	assert.Equal(t, []string{"a", "b"}, keys)
}

func TestFileKV_List_NoMatches(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "a", []byte("1")))

	keys, err := kv.List(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestFileKV_List_ReturnsSorted(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "c", []byte("3")))
	require.NoError(t, kv.Put(ctx, "a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "b", []byte("2")))

	keys, err := kv.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, keys)
}

func TestFileKV_List_EmptyStore(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	keys, err := kv.List(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestFileKV_List_SkipsTempFiles(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	// Plant a fake temp file directly in the root directory.
	tmpPath := filepath.Join(kv.rootDir, "ghost.tmp.aabbccdd")
	require.NoError(t, os.WriteFile(tmpPath, []byte("noise"), 0600))

	require.NoError(t, kv.Put(ctx, "real", []byte("v")))

	keys, err := kv.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"real"}, keys)
}

// --- Scan ---

func TestFileKV_Scan_AllPrefixed(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "ns/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "ns/b", []byte("2")))
	require.NoError(t, kv.Put(ctx, "other/c", []byte("3")))

	var collected []string
	err := kv.Scan(ctx, "ns/", func(key string, value []byte) error {
		collected = append(collected, key+"="+string(value))
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"ns/a=1", "ns/b=2"}, collected)
}

func TestFileKV_Scan_StopsOnError(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "ns/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "ns/b", []byte("2")))

	sentinel := errors.New("stop")
	count := 0
	err := kv.Scan(ctx, "ns/", func(key string, value []byte) error {
		count++
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, count)
}

func TestFileKV_Scan_EmptyPrefix(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "x", []byte("1")))

	var keys []string
	err := kv.Scan(ctx, "", func(key string, _ []byte) error {
		keys = append(keys, key)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, keys)
}

func TestFileKV_Scan_NoMatches(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "a", []byte("1")))

	called := false
	err := kv.Scan(ctx, "none/", func(key string, _ []byte) error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.False(t, called)
}

// TestFileKV_Scan_KeyDeletedBetweenListAndGet exercises the TOCTOU path in
// Scan where a key disappears after List but before Get. The implementation
// continues past a KeyNotFoundError, so the scan should succeed with the
// remaining keys.
func TestFileKV_Scan_KeyDeletedBetweenListAndGet(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "ns/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "ns/b", []byte("2")))

	// Remove "ns/a" from disk directly so List sees it but Get returns KeyNotFoundError.
	require.NoError(t, os.Remove(filepath.Join(kv.rootDir, "ns", "a")))

	var collected []string
	err := kv.Scan(ctx, "ns/", func(key string, value []byte) error {
		collected = append(collected, key)
		return nil
	})
	require.NoError(t, err)
	// Only ns/b should be returned; ns/a was silently skipped.
	assert.Equal(t, []string{"ns/b"}, collected)
}

// --- Exists ---

func TestFileKV_Exists_Present(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("v")))

	exists, err := kv.Exists(ctx, "k")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestFileKV_Exists_Absent(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	exists, err := kv.Exists(ctx, "missing")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestFileKV_Exists_AfterDelete(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("v")))
	require.NoError(t, kv.Delete(ctx, "k"))

	exists, err := kv.Exists(ctx, "k")
	require.NoError(t, err)
	assert.False(t, exists)
}

// --- Concurrency ---

func TestFileKV_ConcurrentAccess(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	const goroutines = 20
	const iterations = 30

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			key := "key-" + string(rune('A'+id%26))
			for range iterations {
				_ = kv.Put(ctx, key, []byte("val"))
				_, _ = kv.Get(ctx, key)
				_, _ = kv.List(ctx, "key-")
				_, _ = kv.Exists(ctx, key)
			}
		}(g)
	}

	wg.Wait()
}

func TestFileKV_ConcurrentPutDelete(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for g := range goroutines {
		key := "ck-" + string(rune('A'+g%26))
		go func() {
			defer wg.Done()
			for range 20 {
				_ = kv.Put(ctx, key, []byte("v"))
			}
		}()
		go func() {
			defer wg.Done()
			for range 20 {
				_ = kv.Delete(ctx, key)
			}
		}()
	}

	wg.Wait()
}

// --- keyPath helper ---

func TestFileKV_keyPath_SlashSeparated(t *testing.T) {
	dir := t.TempDir()
	kv := &FileKVClient{rootDir: dir}
	got := kv.keyPath("accounts/uuid1/profile")
	expected := filepath.Join(dir, "accounts", "uuid1", "profile")
	assert.Equal(t, expected, got)
}

func TestFileKV_keyPath_FlatKey(t *testing.T) {
	dir := t.TempDir()
	kv := &FileKVClient{rootDir: dir}
	got := kv.keyPath("flatkey")
	assert.Equal(t, filepath.Join(dir, "flatkey"), got)
}

// --- Error paths that require filesystem manipulation ---

// blockPath plants a regular file at rootDir/name and returns a key beneath it.
// Using that key makes the filesystem answer ENOTDIR for every syscall that has
// to walk through it — a fault that holds for every uid, unlike the permission
// bits these tests used to rely on, which root bypasses
// (testing-guidelines.md §Fault Injection).
func blockPath(t *testing.T, rootDir, name string) string {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, name), []byte("regular file"), 0600))
	return name + "/child"
}

// TestNewFileKVClient_MkdirAllFails exercises the NewFileKVClient error return
// when the root cannot be created because a path component is a regular file.
func TestNewFileKVClient_MkdirAllFails(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "notadir")
	require.NoError(t, os.WriteFile(blocker, []byte("regular file"), 0600))

	_, err := NewFileKVClient(filepath.Join(blocker, "cannot-create"))
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOTDIR)
}

// TestFileKV_Put_MkdirFails exercises the mkdir error branch in Put: the key's
// parent directory cannot be created because that path component is a file.
func TestFileKV_Put_MkdirFails(t *testing.T) {
	kv := newTestFileKV(t)
	key := blockPath(t, kv.rootDir, "notadir")

	err := kv.Put(context.Background(), key, []byte("v"))
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOTDIR)
	require.Contains(t, err.Error(), "kv_file: mkdir")
}

// TestFileKV_Put_WriteFileFails exercises the write-temp error branch in Put.
// The fault must spare the MkdirAll that runs first, so it targets the temp
// file alone: Put appends ".tmp.<16 hex>" to the key path, which pushes a
// final component near NAME_MAX past the 255-byte limit and fails the write
// with ENAMETOOLONG for every uid.
func TestFileKV_Put_WriteFileFails(t *testing.T) {
	kv := newTestFileKV(t)

	err := kv.Put(context.Background(), "sub/"+strings.Repeat("n", 250), []byte("v"))
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENAMETOOLONG)
	require.Contains(t, err.Error(), "kv_file: write temp")
}

// TestFileKV_Exists_StatError exercises the non-IsNotExist error branch in
// Exists: stat through a regular file returns ENOTDIR, not ENOENT.
func TestFileKV_Exists_StatError(t *testing.T) {
	kv := newTestFileKV(t)
	key := blockPath(t, kv.rootDir, "notadir")

	_, err := kv.Exists(context.Background(), key)
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOTDIR)
}

// TestFileKV_Get_ReadError exercises the non-IsNotExist error branch in Get:
// reading through a regular file returns ENOTDIR, so Get must report a real
// error rather than "key not found".
func TestFileKV_Get_ReadError(t *testing.T) {
	kv := newTestFileKV(t)
	key := blockPath(t, kv.rootDir, "notadir")

	_, err := kv.Get(context.Background(), key)
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOTDIR)

	var knf *KeyNotFoundError
	require.False(t, errors.As(err, &knf), "ENOTDIR must not be reported as key-not-found")
}

// TestFileKV_Delete_RemoveError exercises the non-IsNotExist error branch in
// Delete: removing through a regular file returns ENOTDIR, which Delete must
// propagate instead of treating the key as already absent.
func TestFileKV_Delete_RemoveError(t *testing.T) {
	kv := newTestFileKV(t)
	key := blockPath(t, kv.rootDir, "notadir")

	err := kv.Delete(context.Background(), key)
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ENOTDIR)
}

// --- randSuffix ---

func TestRandSuffix_Length(t *testing.T) {
	s := randSuffix()
	// 8 bytes → 16 hex characters.
	assert.Len(t, s, 16)
}

func TestRandSuffix_Unique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for range 100 {
		s := randSuffix()
		assert.False(t, seen[s], "duplicate suffix: %s", s)
		seen[s] = true
	}
}

// --- DeleteIfPresent ---

func TestFileKV_DeleteIfPresent_Exists(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("v")))

	deleted, err := kv.DeleteIfPresent(ctx, "k")
	require.NoError(t, err)
	assert.True(t, deleted)

	_, err = kv.Get(ctx, "k")
	var knf *KeyNotFoundError
	require.True(t, errors.As(err, &knf))
}

func TestFileKV_DeleteIfPresent_Absent(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	deleted, err := kv.DeleteIfPresent(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, deleted)
}

func TestFileKV_DeleteIfPresent_CleanupEmptyParents(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "ns/sub/key", []byte("v")))

	deleted, err := kv.DeleteIfPresent(ctx, "ns/sub/key")
	require.NoError(t, err)
	assert.True(t, deleted)

	_, statErr := os.Stat(filepath.Join(kv.rootDir, "ns", "sub"))
	assert.True(t, os.IsNotExist(statErr), "expected ns/sub to be cleaned up")
}

func TestFileKV_DeleteIfPresent_SecondCallReturnsFalse(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("v")))

	deleted1, err := kv.DeleteIfPresent(ctx, "k")
	require.NoError(t, err)
	assert.True(t, deleted1)

	deleted2, err := kv.DeleteIfPresent(ctx, "k")
	require.NoError(t, err)
	assert.False(t, deleted2)
}

// TestFileKV_Scan_GetReadError exercises the non-KeyNotFoundError branch in
// Scan.Get. The entry has to survive List and then fail Get, so ENOTDIR is no
// use here — List would never enumerate it. A self-referential symlink does
// both: filepath.Walk lstats it and sees a non-directory, so it is listed,
// while Get's os.ReadFile follows it and fails with ELOOP. Neither step
// depends on the uid, so this runs as root in CI.
func TestFileKV_Scan_GetReadError(t *testing.T) {
	kv := newTestFileKV(t)
	ctx := context.Background()

	dir := filepath.Join(kv.rootDir, "ns")
	require.NoError(t, os.MkdirAll(dir, 0700))
	loop := filepath.Join(dir, "key")
	require.NoError(t, os.Symlink(loop, loop))

	called := false
	err := kv.Scan(ctx, "ns/", func(_ string, _ []byte) error {
		called = true
		return nil
	})
	require.Error(t, err)
	require.ErrorIs(t, err, syscall.ELOOP)
	assert.False(t, called)

	var knf *KeyNotFoundError
	require.False(t, errors.As(err, &knf), "ELOOP must not be reported as key-not-found")
}
