package attachments

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errReader returns an error on the first Read call.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read error")
}

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	return s
}

// -- NewFileStore --

func TestNewFileStore_Success(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileStore(dir)
	require.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, dir, s.rootDir)
}

func TestNewFileStore_CreatesNestedDirectory(t *testing.T) {
	dir := t.TempDir() + "/nested/deep"
	s, err := NewFileStore(dir)
	require.NoError(t, err)
	assert.NotNil(t, s)
}

func TestNewFileStore_InvalidPath(t *testing.T) {
	// /dev/null is a char device; creating a sub-directory under it must fail.
	_, err := NewFileStore("/dev/null/invalid-dir")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create root dir")
}

// -- Put --

func TestFileStore_Put_Success(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()
	data := []byte("hello attachment")
	err := s.Put(ctx, "key1", bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
}

func TestFileStore_Put_OverwritesExistingFile(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "k", bytes.NewReader([]byte("old")), 3))
	require.NoError(t, s.Put(ctx, "k", bytes.NewReader([]byte("new-value")), 9))

	rc, _, err := s.Get(ctx, "k")
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "new-value", string(got))
}

func TestFileStore_Put_NestedKey(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()
	data := []byte("nested")
	require.NoError(t, s.Put(ctx, "dir/sub/file.bin", bytes.NewReader(data), int64(len(data))))
	ok, err := s.Exists(ctx, "dir/sub/file.bin")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestFileStore_Put_MkdirError(t *testing.T) {
	// "conflict" is written as a regular file; then we attempt to put "conflict/child",
	// which requires creating a directory at rootDir/conflict — impossible since it is
	// already a regular file. This exercises the os.MkdirAll error branch.
	s := newTestFileStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "conflict", bytes.NewReader([]byte("x")), 1))

	err := s.Put(ctx, "conflict/child", bytes.NewReader([]byte("y")), 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mkdir")
}

func TestFileStore_Put_CreateTempError(t *testing.T) {
	// Exercises the os.Create error branch. Put first does MkdirAll on the
	// key's parent, so the fault has to spare the parent and hit only the
	// temp file: a final path component near NAME_MAX does exactly that,
	// because Put appends ".tmp.<16 hex>" to it and pushes the temp name past
	// the 255-byte limit. ENAMETOOLONG holds for every uid — a mode-0500
	// parent would not, since CI runs as root and root bypasses the
	// permission check (testing-guidelines.md §Fault Injection).
	root := t.TempDir()
	s, err := NewFileStore(root)
	require.NoError(t, err)

	longName := strings.Repeat("n", 250)

	putErr := s.Put(context.Background(), "sub/"+longName, bytes.NewReader([]byte("z")), 1)
	require.Error(t, putErr)
	assert.Contains(t, putErr.Error(), "create temp")
	assert.ErrorIs(t, putErr, syscall.ENAMETOOLONG)
}

func TestFileStore_Put_WriteError(t *testing.T) {
	// An errReader that always fails exercises the io.Copy error branch.
	s := newTestFileStore(t)
	ctx := context.Background()
	err := s.Put(ctx, "writekey", errReader{}, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write")
}

func TestFileStore_Put_RenameError(t *testing.T) {
	// If a directory already exists at the target path, os.Rename of the
	// temp file to that path fails on Linux (EISDIR).  This exercises the
	// rename error branch.
	root := t.TempDir()
	s, err := NewFileStore(root)
	require.NoError(t, err)

	// Create a directory where the file should land.
	target := filepath.Join(root, "targetdir")
	require.NoError(t, os.Mkdir(target, 0700))

	ctx := context.Background()
	putErr := s.Put(ctx, "targetdir", bytes.NewReader([]byte("data")), 4)
	require.Error(t, putErr)
	assert.Contains(t, putErr.Error(), "rename")
}

// -- Get --

func TestFileStore_Get_Success(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()
	data := []byte("get-content")
	require.NoError(t, s.Put(ctx, "getkey", bytes.NewReader(data), int64(len(data))))

	rc, size, err := s.Get(ctx, "getkey")
	require.NoError(t, err)
	defer rc.Close()
	assert.Equal(t, int64(len(data)), size)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

func TestFileStore_Get_NotFound(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()
	_, _, err := s.Get(ctx, "missing-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestFileStore_Get_OpenError(t *testing.T) {
	// Exercises the non-ENOENT open error branch. A regular file used as a
	// directory component makes the child path fail with ENOTDIR, which is
	// not ENOENT, so Get takes the wrapped-error path rather than reporting
	// "not found". Root cannot bypass ENOTDIR the way it bypasses the
	// permission bits this test used to rely on.
	root := t.TempDir()
	s, err := NewFileStore(root)
	require.NoError(t, err)

	blocker := filepath.Join(root, "notadir")
	require.NoError(t, os.WriteFile(blocker, []byte("regular file"), 0600))

	_, _, getErr := s.Get(context.Background(), "notadir/child")
	require.Error(t, getErr)
	assert.Contains(t, getErr.Error(), "attachments: open")
	assert.ErrorIs(t, getErr, syscall.ENOTDIR)
}

// -- Delete --

func TestFileStore_Delete_Success(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "del", bytes.NewReader([]byte("bye")), 3))

	require.NoError(t, s.Delete(ctx, "del"))

	ok, err := s.Exists(ctx, "del")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestFileStore_Delete_NotFound(t *testing.T) {
	// Deleting a non-existent key must succeed (idempotent).
	s := newTestFileStore(t)
	err := s.Delete(context.Background(), "no-such-key")
	require.NoError(t, err)
}

func TestFileStore_Delete_NonEnoentError(t *testing.T) {
	// Covers the non-ENOENT delete branch: Delete swallows ENOENT to stay
	// idempotent, so the fault must be a different errno. A regular file used
	// as a directory component yields ENOTDIR, which root cannot bypass —
	// unlike the mode-0500 parent this test used to rely on.
	root := t.TempDir()
	s, err := NewFileStore(root)
	require.NoError(t, err)

	blocker := filepath.Join(root, "notadir")
	require.NoError(t, os.WriteFile(blocker, []byte("regular file"), 0600))

	delErr := s.Delete(context.Background(), "notadir/child")
	require.Error(t, delErr)
	assert.Contains(t, delErr.Error(), "attachments: delete")
	assert.ErrorIs(t, delErr, syscall.ENOTDIR)
}

// -- Exists --

func TestFileStore_Exists_True(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, "present", bytes.NewReader([]byte("v")), 1))

	ok, err := s.Exists(ctx, "present")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestFileStore_Exists_False(t *testing.T) {
	s := newTestFileStore(t)
	ok, err := s.Exists(context.Background(), "absent")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestFileStore_Exists_StatError(t *testing.T) {
	// Covers the non-ENOENT stat branch: Exists reports (false, nil) for
	// ENOENT, so the fault must be a different errno. A regular file used as
	// a directory component yields ENOTDIR, which holds for every uid —
	// unlike the permission bits this test used to rely on.
	root := t.TempDir()
	s, err := NewFileStore(root)
	require.NoError(t, err)

	blocker := filepath.Join(root, "notadir")
	require.NoError(t, os.WriteFile(blocker, []byte("regular file"), 0600))

	ok, statErr := s.Exists(context.Background(), "notadir/child")
	require.Error(t, statErr)
	assert.False(t, ok)
	assert.Contains(t, statErr.Error(), "attachments: stat")
	assert.ErrorIs(t, statErr, syscall.ENOTDIR)
}

// -- Interface compliance --

func TestFileStore_ImplementsStore(t *testing.T) {
	var _ Store = (*FileStore)(nil)
}
