package blob

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

func newFSStore(t *testing.T) *FilesystemStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewFilesystemStore(FilesystemOptions{Root: dir})
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	return s
}

func TestFilesystemStore_NewRequiresRoot(t *testing.T) {
	if _, err := NewFilesystemStore(FilesystemOptions{}); err == nil {
		t.Fatal("expected error for missing Root")
	}
}

func TestFilesystemStore_CDNNumberDefault(t *testing.T) {
	s := newFSStore(t)
	if got := s.CDNNumber(); got != 3 {
		t.Errorf("CDNNumber default = %d; want 3", got)
	}

	custom, err := NewFilesystemStore(FilesystemOptions{Root: t.TempDir(), CDNNumber: 5})
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	if got := custom.CDNNumber(); got != 5 {
		t.Errorf("CDNNumber custom = %d; want 5", got)
	}
}

func TestFilesystemStore_RejectsPathTraversal(t *testing.T) {
	s := newFSStore(t)
	ctx := context.Background()
	if _, err := s.GenerateUpload(ctx, "../escape"); err == nil {
		t.Error("expected error on path traversal in GenerateUpload")
	}
	if _, err := s.Delete(ctx, "../escape"); err == nil {
		t.Error("expected error on path traversal in Delete")
	}
}

func TestFilesystemStore_GenerateUploadCreatesParentDir(t *testing.T) {
	s := newFSStore(t)
	ctx := context.Background()
	desc, err := s.GenerateUpload(ctx, "u1/u2/file.bin")
	if err != nil {
		t.Fatalf("GenerateUpload: %v", err)
	}
	if desc.CDN != 3 || desc.Key != "u1/u2/file.bin" {
		t.Errorf("descriptor = %+v", desc)
	}
	if _, statErr := os.Stat(filepath.Join(s.root, "u1", "u2")); statErr != nil {
		t.Errorf("parent dir not created: %v", statErr)
	}
}

func TestFilesystemStore_ReadHeadersIsEmptyMap(t *testing.T) {
	s := newFSStore(t)
	h, err := s.ReadHeaders(context.Background(), "anything")
	if err != nil || h == nil {
		t.Fatalf("ReadHeaders: %v %v", h, err)
	}
	if len(h) != 0 {
		t.Errorf("expected empty headers, got %v", h)
	}
}

func TestFilesystemStore_Copy_EncryptsAndRoundtrips(t *testing.T) {
	s := newFSStore(t)
	ctx := context.Background()
	// Create the source object.
	srcKey := "src/object"
	plaintext := []byte("hello, signal backup")
	if err := os.MkdirAll(filepath.Join(s.root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, srcKey), plaintext, 0o644); err != nil {
		t.Fatal(err)
	}

	encKey := bytes.Repeat([]byte{0x42}, 32)
	macKey := bytes.Repeat([]byte{0x21}, 32)
	dest := "dst/object"
	if err := s.Copy(ctx, 3, srcKey, len(plaintext), backups.MediaEncryptionParameters{
		EncryptionKey: encKey,
		MACKey:        macKey,
	}, dest); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	encrypted, err := os.ReadFile(filepath.Join(s.root, dest))
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	// Format: 16-byte IV + ciphertext + 32-byte HMAC tag.
	if len(encrypted) < 16+aes.BlockSize+32 {
		t.Fatalf("encrypted output too small: %d", len(encrypted))
	}
	iv := encrypted[:16]
	ct := encrypted[16 : len(encrypted)-32]
	tag := encrypted[len(encrypted)-32:]

	// Recompute MAC and compare.
	mac := hmac.New(sha256.New, macKey)
	mac.Write(iv)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil), tag) {
		t.Error("HMAC tag does not verify")
	}

	// Decrypt and check PKCS#7 unpadding.
	block, _ := aes.NewCipher(encKey)
	mode := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(ct))
	mode.CryptBlocks(out, ct)
	padLen := int(out[len(out)-1])
	if padLen < 1 || padLen > aes.BlockSize {
		t.Fatalf("invalid pad length %d", padLen)
	}
	got := out[:len(out)-padLen]
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted = %q; want %q", got, plaintext)
	}
}

func TestFilesystemStore_Copy_SourceNotFound(t *testing.T) {
	s := newFSStore(t)
	err := s.Copy(context.Background(), 3, "missing", 0, backups.MediaEncryptionParameters{
		EncryptionKey: bytes.Repeat([]byte{1}, 32),
		MACKey:        bytes.Repeat([]byte{2}, 32),
	}, "dest")
	var snf *backups.SourceNotFoundError
	if !errors.As(err, &snf) {
		t.Fatalf("expected *SourceNotFoundError, got %T: %v", err, err)
	}
}

func TestFilesystemStore_Copy_WrongLength(t *testing.T) {
	s := newFSStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "x"), []byte("five!"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := s.Copy(context.Background(), 3, "x", 999, backups.MediaEncryptionParameters{
		EncryptionKey: bytes.Repeat([]byte{1}, 32),
		MACKey:        bytes.Repeat([]byte{2}, 32),
	}, "dest")
	var inv *backups.InvalidLengthError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidLengthError, got %T: %v", err, err)
	}
}

func TestFilesystemStore_Delete_ReturnsBytesFreed(t *testing.T) {
	s := newFSStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "x"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	freed, err := s.Delete(context.Background(), "x")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if freed != 5 {
		t.Errorf("freed = %d; want 5", freed)
	}
	// Idempotent: deleting again returns (0, nil).
	freed, err = s.Delete(context.Background(), "x")
	if err != nil || freed != 0 {
		t.Errorf("repeat Delete: freed=%d err=%v", freed, err)
	}
}

func TestFilesystemStore_ListPaginatesCorrectly(t *testing.T) {
	s := newFSStore(t)
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		if err := os.WriteFile(filepath.Join(s.root, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.List(context.Background(), "", nil, 2)
	if err != nil {
		t.Fatalf("List page 1: %v", err)
	}
	if len(page.Objects) != 2 || page.Cursor == nil {
		t.Fatalf("page 1 = %+v", page)
	}
	page2, err := s.List(context.Background(), "", page.Cursor, 2)
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	if len(page2.Objects) != 2 || page2.Cursor == nil {
		t.Fatalf("page 2 = %+v", page2)
	}
	page3, err := s.List(context.Background(), "", page2.Cursor, 2)
	if err != nil {
		t.Fatalf("List page 3: %v", err)
	}
	if len(page3.Objects) != 1 || page3.Cursor != nil {
		t.Fatalf("page 3 = %+v", page3)
	}
}

func TestFilesystemStore_CalculateBytesUsed(t *testing.T) {
	s := newFSStore(t)
	if err := os.MkdirAll(filepath.Join(s.root, "p"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, sz := range []int{10, 20, 30} {
		buf := make([]byte, sz)
		_, _ = rand.Read(buf)
		if err := os.WriteFile(filepath.Join(s.root, "p", string(rune('a'+i))), buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := s.CalculateBytesUsed(context.Background(), "p")
	if err != nil {
		t.Fatalf("CalculateBytesUsed: %v", err)
	}
	if usage.BytesUsed != 60 || usage.NumObjects != 3 {
		t.Errorf("usage = %+v; want bytes=60 count=3", usage)
	}
}

func TestFilesystemStore_Copy_BadEncryptionKey(t *testing.T) {
	s := newFSStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "x"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// AES requires a 16/24/32-byte key; 17 should be rejected by NewCipher.
	err := s.Copy(context.Background(), 3, "x", 4, backups.MediaEncryptionParameters{
		EncryptionKey: make([]byte, 17),
		MACKey:        make([]byte, 32),
	}, "dest")
	if err == nil {
		t.Error("expected error for invalid encryption key length")
	}
}

func TestFilesystemStore_List_CursorPastEndIsEmpty(t *testing.T) {
	s := newFSStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "a"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := "z"
	page, err := s.List(context.Background(), "", &past, 10)
	if err != nil {
		t.Fatalf("List past end: %v", err)
	}
	if len(page.Objects) != 0 || page.Cursor != nil {
		t.Errorf("expected empty page, got %+v", page)
	}
}

func TestFilesystemStore_List_DefaultsLimit(t *testing.T) {
	s := newFSStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "x"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(context.Background(), "", nil, 0)
	if err != nil || len(page.Objects) != 1 {
		t.Fatalf("List with default limit: %+v err=%v", page, err)
	}
}

func TestFilesystemStore_CalculateBytesUsed_MissingPrefixIsZero(t *testing.T) {
	s := newFSStore(t)
	usage, err := s.CalculateBytesUsed(context.Background(), "missing")
	if err != nil {
		t.Fatalf("CalculateBytesUsed missing: %v", err)
	}
	if usage.BytesUsed != 0 || usage.NumObjects != 0 {
		t.Errorf("usage on missing prefix = %+v; want zeros", usage)
	}
}

func TestFilesystemStore_NewRootMkdirFails(t *testing.T) {
	// Pointing Root at a path whose parent is a regular file makes MkdirAll fail.
	tmp := t.TempDir()
	fileAsParent := filepath.Join(tmp, "regular-file")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := NewFilesystemStore(FilesystemOptions{Root: filepath.Join(fileAsParent, "inner")})
	if err == nil {
		t.Fatal("expected MkdirAll error when parent is a regular file")
	}
}

func TestFilesystemStore_Copy_RejectsPathTraversal(t *testing.T) {
	s := newFSStore(t)
	ctx := context.Background()
	params := backups.MediaEncryptionParameters{
		EncryptionKey: make([]byte, 32),
		MACKey:        make([]byte, 32),
	}
	// Source traversal — pathFor("../escape") rejects.
	if err := s.Copy(ctx, 3, "../escape", 0, params, "dest"); err == nil {
		t.Error("expected error on Copy with traversal source")
	}
	// Destination traversal — pathFor on destPath rejects after a valid read.
	if err := os.WriteFile(filepath.Join(s.root, "src"), []byte("data"), 0o600); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if err := s.Copy(ctx, 3, "src", 4, params, "../escape"); err == nil {
		t.Error("expected error on Copy with traversal destPath")
	}
}

func TestFilesystemStore_Delete_StatError(t *testing.T) {
	// Delete returns (0, nil) for ENOENT, so the fault has to be a different
	// errno. A regular file used as a directory component makes the stat fail
	// with ENOTDIR, which holds for every uid — the permission bits this test
	// used to strip are bypassed by root, and CI runs as root
	// (testing-guidelines.md §Fault Injection).
	s := newFSStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "notadir"), []byte("regular file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	_, err := s.Delete(context.Background(), "notadir/obj")
	if err == nil {
		t.Fatal("expected stat error")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("expected ENOTDIR, got %v", err)
	}
}

func TestFilesystemStore_List_RejectsPathTraversal(t *testing.T) {
	s := newFSStore(t)
	if _, err := s.List(context.Background(), "../escape", nil, 0); err == nil {
		t.Fatal("expected error on List with traversal prefix")
	}
}

func TestFilesystemStore_CalculateBytesUsed_RejectsPathTraversal(t *testing.T) {
	s := newFSStore(t)
	if _, err := s.CalculateBytesUsed(context.Background(), "../escape"); err == nil {
		t.Fatal("expected error on CalculateBytesUsed with traversal prefix")
	}
}

func TestFilesystemStore_Delete_RemoveFailsOnNonEmptyDir(t *testing.T) {
	s := newFSStore(t)
	dir := filepath.Join(s.root, "non-empty")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.Delete(context.Background(), "non-empty"); err == nil {
		t.Fatal("expected remove error on non-empty directory")
	}
}

func TestFilesystemStore_GenerateUpload_MkdirParentFails(t *testing.T) {
	// Make a regular file at the path where MkdirAll wants to put a directory.
	s := newFSStore(t)
	collision := filepath.Join(s.root, "collision")
	if err := os.WriteFile(collision, []byte("x"), 0o600); err != nil {
		t.Fatalf("write collision: %v", err)
	}
	// "collision/inner/file.bin" → parent is "collision/inner" — MkdirAll fails because
	// "collision" is a regular file, not a directory.
	if _, err := s.GenerateUpload(context.Background(), "collision/inner/file.bin"); err == nil {
		t.Fatal("expected MkdirAll error when parent path is a file")
	}
}

func TestFilesystemStore_Copy_MkdirDestParentFails(t *testing.T) {
	s := newFSStore(t)
	ctx := context.Background()
	// Seed a valid 4-byte source.
	if err := os.WriteFile(filepath.Join(s.root, "src"), []byte("data"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	// Make a regular file at "collision"; dest "collision/x" forces MkdirAll to fail.
	if err := os.WriteFile(filepath.Join(s.root, "collision"), []byte("y"), 0o600); err != nil {
		t.Fatalf("write collision: %v", err)
	}
	params := backups.MediaEncryptionParameters{
		EncryptionKey: make([]byte, 32),
		MACKey:        make([]byte, 32),
	}
	if err := s.Copy(ctx, 3, "src", 4, params, "collision/x"); err == nil {
		t.Fatal("expected MkdirAll error on dest with file-as-parent")
	}
}

func TestFilesystemStore_CalculateBytesUsed_WalkErrorBubblesUp(t *testing.T) {
	// The walk callback swallows ENOENT and propagates everything else, so the
	// fault must be a different errno. Walking beneath a regular file yields
	// ENOTDIR on the very first lstat, which no uid can bypass.
	s := newFSStore(t)
	if err := os.WriteFile(filepath.Join(s.root, "notadir"), []byte("regular file"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	_, err := s.CalculateBytesUsed(context.Background(), "notadir/sub")
	if err == nil {
		t.Fatal("expected walk error to bubble up")
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("expected ENOTDIR, got %v", err)
	}
}
