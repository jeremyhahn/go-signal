package stickers

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(_ []byte) (int, error) { return 0, nil }

// testAccountUUID is used by tests that just need a non-empty caller
// identifier — pack metadata is keyed by accountUUID so tests must
// supply one.
const testAccountUUID = "11111111-1111-1111-1111-111111111111"

// newTestManager returns a fresh manager wired to an in-memory pack store
// with no S3 credentials configured. Tests that exercise the signed-policy
// path build their own manager with S3Config set.
func newTestManager(t *testing.T) *StickersManager {
	t.Helper()
	return NewStickersManager(t.Context(), ManagerConfig{Logger: testLogger()})
}

func TestNewStickersManager_DefaultsStoreToMemory(t *testing.T) {
	m := NewStickersManager(t.Context(), ManagerConfig{Logger: testLogger()})
	if m == nil || m.store == nil {
		t.Fatal("expected non-nil manager + store")
	}
	if _, ok := m.store.(*MemoryPackStore); !ok {
		t.Errorf("default store = %T, want *MemoryPackStore", m.store)
	}
}

func TestNewStickersManager_NilLoggerOK(t *testing.T) {
	m := NewStickersManager(t.Context(), ManagerConfig{})
	if m.logger == nil {
		t.Error("nil Logger should default to slog.Default")
	}
}

func TestNewStickersManager_S3WiredWhenConfigured(t *testing.T) {
	m := NewStickersManager(t.Context(), ManagerConfig{
		Logger: testLogger(),
		S3: S3Config{
			Region: "us-east-1", Bucket: "b", AccessKeyID: "k", SecretAccessKey: secrets.MustNewSecureString(t.Context(), "s"),
		},
	})
	if m.generator == nil || m.signer == nil {
		t.Errorf("expected generator+signer when S3 configured; got %v / %v", m.generator, m.signer)
	}
}

func TestNewStickersManager_S3OmittedWhenIncomplete(t *testing.T) {
	m := NewStickersManager(t.Context(), ManagerConfig{
		Logger: testLogger(),
		S3:     S3Config{Region: "us-east-1"}, // missing other fields
	})
	if m.generator != nil || m.signer != nil {
		t.Error("partial S3 config must not enable signing")
	}
}

func TestGetUploadForm_SingleSticker(t *testing.T) {
	m := newTestManager(t)
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if form.PackId == "" {
		t.Fatal("expected non-empty pack ID")
	}
	if len(form.PackId) != 32 {
		t.Errorf("pack ID len = %d, want 32 (hex(16 bytes))", len(form.PackId))
	}
	if len(form.Stickers) != 1 {
		t.Fatalf("got %d stickers, want 1", len(form.Stickers))
	}
	if form.Stickers[0].Id != 0 {
		t.Errorf("sticker[0].Id = %d, want 0", form.Stickers[0].Id)
	}
}

func TestGetUploadForm_MaxStickers(t *testing.T) {
	m := newTestManager(t)
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 201)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(form.Stickers) != 201 {
		t.Fatalf("got %d stickers, want 201", len(form.Stickers))
	}
}

func TestGetUploadForm_ManifestFields(t *testing.T) {
	m := newTestManager(t)
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if form.Manifest.Id != -1 {
		t.Errorf("manifest ID = %d, want -1 (Java parity)", form.Manifest.Id)
	}
	if !strings.Contains(form.Manifest.Key, form.PackId) {
		t.Errorf("manifest key %q should contain pack ID %q", form.Manifest.Key, form.PackId)
	}
	if !strings.HasSuffix(form.Manifest.Key, "/manifest.proto") {
		t.Errorf("manifest key %q should end with /manifest.proto", form.Manifest.Key)
	}
}

func TestGetUploadForm_StickerKeysFollowJavaPattern(t *testing.T) {
	m := newTestManager(t)
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, sticker := range form.Stickers {
		if sticker.Id != i {
			t.Errorf("sticker[%d].Id = %d, want %d", i, sticker.Id, i)
		}
		wantSuffix := "/full/" + itoa(i)
		if !strings.HasSuffix(sticker.Key, wantSuffix) {
			t.Errorf("sticker[%d].Key = %q, expected suffix %q", i, sticker.Key, wantSuffix)
		}
		if !strings.Contains(sticker.Key, form.PackId) {
			t.Errorf("sticker[%d].Key = %q missing pack ID %q", i, sticker.Key, form.PackId)
		}
	}
}

// itoa avoids the strconv import for the assertion-helper above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := false
	if n < 0 {
		negative = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestGetUploadForm_UniquePackIds(t *testing.T) {
	m := newTestManager(t)
	form1, err := m.GetUploadForm(context.Background(), testAccountUUID, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	form2, err := m.GetUploadForm(context.Background(), testAccountUUID, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if form1.PackId == form2.PackId {
		t.Error("expected unique pack IDs across calls")
	}
}

func TestGetUploadForm_PersistsToStore(t *testing.T) {
	store := NewMemoryPackStore()
	m := NewStickersManager(t.Context(), ManagerConfig{Logger: testLogger(), Store: store})
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 2)
	if err != nil {
		t.Fatalf("GetUploadForm: %v", err)
	}
	got, err := store.Get(context.Background(), form.PackId)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.AccountUUID != testAccountUUID {
		t.Errorf("AccountUUID = %q", got.AccountUUID)
	}
	if got.PackID != form.PackId {
		t.Errorf("PackID mismatch")
	}
}

func TestGetUploadForm_StorePropagatesError(t *testing.T) {
	store := &failingStore{err: errors.New("store down")}
	m := NewStickersManager(t.Context(), ManagerConfig{Logger: testLogger(), Store: store})
	if _, err := m.GetUploadForm(context.Background(), testAccountUUID, 1); err == nil {
		t.Fatal("expected store error to propagate")
	}
}

type failingStore struct {
	err error
}

func (s *failingStore) Put(_ context.Context, _ *PackMetadata) error           { return s.err }
func (s *failingStore) Get(_ context.Context, _ string) (*PackMetadata, error) { return nil, s.err }

func TestGetUploadForm_RejectsEmptyAccountUUID(t *testing.T) {
	m := newTestManager(t)
	_, err := m.GetUploadForm(context.Background(), "", 1)
	var inv *InvalidPackError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidPackError, got %T: %v", err, err)
	}
}

func TestGetUploadForm_RejectsOutOfRangeCounts(t *testing.T) {
	cases := []int{0, -1, 202}
	m := newTestManager(t)
	for _, c := range cases {
		_, err := m.GetUploadForm(context.Background(), testAccountUUID, c)
		var target *InvalidStickerCountError
		if !errors.As(err, &target) {
			t.Errorf("count=%d: expected *InvalidStickerCountError, got %T", c, err)
		}
	}
}

func TestGetUploadForm_BoundaryValues(t *testing.T) {
	m := newTestManager(t)
	for _, n := range []int{1, 201} {
		form, err := m.GetUploadForm(context.Background(), testAccountUUID, n)
		if err != nil {
			t.Fatalf("count=%d: %v", n, err)
		}
		if len(form.Stickers) != n {
			t.Errorf("count=%d: got %d stickers", n, len(form.Stickers))
		}
	}
}

func TestGetUploadForm_LocationPrefix_EmbeddedCDN(t *testing.T) {
	// Without S3 credentials, the form must include the legacy Location
	// field pointing at /cdn3 so dev deployments keep working.
	m := newTestManager(t)
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(form.Manifest.Location, "/cdn3/") {
		t.Errorf("manifest location %q should start with /cdn3/", form.Manifest.Location)
	}
	if !strings.HasPrefix(form.Stickers[0].Location, "/cdn3/") {
		t.Errorf("sticker location %q should start with /cdn3/", form.Stickers[0].Location)
	}
	if form.Manifest.Policy != "" {
		t.Errorf("manifest Policy must be empty when S3 not configured: %q", form.Manifest.Policy)
	}
}

func TestGetUploadForm_SignedFormWhenS3Configured(t *testing.T) {
	m := NewStickersManager(t.Context(), ManagerConfig{
		Logger: testLogger(),
		S3: S3Config{
			Region: "us-east-1", Bucket: "signal-stickers",
			AccessKeyID: "AKID", SecretAccessKey: secrets.MustNewSecureString(t.Context(), "secret"),
		},
	})
	m.SetClock(func() time.Time { return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC) })
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 2)
	if err != nil {
		t.Fatalf("GetUploadForm: %v", err)
	}
	for i, field := range append([]StickerFormField{form.Manifest}, form.Stickers...) {
		if field.Policy == "" {
			t.Errorf("field[%d] Policy empty", i)
		}
		if field.Signature == "" || len(field.Signature) != 64 {
			t.Errorf("field[%d] Signature = %q (expected 64-char hex)", i, field.Signature)
		}
		if field.Acl != "private" {
			t.Errorf("field[%d] Acl = %q", i, field.Acl)
		}
		if field.Algorithm != "AWS4-HMAC-SHA256" {
			t.Errorf("field[%d] Algorithm = %q", i, field.Algorithm)
		}
		if field.Date != "20150830T123600Z" {
			t.Errorf("field[%d] Date = %q", i, field.Date)
		}
		// Decode the policy and verify it carries the expected key.
		decoded, err := base64.StdEncoding.DecodeString(field.Policy)
		if err != nil {
			t.Errorf("field[%d] policy not base64: %v", i, err)
			continue
		}
		if !strings.Contains(string(decoded), `"bucket": "signal-stickers"`) {
			t.Errorf("field[%d] policy missing bucket", i)
		}
	}
}

func TestGetPack_RoundTrip(t *testing.T) {
	m := newTestManager(t)
	form, err := m.GetUploadForm(context.Background(), testAccountUUID, 1)
	if err != nil {
		t.Fatalf("GetUploadForm: %v", err)
	}
	got, err := m.GetPack(context.Background(), form.PackId)
	if err != nil {
		t.Fatalf("GetPack: %v", err)
	}
	if got.AccountUUID != testAccountUUID {
		t.Errorf("AccountUUID = %q", got.AccountUUID)
	}
}

func TestGetPack_NotFound(t *testing.T) {
	m := newTestManager(t)
	_, err := m.GetPack(context.Background(), "missing")
	var nf *PackNotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *PackNotFoundError, got %T: %v", err, err)
	}
}

func TestMemoryPackStore_RejectsBlankPackID(t *testing.T) {
	store := NewMemoryPackStore()
	if err := store.Put(context.Background(), &PackMetadata{}); err == nil {
		t.Error("expected error for blank PackID")
	}
	if err := store.Put(context.Background(), nil); err == nil {
		t.Error("expected error for nil meta")
	}
}

// Error-string smoke tests ensure the typed errors stay readable; they
// also pin the format so log search tools don't break on a refactor.

func TestPackNotFoundError_String(t *testing.T) {
	want := "sticker pack not found: abc"
	if got := (&PackNotFoundError{PackID: "abc"}).Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestInvalidPackError_String(t *testing.T) {
	want := "invalid sticker pack: nope"
	if got := (&InvalidPackError{Reason: "nope"}).Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGetUploadForm_S3ConfiguredSignerFailurePropagates(t *testing.T) {
	// Configure the manager with credentials that pass the configured()
	// check but produce an empty access key when the form is built — the
	// signer/generator detects the empty field and the manager surfaces
	// the error rather than silently emitting an unsigned form.
	m := NewStickersManager(t.Context(), ManagerConfig{
		Logger: testLogger(),
		S3: S3Config{
			Region: "us-east-1", Bucket: "b", AccessKeyID: "k", SecretAccessKey: secrets.MustNewSecureString(t.Context(), "s"),
		},
	})
	// Replace the generator's required field after construction to force
	// FormatForm to return an error inside makeField; this exercises the
	// otherwise-uncovered error branch.
	m.generator.AccessKeyID = ""
	_, err := m.GetUploadForm(context.Background(), testAccountUUID, 1)
	if err == nil {
		t.Fatal("expected error when generator misconfigured at call time")
	}
}
