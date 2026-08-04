package signal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/stickers"
)

func writeStickerPackDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifest := `{
		"title": "Test Pack",
		"author": "Tester",
		"cover": {"file": "cover.png", "emoji": "🎉"},
		"stickers": [
			{"file": "s1.png", "emoji": "😀"},
			{"file": "s2.png", "emoji": "😂"}
		]
	}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	for _, n := range []string{"cover.png", "s1.png", "s2.png"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("data-"+n), 0644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	return dir
}

// stickerStub records every request the CLI makes so the test can
// assert ordering + envelope shape.
type stickerStub struct {
	mu        sync.Mutex
	manifest  []byte
	stickers  map[string][]byte
	formCount int
}

func newStickerStub() *stickerStub {
	return &stickerStub{stickers: make(map[string][]byte)}
}

func (s *stickerStub) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/sticker/pack/form/"):
		s.mu.Lock()
		s.formCount++
		s.mu.Unlock()
		// 2 stickers per the test pack.
		resp := stickers.StickerPackFormUpload{
			PackId: "deadbeefcafe1234",
			Manifest: stickers.StickerFormField{
				Id:       -1,
				Key:      "stickers/deadbeefcafe1234/manifest.proto",
				Location: "/cdn3/stickers/deadbeefcafe1234/manifest.proto",
				Headers:  map[string]string{},
			},
			Stickers: []stickers.StickerFormField{
				{Id: 0, Key: "stickers/deadbeefcafe1234/full/0",
					Location: "/cdn3/stickers/deadbeefcafe1234/full/0", Headers: map[string]string{}},
				{Id: 1, Key: "stickers/deadbeefcafe1234/full/1",
					Location: "/cdn3/stickers/deadbeefcafe1234/full/1", Headers: map[string]string{}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/cdn3/"):
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		if strings.HasSuffix(r.URL.Path, "/manifest.proto") {
			s.manifest = body
		} else {
			s.stickers[r.URL.Path] = body
		}
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func TestClient_UploadStickerPack_HappyPath(t *testing.T) {
	stub := newStickerStub()
	srv := httptest.NewServer(http.HandlerFunc(stub.serve))
	defer srv.Close()

	packDir := writeStickerPackDir(t)
	cfg := ClientConfig{
		ServerURL: srv.URL,
		DataDir:   t.TempDir(),
		Account:   "+15550000000",
		// Inject a no-op store so the test doesn't depend on the
		// codec_json build tag the file-backed DAO needs.
		Store: &stubStore{},
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.UploadStickerPack(context.Background(), packDir)
	if err != nil {
		t.Fatalf("UploadStickerPack: %v", err)
	}
	if result.PackID != "deadbeefcafe1234" {
		t.Errorf("PackID = %q", result.PackID)
	}
	if len(result.PackKey) != stickers.PackKeyLen {
		t.Errorf("PackKey length = %d, want %d", len(result.PackKey), stickers.PackKeyLen)
	}
	if !strings.Contains(result.URL, result.PackID) {
		t.Errorf("share URL missing pack id: %s", result.URL)
	}

	// Server must have received exactly one manifest + 2 stickers.
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.formCount != 1 {
		t.Errorf("formCount = %d, want 1", stub.formCount)
	}
	if len(stub.manifest) == 0 {
		t.Error("manifest payload empty")
	}
	if len(stub.stickers) != 2 {
		t.Errorf("got %d sticker uploads, want 2", len(stub.stickers))
	}
	// Uploaded manifest must decrypt to a valid Pack protobuf.
	plaintext, err := stickers.DecryptPackPayload(result.PackKey, stub.manifest)
	if err != nil {
		t.Errorf("uploaded manifest envelope rejected on decrypt: %v", err)
	}
	if len(plaintext) == 0 {
		t.Error("decrypted manifest is empty")
	}
}

func TestClient_UploadStickerPack_RejectsBadPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	cfg := ClientConfig{ServerURL: srv.URL, DataDir: t.TempDir(), Store: &stubStore{}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.UploadStickerPack(context.Background(), "/no/such/path")
	if err == nil {
		t.Error("expected error from missing pack")
	}
}

func TestClient_GetSticker_HappyPath(t *testing.T) {
	plain := []byte("decrypted sticker bytes")
	packKey, _ := stickers.NewPackKey()
	envelope, _ := stickers.EncryptPackPayload(packKey, plain)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/cdn3/stickers/") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(envelope)
	}))
	defer srv.Close()

	cfg := ClientConfig{ServerURL: srv.URL, DataDir: t.TempDir(), Store: &stubStore{}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	got, err := client.GetSticker(context.Background(), "deadbeef", 0, packKey)
	if err != nil {
		t.Fatalf("GetSticker: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("got %q, want %q", got, plain)
	}
}

func TestClient_GetSticker_BadPackKeyLength(t *testing.T) {
	cfg := ClientConfig{ServerURL: "http://localhost:0", DataDir: t.TempDir(), Store: &stubStore{}}
	client, _ := NewClient(cfg)
	defer func() { _ = client.Close() }()
	_, err := client.GetSticker(context.Background(), "deadbeef", 0, []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error on short pack key")
	}
}

func TestClient_GetSticker_TamperedEnvelopeRejected(t *testing.T) {
	packKey, _ := stickers.NewPackKey()
	envelope, _ := stickers.EncryptPackPayload(packKey, []byte("hi"))
	envelope[len(envelope)-1] ^= 0xFF

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(envelope)
	}))
	defer srv.Close()

	cfg := ClientConfig{ServerURL: srv.URL, DataDir: t.TempDir(), Store: &stubStore{}}
	client, _ := NewClient(cfg)
	defer func() { _ = client.Close() }()
	_, err := client.GetSticker(context.Background(), "deadbeef", 0, packKey)
	if err == nil {
		t.Error("expected decrypt failure on tampered payload")
	}
}

func TestClient_StickerPackRegistry_CRUDRoundTrip(t *testing.T) {
	cfg := ClientConfig{ServerURL: "http://localhost:0", DataDir: t.TempDir(), Store: &stubStore{}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	if packs, err := client.ListStickerPacks(); err != nil || len(packs) != 0 {
		t.Errorf("initial list = %v %v", packs, err)
	}

	pack := &InstalledStickerPack{PackID: "abc", PackKey: "deadbeef", URL: "https://signal.art"}
	if err := client.SaveStickerPack(pack); err != nil {
		t.Fatalf("Save: %v", err)
	}
	packs, err := client.ListStickerPacks()
	if err != nil || len(packs) != 1 {
		t.Fatalf("post-save list = %v %v", packs, err)
	}
	if packs[0].PackID != "abc" || packs[0].URL != "https://signal.art" {
		t.Errorf("round-trip drift: %+v", packs[0])
	}

	// Upsert by ID.
	pack.URL = "https://signal.org/stickers"
	if err := client.SaveStickerPack(pack); err != nil {
		t.Fatalf("upsert Save: %v", err)
	}
	packs, _ = client.ListStickerPacks()
	if len(packs) != 1 || packs[0].URL != "https://signal.org/stickers" {
		t.Errorf("upsert drift: %+v", packs)
	}

	if err := client.DeleteStickerPack("abc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	packs, _ = client.ListStickerPacks()
	if len(packs) != 0 {
		t.Errorf("expected 0 packs after delete, got %d", len(packs))
	}

	// Delete-missing is idempotent.
	if err := client.DeleteStickerPack("never"); err != nil {
		t.Errorf("Delete missing: %v", err)
	}
}

func TestClient_SaveStickerPack_RejectsEmptyID(t *testing.T) {
	cfg := ClientConfig{ServerURL: "http://localhost:0", DataDir: t.TempDir(), Store: &stubStore{}}
	client, _ := NewClient(cfg)
	defer func() { _ = client.Close() }()
	if err := client.SaveStickerPack(&InstalledStickerPack{}); err == nil {
		t.Error("expected error on empty PackID")
	}
}

func TestStickerPath_ManifestVsSlot(t *testing.T) {
	if p := StickerPath("abc", -1); !strings.HasSuffix(p, "/manifest.proto") {
		t.Errorf("manifest path = %q", p)
	}
	if p := StickerPath("abc", 5); !strings.HasSuffix(p, "/full/5") {
		t.Errorf("slot path = %q", p)
	}
}

func TestClient_UploadStickerPack_SurfacesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := ClientConfig{ServerURL: srv.URL, DataDir: t.TempDir(), Store: &stubStore{}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.UploadStickerPack(context.Background(), writeStickerPackDir(t))
	if err == nil {
		t.Error("expected error when server fails")
	}
}

// --- uploadStickerPayload / uploadStickerS3 / uploadStickerEmbeddedCDN ---

func TestUploadStickerPayload_S3Path_NoContent(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	field := stickers.StickerFormField{
		Key:            "stickers/pack/full/0",
		Policy:         "my-policy",
		Signature:      "my-sig",
		BucketEndpoint: srv.URL,
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("payload"))
	if err != nil {
		t.Fatalf("uploadStickerPayload S3 204: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("expected POST to S3, got %q", gotMethod)
	}
}

func TestUploadStickerPayload_S3Path_OK200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	field := stickers.StickerFormField{
		Key:            "stickers/pack/full/0",
		Acl:            "public-read",
		Algorithm:      "AWS4-HMAC-SHA256",
		Credential:     "cred",
		Date:           "20260101T000000Z",
		Policy:         "policy-val",
		Signature:      "sig-val",
		BucketEndpoint: srv.URL,
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("bytes"))
	if err != nil {
		t.Fatalf("uploadStickerPayload S3 200: %v", err)
	}
}

func TestUploadStickerPayload_S3Path_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	field := stickers.StickerFormField{
		Key:            "stickers/pack/full/0",
		Policy:         "policy",
		Signature:      "sig",
		BucketEndpoint: srv.URL,
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("data"))
	if err == nil {
		t.Fatal("expected error from S3 403")
	}
	var apiErr *APIError
	if ok := errors.As(err, &apiErr); !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
}

func TestUploadStickerPayload_S3Path_MissingBucketEndpoint(t *testing.T) {
	c := newTestClient(t, "http://localhost:0", &stubStore{})
	field := stickers.StickerFormField{
		Key:       "stickers/pack/full/0",
		Policy:    "policy",
		Signature: "sig",
		// BucketEndpoint intentionally empty.
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("data"))
	if err == nil {
		t.Fatal("expected error for missing BucketEndpoint")
	}
}

func TestUploadStickerPayload_EmbeddedCDN_AbsoluteURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %q", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	field := stickers.StickerFormField{
		Key:      "stickers/pack/manifest.proto",
		Location: srv.URL + "/cdn3/stickers/pack/manifest.proto",
		// Policy/Signature empty → embedded CDN path.
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("manifest"))
	if err != nil {
		t.Fatalf("uploadStickerPayload CDN absolute: %v", err)
	}
}

func TestUploadStickerPayload_EmbeddedCDN_RelativePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	field := stickers.StickerFormField{
		Key:      "stickers/pack/full/1",
		Location: "/cdn3/stickers/pack/full/1",
		// Relative location → prepend ServerURL.
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("sticker"))
	if err != nil {
		t.Fatalf("uploadStickerPayload CDN relative: %v", err)
	}
}

func TestUploadStickerPayload_EmbeddedCDN_NoLocation(t *testing.T) {
	c := newTestClient(t, "http://localhost:0", &stubStore{})
	field := stickers.StickerFormField{
		Key: "stickers/pack/full/0",
		// Location empty, Policy/Signature also empty → error.
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("data"))
	if err == nil {
		t.Fatal("expected error: no Location and no S3 policy")
	}
}

func TestUploadStickerPayload_EmbeddedCDN_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	field := stickers.StickerFormField{
		Key:      "stickers/pack/full/0",
		Location: srv.URL + "/cdn3/stickers/pack/full/0",
	}
	err := c.uploadStickerPayload(context.Background(), field, []byte("data"))
	if err == nil {
		t.Fatal("expected error from CDN 410")
	}
}

func TestClient_GetSticker_EmptyPackID(t *testing.T) {
	packKey, _ := stickers.NewPackKey()
	cfg := ClientConfig{ServerURL: "http://localhost:0", DataDir: t.TempDir(), Store: &stubStore{}}
	client, _ := NewClient(cfg)
	defer func() { _ = client.Close() }()

	_, err := client.GetSticker(context.Background(), "", 0, packKey)
	if err == nil {
		t.Fatal("expected error for empty packID")
	}
}

func TestClient_GetSticker_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	packKey, _ := stickers.NewPackKey()
	cfg := ClientConfig{ServerURL: srv.URL, DataDir: t.TempDir(), Store: &stubStore{}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.GetSticker(context.Background(), "deadbeef", 0, packKey)
	if err == nil {
		t.Fatal("expected error from 403 response")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
}

func TestClient_UploadStickerPack_StickerCountMismatch(t *testing.T) {
	// Server returns fewer sticker slots than the pack has stickers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/sticker/pack/form/"):
			// Pack has 2 stickers but server returns only 1 slot.
			resp := stickers.StickerPackFormUpload{
				PackId: "mismatch-pack",
				Manifest: stickers.StickerFormField{
					Key:      "stickers/m/manifest.proto",
					Location: "/cdn3/stickers/m/manifest.proto",
					Headers:  map[string]string{},
				},
				Stickers: []stickers.StickerFormField{
					{Key: "stickers/m/full/0", Location: "/cdn3/stickers/m/full/0", Headers: map[string]string{}},
					// Only 1 sticker slot instead of 2.
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/cdn3/"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	packDir := writeStickerPackDir(t) // has 2 stickers
	cfg := ClientConfig{ServerURL: srv.URL, DataDir: t.TempDir(), Store: &stubStore{}}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.UploadStickerPack(context.Background(), packDir)
	if err == nil {
		t.Fatal("expected error when sticker slot count mismatches pack size")
	}
}

// stubStore is a no-op Store satisfying the SDK interface so tests
// can construct a Client without going through the DAO factory (which
// requires the codec_json build tag). The stickerPacks slice backs
// the sticker pack registry tests below.
type stubStore struct {
	stickerPacks []InstalledStickerPack
}

func (*stubStore) GetCredentials() (*Credentials, error)      { return nil, nil }
func (*stubStore) SaveCredentials(*Credentials) error         { return nil }
func (*stubStore) GetContacts() ([]Contact, error)            { return nil, nil }
func (*stubStore) SaveContact(*Contact) error                 { return nil }
func (*stubStore) DeleteContact(string) error                 { return nil }
func (*stubStore) GetMessages(string, int) ([]Message, error) { return nil, nil }
func (*stubStore) SaveMessage(*Message) error                 { return nil }
func (*stubStore) GetGroups() ([]Group, error)                { return nil, nil }
func (*stubStore) SaveGroup(*Group) error                     { return nil }
func (s *stubStore) GetStickerPacks() ([]InstalledStickerPack, error) {
	return append([]InstalledStickerPack(nil), s.stickerPacks...), nil
}
func (s *stubStore) SaveStickerPack(p *InstalledStickerPack) error {
	if p == nil || p.PackID == "" {
		return errSDKInvalidStickerPack
	}
	for i := range s.stickerPacks {
		if s.stickerPacks[i].PackID == p.PackID {
			s.stickerPacks[i] = *p
			return nil
		}
	}
	s.stickerPacks = append(s.stickerPacks, *p)
	return nil
}
func (s *stubStore) DeleteStickerPack(id string) error {
	out := s.stickerPacks[:0]
	for _, p := range s.stickerPacks {
		if p.PackID != id {
			out = append(out, p)
		}
	}
	s.stickerPacks = out
	return nil
}
func (*stubStore) Close() error { return nil }
