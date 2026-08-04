package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
)

func decodeBasic(hdr string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(hdr, prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(hdr[len(prefix):])
	if err != nil {
		return "", "", false
	}
	sep := strings.IndexByte(string(raw), ':')
	if sep < 0 {
		return "", "", false
	}
	return string(raw[:sep]), string(raw[sep+1:]), true
}

func newStub(t *testing.T, secret string, status int) *httptest.Server {
	t.Helper()
	mac := func(id string) string {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(id))
		return hex.EncodeToString(h.Sum(nil))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/storage" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		user, pass, ok := decodeBasic(r.Header.Get("Authorization"))
		if !ok || pass != mac(user) {
			w.Header().Set("WWW-Authenticate", `Basic realm="storage-service"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
	}))
}

func TestHTTPClient_HappyPath(t *testing.T) {
	srv := newStub(t, "secret-1", http.StatusNoContent)
	t.Cleanup(srv.Close)
	c, err := NewHTTP(HTTPConfig{
		BaseURL:      srv.URL,
		SharedSecret: "secret-1",
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.DeleteStoredData(context.Background(), "alice"); err != nil {
		t.Fatalf("DeleteStoredData: %v", err)
	}
}

func TestHTTPClient_404IsSuccess(t *testing.T) {
	srv := newStub(t, "s", http.StatusNotFound)
	t.Cleanup(srv.Close)
	c, _ := NewHTTP(HTTPConfig{BaseURL: srv.URL, SharedSecret: "s"})
	t.Cleanup(func() { _ = c.Close() })
	if err := c.DeleteStoredData(context.Background(), "alice"); err != nil {
		t.Errorf("404 should be success; got %v", err)
	}
}

func TestHTTPClient_5xxReturnsTypedError(t *testing.T) {
	srv := newStub(t, "s", http.StatusInternalServerError)
	t.Cleanup(srv.Close)
	c, _ := NewHTTP(HTTPConfig{BaseURL: srv.URL, SharedSecret: "s"})
	t.Cleanup(func() { _ = c.Close() })
	err := c.DeleteStoredData(context.Background(), "alice")
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *Error, got %v", err)
	}
	if e.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d", e.StatusCode)
	}
}

func TestHTTPClient_AuthMismatch(t *testing.T) {
	srv := newStub(t, "right", http.StatusNoContent)
	t.Cleanup(srv.Close)
	c, _ := NewHTTP(HTTPConfig{BaseURL: srv.URL, SharedSecret: "wrong"})
	t.Cleanup(func() { _ = c.Close() })
	err := c.DeleteStoredData(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestNewHTTP_Validation(t *testing.T) {
	if _, err := NewHTTP(HTTPConfig{}); err == nil {
		t.Error("expected error on empty config")
	}
	if _, err := NewHTTP(HTTPConfig{BaseURL: "https://x"}); err == nil {
		t.Error("expected error on missing SharedSecret")
	}
}

func TestNoopClient(t *testing.T) {
	n := NewNoop()
	if err := n.DeleteStoredData(context.Background(), "x"); err != nil {
		t.Errorf("Noop should return nil; got %v", err)
	}
	if err := n.Close(); err != nil {
		t.Errorf("Noop Close should return nil; got %v", err)
	}
}

func TestBasicAuthFormat(t *testing.T) {
	hdr := common.BasicAuthHeader("alice", []byte("k"))
	user, pass, ok := decodeBasic(hdr)
	if !ok || user != "alice" {
		t.Fatalf("decode failed")
	}
	h := hmac.New(sha256.New, []byte("k"))
	h.Write([]byte("alice"))
	if pass != hex.EncodeToString(h.Sum(nil)) {
		t.Errorf("password format mismatch")
	}
}
