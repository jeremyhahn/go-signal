package svr

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

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
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

func newSVRStub(t *testing.T, secret string, status int) *httptest.Server {
	t.Helper()
	mac := func(identity string) string {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(identity))
		return hex.EncodeToString(h.Sum(nil))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/delete" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		user, pass, ok := decodeBasic(r.Header.Get("Authorization"))
		if !ok || pass != mac(user) {
			w.Header().Set("WWW-Authenticate", `Basic realm="svr2"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(status)
	}))
}

func TestHTTPClient_RemoveData_HappyPath(t *testing.T) {
	srv := newSVRStub(t, "test-secret", http.StatusNoContent)
	t.Cleanup(srv.Close)

	c, err := NewHTTP(t.Context(), HTTPConfig{
		BaseURL:      srv.URL,
		SharedSecret: secrets.MustNewSecureString(t.Context(), "test-secret"),
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	if err := c.RemoveData(context.Background(), "alice"); err != nil {
		t.Fatalf("RemoveData: %v", err)
	}
}

func TestHTTPClient_RemoveData_TreatsNotFoundAsSuccess(t *testing.T) {
	srv := newSVRStub(t, "test-secret", http.StatusNotFound)
	t.Cleanup(srv.Close)
	c, _ := NewHTTP(t.Context(), HTTPConfig{BaseURL: srv.URL, SharedSecret: secrets.MustNewSecureString(t.Context(), "test-secret")})
	t.Cleanup(func() { _ = c.Close() })
	if err := c.RemoveData(context.Background(), "alice"); err != nil {
		t.Errorf("404 should be treated as success; got %v", err)
	}
}

func TestHTTPClient_RemoveData_5xxReturnsTypedError(t *testing.T) {
	srv := newSVRStub(t, "test-secret", http.StatusInternalServerError)
	t.Cleanup(srv.Close)
	c, _ := NewHTTP(t.Context(), HTTPConfig{BaseURL: srv.URL, SharedSecret: secrets.MustNewSecureString(t.Context(), "test-secret")})
	t.Cleanup(func() { _ = c.Close() })
	err := c.RemoveData(context.Background(), "alice")
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *svr.Error, got %v", err)
	}
	if e.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d", e.StatusCode)
	}
}

func TestHTTPClient_RemoveData_AuthRequired(t *testing.T) {
	srv := newSVRStub(t, "right-secret", http.StatusNoContent)
	t.Cleanup(srv.Close)
	c, _ := NewHTTP(t.Context(), HTTPConfig{BaseURL: srv.URL, SharedSecret: secrets.MustNewSecureString(t.Context(), "wrong-secret")})
	t.Cleanup(func() { _ = c.Close() })
	err := c.RemoveData(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected auth error with wrong shared secret")
	}
}

func TestNewHTTP_Validation(t *testing.T) {
	if _, err := NewHTTP(t.Context(), HTTPConfig{}); err == nil {
		t.Error("expected error on empty config")
	}
	if _, err := NewHTTP(t.Context(), HTTPConfig{BaseURL: "https://x"}); err == nil {
		t.Error("expected error on missing SharedSecret")
	}
}

func TestNoopClient(t *testing.T) {
	n := NewNoop()
	if err := n.RemoveData(context.Background(), "alice"); err != nil {
		t.Errorf("Noop should return nil; got %v", err)
	}
	if err := n.Close(); err != nil {
		t.Errorf("Noop Close should return nil; got %v", err)
	}
}

func TestBasicAuthFormat(t *testing.T) {
	const secret = "abc"
	hdr := common.BasicAuthHeader("alice", []byte(secret))
	user, pass, ok := decodeBasic(hdr)
	if !ok || user != "alice" {
		t.Fatalf("decode: ok=%v user=%q", ok, user)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("alice"))
	want := hex.EncodeToString(mac.Sum(nil))
	if pass != want {
		t.Errorf("password = %q, want %q", pass, want)
	}
}
