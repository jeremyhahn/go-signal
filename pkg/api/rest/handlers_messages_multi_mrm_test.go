package rest

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/cache"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

func TestIsMRMContentType_Variants(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"", false},
		{"application/json", false},
		{"application/vnd.signal-messenger.mrm", true},
		{"application/vnd.signal-messenger.mrm; charset=utf-8", true},
		{"  application/vnd.signal-messenger.mrm  ", true},
		{"APPLICATION/VND.SIGNAL-MESSENGER.MRM", true},
		{"text/plain", false},
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			if got := isMRMContentType(tc.ct); got != tc.want {
				t.Errorf("isMRMContentType(%q) = %v, want %v", tc.ct, got, tc.want)
			}
		})
	}
}

func TestParseUnsignedTimestamp_Valid(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"0", 0},
		{"1", 1},
		{"12345", 12345},
		{"9999999999", 9999999999},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseUnsignedTimestamp(tc.in)
			if err != nil {
				t.Fatalf("parseUnsignedTimestamp(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseUnsignedTimestamp(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseUnsignedTimestamp_Invalid(t *testing.T) {
	cases := []string{"", "-1", " 1", "1.5", "abc", "1e3"}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := parseUnsignedTimestamp(in); err == nil {
				t.Errorf("parseUnsignedTimestamp(%q) should error", in)
			}
		})
	}
}

func TestHandleSendMultiRecipientMessageBinary_NoCache(t *testing.T) {
	// Default test server has no MRM cache wired, so the binary path must
	// short-circuit with 503.
	s := newTestServer(t)
	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader([]byte{0x22, 0x01}))
	r.Header.Set("Content-Type", mrmContentType)
	r.Header.Set("X-Signal-Timestamp", "1")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// noopCacheClient is a minimal cache.Client implementation that stores
// nothing; sufficient for binary-handler tests that need to wire an MRMCache
// into the test server but never expect to roundtrip through Redis. Eval is
// a no-op so MRMCache.Insert/RemoveRecipientView complete without errors.
type noopCacheClient struct{}

func (noopCacheClient) Set(context.Context, string, []byte, time.Duration) error { return nil }
func (noopCacheClient) Get(context.Context, string) ([]byte, error)              { return nil, cache.ErrKeyNotFound }
func (noopCacheClient) Del(context.Context, ...string) error                     { return nil }
func (noopCacheClient) Exists(context.Context, string) (bool, error)             { return false, nil }
func (noopCacheClient) Expire(context.Context, string, time.Duration) (bool, error) {
	return false, nil
}
func (noopCacheClient) TTL(context.Context, string) (time.Duration, error)        { return 0, nil }
func (noopCacheClient) Incr(context.Context, string) (int64, error)               { return 0, nil }
func (noopCacheClient) IncrBy(context.Context, string, int64) (int64, error)      { return 0, nil }
func (noopCacheClient) Lock(context.Context, string, string, time.Duration) error { return nil }
func (noopCacheClient) Unlock(context.Context, string, string) error              { return nil }
func (noopCacheClient) ZAdd(context.Context, string, ...cache.ScoredMember) error { return nil }
func (noopCacheClient) ZRange(context.Context, string, int64, int64) ([][]byte, error) {
	return nil, nil
}
func (noopCacheClient) ZRem(context.Context, string, ...[]byte) error { return nil }
func (noopCacheClient) ZCard(context.Context, string) (int64, error)  { return 0, nil }
func (noopCacheClient) HSet(context.Context, string, string, []byte) error {
	return nil
}
func (noopCacheClient) HGet(context.Context, string, string) ([]byte, error) {
	return nil, cache.ErrKeyNotFound
}
func (noopCacheClient) HDel(context.Context, string, ...string) error { return nil }
func (noopCacheClient) HLen(context.Context, string) (int64, error)   { return 0, nil }
func (noopCacheClient) Publish(context.Context, string, []byte) (int64, error) {
	return 0, nil
}
func (noopCacheClient) Subscribe(context.Context, ...string) (cache.Subscription, error) {
	return nil, errors.New("not implemented")
}
func (noopCacheClient) Eval(context.Context, string, []string, ...interface{}) (interface{}, error) {
	return int64(1), nil
}
func (noopCacheClient) Ping(context.Context) error { return nil }
func (noopCacheClient) Close() error               { return nil }

// withMRMCache injects an MRMCache (backed by noopCacheClient) into the
// supplied test server so binary-handler tests can exercise paths past the
// cache-missing short-circuit.
func withMRMCache(t *testing.T, s *Server) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	s.mrmCache = messages.NewMRMCache(noopCacheClient{}, logger)
	s.messages.SetMRMCache(s.mrmCache)
}

func TestHandleSendMultiRecipientMessageBinary_MissingTimestamp(t *testing.T) {
	s := newTestServer(t)
	withMRMCache(t, s)

	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader([]byte{0x22, 0x01}))
	r.Header.Set("Content-Type", mrmContentType)
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), "X-Signal-Timestamp") {
		t.Errorf("body = %q, want mention of X-Signal-Timestamp", w.Body.String())
	}
}

func TestHandleSendMultiRecipientMessageBinary_InvalidTimestamp(t *testing.T) {
	s := newTestServer(t)
	withMRMCache(t, s)

	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader([]byte{0x22, 0x01}))
	r.Header.Set("Content-Type", mrmContentType)
	r.Header.Set("X-Signal-Timestamp", "not-a-number")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleSendMultiRecipientMessageBinary_TimestampOutOfRange(t *testing.T) {
	s := newTestServer(t)
	withMRMCache(t, s)

	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader([]byte{0x22, 0x01}))
	r.Header.Set("Content-Type", mrmContentType)
	// max + 1 — guaranteed to overflow the legal range.
	r.Header.Set("X-Signal-Timestamp", "99999999999999999")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleSendMultiRecipientMessageBinary_BadCiphertext(t *testing.T) {
	s := newTestServer(t)
	withMRMCache(t, s)

	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader([]byte{0x99, 0x01})) // unknown SSv2 version
	r.Header.Set("Content-Type", mrmContentType)
	r.Header.Set("X-Signal-Timestamp", "1")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleSendMultiRecipientMessageBinary_OversizeBody(t *testing.T) {
	s := newTestServer(t)
	withMRMCache(t, s)

	body := bytes.Repeat([]byte{0x22}, maxMRMRequestBytes+1)
	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader(body))
	r.Header.Set("Content-Type", mrmContentType)
	r.Header.Set("X-Signal-Timestamp", "1")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestHandleSendMultiRecipientMessageBinary_EmptyBody(t *testing.T) {
	s := newTestServer(t)
	withMRMCache(t, s)

	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader(nil))
	r.Header.Set("Content-Type", mrmContentType)
	r.Header.Set("X-Signal-Timestamp", "1")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// build0RecipientCiphertext crafts a wire-format-valid SealedSender v2
// SentMessage with zero recipients. The binary handler should reject this
// with 400 ("no recipients in ciphertext"), exercising the
// ErrMRMNoRecipients branch.
func build0RecipientCiphertext() []byte {
	out := make([]byte, 0, 1+1+32+1)
	out = append(out, 0x22) // version
	out = append(out, 0x00) // recipient count = 0 (varint)
	// 32-byte ephemeral public.
	for i := 0; i < 32; i++ {
		out = append(out, byte(i))
	}
	// At least one byte of "encrypted payload" is required.
	out = append(out, 0xFF)
	return out
}

func TestHandleSendMultiRecipientMessageBinary_NoRecipients(t *testing.T) {
	s := newTestServer(t)
	withMRMCache(t, s)

	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader(build0RecipientCiphertext()))
	r.Header.Set("Content-Type", mrmContentType)
	r.Header.Set("X-Signal-Timestamp", "1")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if !strings.Contains(w.Body.String(), "no recipients") {
		t.Errorf("body = %q, want mention of no-recipients", w.Body.String())
	}
}

// build1RecipientCiphertext crafts a wire-format-valid SealedSender v2
// SentMessage with exactly one recipient (one device) that the test can use
// to drive the success path through the binary handler.
func build1RecipientCiphertext(uuidBytes [16]byte, deviceID byte, regID uint16) []byte {
	out := make([]byte, 0, 128)
	out = append(out, 0x22) // version
	out = append(out, 0x01) // recipient count = 1
	out = append(out, uuidBytes[:]...)
	// device entry: deviceID + 2-byte regID (no has_more bit).
	out = append(out, deviceID)
	out = append(out, byte(regID>>8), byte(regID))
	// 32-byte encrypted M and 16-byte auth tag (synthetic).
	for i := 0; i < 32; i++ {
		out = append(out, 0xC0|byte(i))
	}
	for i := 0; i < 16; i++ {
		out = append(out, 0xA0|byte(i))
	}
	// 32-byte ephemeral public.
	for i := 0; i < 32; i++ {
		out = append(out, 0xE0|byte(i))
	}
	// 1-byte payload.
	out = append(out, 0xFF)
	return out
}

func TestHandleSendMultiRecipientMessageBinary_Success_AllRecipientsMissing(t *testing.T) {
	// All recipients in the ciphertext fail to resolve via accounts.Get.
	// SendMRMBinary returns success with uuids404 populated and no envelopes
	// inserted — surface as 200 with empty UUIDs404[] response.
	s := newTestServer(t)
	withMRMCache(t, s)

	var uuidBytes [16]byte
	uuidBytes[15] = 0x9A
	body := build1RecipientCiphertext(uuidBytes, 1, 42)

	r := httptest.NewRequest(http.MethodPut, "/v1/messages/multi_recipient",
		bytes.NewReader(body))
	r.Header.Set("Content-Type", mrmContentType)
	r.Header.Set("X-Signal-Timestamp", "1")
	w := httptest.NewRecorder()

	s.handleSendMultiRecipientMessage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (body: %s)", w.Code, http.StatusOK, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "uuids404") {
		t.Errorf("body should include uuids404 list, got %q", w.Body.String())
	}
}
