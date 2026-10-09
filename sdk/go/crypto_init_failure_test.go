package signal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// flakyCredentialStore serves credentials until fail is set, then reports err.
// It lets a client be constructed normally and have the credential lookup
// inside initCrypto fail afterwards, as a transient storage fault does.
type flakyCredentialStore struct {
	mockStore
	fail   atomic.Bool
	err    error
	closed atomic.Bool
}

func (s *flakyCredentialStore) GetCredentials(ctx context.Context) (*Credentials, error) {
	if s.fail.Load() {
		return nil, s.err
	}
	return s.mockStore.GetCredentials(ctx)
}

func (s *flakyCredentialStore) Close() error {
	s.closed.Store(true)
	return nil
}

// TestSend_CryptoInitFailureDoesNotFallBackToPlaintext: a failure to initialize
// crypto is an error. The message must not be sent as plaintext content.
func TestSend_CryptoInitFailureDoesNotFallBackToPlaintext(t *testing.T) {
	var puts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": false})
	}))
	defer srv.Close()

	boom := errors.New("credential store unavailable")
	store := &flakyCredentialStore{err: boom}
	c := newTestClient(t, srv.URL, store)
	store.fail.Store(true)

	result, err := c.Send(t.Context(), "recipient-uuid", "secret message", nil)

	require.ErrorIs(t, err, boom)
	require.Nil(t, result)
	require.Zero(t, puts.Load(), "message reached the server despite the crypto failure")
}

// TestReceive_CryptoInitFailureStopsBeforeAcknowledging: a first receive whose
// crypto initialization fails must return the error and leave the server copy
// in place, rather than store the ciphertext as the body and delete it.
func TestReceive_CryptoInitFailureStopsBeforeAcknowledging(t *testing.T) {
	var deletes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"messages": []any{map[string]any{
					"type":      int(protocol.WHISPER_TYPE),
					"source":    "sender-uuid",
					"content":   base64.StdEncoding.EncodeToString([]byte("ciphertext")),
					"timestamp": 1,
					"guid":      "guid-1",
				}},
			})
		case http.MethodDelete:
			deletes.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	boom := errors.New("credential store unavailable")
	store := &flakyCredentialStore{err: boom}
	c := newTestClient(t, srv.URL, store)
	store.fail.Store(true)

	msgs, err := c.Receive(t.Context(), nil)

	require.ErrorIs(t, err, boom)
	require.Nil(t, msgs)
	require.Zero(t, deletes.Load(), "server copy was acknowledged without being decrypted")
	require.Empty(t, store.messages, "undecrypted payload was stored locally")
}

// TestNewClient_CredentialLoadErrorIsReturned: only the not-found case (nil
// credentials, nil error) is an unregistered client. Any other error is
// returned. A store the constructor opened itself is closed; one the caller
// supplied is left to the caller.
func TestNewClient_CredentialLoadErrorIsReturned(t *testing.T) {
	boom := errors.New("dao unavailable")
	store := &flakyCredentialStore{err: boom}
	store.fail.Store(true)

	c, err := NewClient(t.Context(), ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		Store:     store,
	})

	require.ErrorIs(t, err, boom)
	require.Nil(t, c)
	require.False(t, store.closed.Load(), "a caller-supplied store must stay the caller's to close")
}

// TestNewClient_CanceledContextIsReturned: a canceled context surfaces from the
// credential lookup instead of producing a half-initialized client.
func TestNewClient_CanceledContextIsReturned(t *testing.T) {
	store := &ctxCredentialStore{mockStore{credentials: &Credentials{UUID: "u", DeviceID: 7}}}

	c, err := NewClient(canceledCtx(), ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		Store:     store,
	})

	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, c)
}
