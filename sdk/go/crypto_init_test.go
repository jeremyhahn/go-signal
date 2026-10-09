package signal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// ctxCredentialStore fails GetCredentials when the context is done, as a
// database-backed store does.
type ctxCredentialStore struct {
	mockStore
}

func (s *ctxCredentialStore) GetCredentials(ctx context.Context) (*Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.mockStore.GetCredentials(ctx)
}

// TestInitCrypto_CredentialStoreErrorIsPropagated: the store error was
// discarded and the identity store cached with registration ID 1, so one
// transient failure pinned the wrong registration ID for the client's life.
func TestInitCrypto_CredentialStoreErrorIsPropagated(t *testing.T) {
	store := &ctxCredentialStore{mockStore{credentials: &Credentials{UUID: "u", DeviceID: 7}}}
	c := newTestClient(t, "http://localhost", store)

	err := c.initCrypto(canceledCtx())

	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, c.crypto, "crypto state was cached after the failure")

	// A later call with a live context must see the real registration state,
	// not the ID the failed attempt would have pinned.
	require.NoError(t, c.initCrypto(t.Context()))
	require.NotNil(t, c.crypto)
	require.Equal(t, uint32(7), c.crypto.identityStore.GetLocalRegistrationId())
}

// TestInitCrypto_StoreFailureIsTyped: a plain store failure reaches the caller
// as the store's own error.
func TestInitCrypto_StoreFailureIsTyped(t *testing.T) {
	boom := errors.New("store unavailable")
	c := newTestClient(t, "http://localhost", &mockStore{credErr: boom})

	err := c.initCrypto(t.Context())

	require.ErrorIs(t, err, boom)
	require.Nil(t, c.crypto)
}
