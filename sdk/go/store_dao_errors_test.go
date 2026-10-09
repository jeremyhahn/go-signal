package signal

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/daostore"
)

// errReadFailed is the injected read failure; it is deliberately not a
// not-found condition.
var errReadFailed = errors.New("kv read failed")

// faultyKV fails every read once armed, the way a store with a broken disk or a
// lost Raft quorum does. Writes pass through so the setup can seed data.
type faultyKV struct {
	kvstore.KVStore
	armed bool
}

func (k *faultyKV) fail() error {
	if k.armed {
		return errReadFailed
	}
	return nil
}

func (k *faultyKV) Get(ctx context.Context, key string) ([]byte, error) {
	if err := k.fail(); err != nil {
		return nil, err
	}
	return k.KVStore.Get(ctx, key)
}

func (k *faultyKV) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	if err := k.fail(); err != nil {
		return err
	}
	return k.KVStore.Scan(ctx, prefix, fn)
}

func (k *faultyKV) List(ctx context.Context, prefix string) ([]string, error) {
	if err := k.fail(); err != nil {
		return nil, err
	}
	return k.KVStore.List(ctx, prefix)
}

func (k *faultyKV) Exists(ctx context.Context, key string) (bool, error) {
	if err := k.fail(); err != nil {
		return false, err
	}
	return k.KVStore.Exists(ctx, key)
}

func newFaultyDAOStore(t *testing.T) (*DAOStore, *faultyKV) {
	t.Helper()
	kv, err := daostore.NewEmbeddedKVStore(t.TempDir())
	require.NoError(t, err)
	if closer, ok := kv.(io.Closer); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	faulty := &faultyKV{KVStore: kv}
	factory, err := daostore.NewFactory(faulty)
	require.NoError(t, err)
	return NewDAOStore(factory), faulty
}

func testCredentials(t *testing.T) *Credentials {
	t.Helper()
	creds := &Credentials{
		Number:   "+15550000001",
		UUID:     "uuid",
		DeviceID: 1,
		Password: secrets.MustNewSecureString(t.Context(), "token"),
	}
	t.Cleanup(creds.Password.Destroy)
	return creds
}

// TestDAOStore_GetCredentials_NoneStoredIsNotAnError: the typed not-found
// condition is the one failure that means "nothing stored yet".
func TestDAOStore_GetCredentials_NoneStoredIsNotAnError(t *testing.T) {
	store, _ := newFaultyDAOStore(t)

	creds, err := store.GetCredentials(t.Context())

	require.NoError(t, err)
	require.Nil(t, creds)
}

// TestDAOStore_GetCredentials_QueryFailureIsAnError: every query error used to
// read as "not found" and return (nil, nil), so a failed read looked like a
// client that had never registered.
func TestDAOStore_GetCredentials_QueryFailureIsAnError(t *testing.T) {
	store, kv := newFaultyDAOStore(t)
	require.NoError(t, store.SaveCredentials(t.Context(), testCredentials(t)))
	kv.armed = true

	creds, err := store.GetCredentials(t.Context())

	require.ErrorIs(t, err, errReadFailed)
	require.Nil(t, creds)
}

// TestDAOStore_GetCredentials_CanceledContextIsAnError: a canceled context is
// not "no credentials" either.
func TestDAOStore_GetCredentials_CanceledContextIsAnError(t *testing.T) {
	store, _ := newFaultyDAOStore(t)
	require.NoError(t, store.SaveCredentials(t.Context(), testCredentials(t)))

	creds, err := store.GetCredentials(canceledCtx())

	require.Error(t, err)
	require.Nil(t, creds)
}

// TestDAOStore_SaveCredentials_QueryFailureIsAnError: the existing-row lookup
// failing must not fall through to inserting a second credentials row.
func TestDAOStore_SaveCredentials_QueryFailureIsAnError(t *testing.T) {
	store, kv := newFaultyDAOStore(t)
	require.NoError(t, store.SaveCredentials(t.Context(), testCredentials(t)))
	kv.armed = true

	err := store.SaveCredentials(t.Context(), testCredentials(t))

	require.ErrorIs(t, err, errReadFailed)
}

// TestDAOStore_SaveCredentials_UnopenablePasswordIsNotStoredEmpty: a password
// that will not open used to be persisted as "".
func TestDAOStore_SaveCredentials_UnopenablePasswordIsNotStoredEmpty(t *testing.T) {
	store, _ := newFaultyDAOStore(t)

	err := store.SaveCredentials(canceledCtx(), testCredentials(t))

	var unavailable *secrets.UnavailableSecretError
	require.ErrorAs(t, err, &unavailable)
	got, err := store.GetCredentials(t.Context())
	require.NoError(t, err)
	require.Nil(t, got, "credentials were persisted despite the failure")
}
