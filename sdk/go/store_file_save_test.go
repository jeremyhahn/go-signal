package signal

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestFileStore_SaveCredentials_UnopenablePasswordLeavesFilesUntouched: a
// password that will not open used to skip the auth token write but still
// replace credentials.json and return nil, leaving new identity fields beside
// the previous account's token.
func TestFileStore_SaveCredentials_UnopenablePasswordLeavesFilesUntouched(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	original := &Credentials{
		Number:   "+15550000001",
		UUID:     "old-uuid",
		DeviceID: 1,
		Password: secrets.MustNewSecureString(t.Context(), "old-token"),
	}
	defer original.Password.Destroy()
	require.NoError(t, store.SaveCredentials(t.Context(), original))
	jsonBefore, err := os.ReadFile(store.path("credentials.json"))
	require.NoError(t, err)
	tokenBefore, err := os.ReadFile(store.path(".auth_token"))
	require.NoError(t, err)

	replacement := &Credentials{
		Number:   "+15550000002",
		UUID:     "new-uuid",
		DeviceID: 2,
		Password: secrets.MustNewSecureString(t.Context(), "new-token"),
	}
	defer replacement.Password.Destroy()

	err = store.SaveCredentials(canceledCtx(), replacement)

	var unavailable *secrets.UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %T (%v), want it to wrap *UnavailableSecretError", err, err)
	}
	jsonAfter, err := os.ReadFile(store.path("credentials.json"))
	require.NoError(t, err)
	tokenAfter, err := os.ReadFile(store.path(".auth_token"))
	require.NoError(t, err)
	require.Equal(t, string(jsonBefore), string(jsonAfter), "credentials.json was modified")
	require.Equal(t, string(tokenBefore), string(tokenAfter), ".auth_token was modified")
}

// TestFileStore_SaveCredentials_WritesBothFiles: with an openable password both
// files are written and the token round-trips.
func TestFileStore_SaveCredentials_WritesBothFiles(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	creds := &Credentials{
		Number:   "+15550000003",
		UUID:     "uuid",
		DeviceID: 1,
		Password: secrets.MustNewSecureString(t.Context(), "token"),
	}
	defer creds.Password.Destroy()

	require.NoError(t, store.SaveCredentials(t.Context(), creds))

	token, err := os.ReadFile(store.path(".auth_token"))
	require.NoError(t, err)
	require.Equal(t, "token", string(token))
	got, err := store.GetCredentials(t.Context())
	require.NoError(t, err)
	require.Equal(t, "uuid", got.UUID)
}
