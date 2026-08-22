package signal

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/daostore"

	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// TestDAOStore_CloseReleasesTheStoreItOpened is the sdk half of the #55 fix.
//
// Close used to return nil without doing anything, so the PebbleDB behind
// NewDefaultDAOStore was never released: its exclusive directory lock outlived
// every caller that shut down correctly. Reopening the same directory is the
// observable proof — it fails with "lock held by current process" if Close goes
// back to doing nothing.
func TestDAOStore_CloseReleasesTheStoreItOpened(t *testing.T) {
	dir := t.TempDir()

	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	require.NoError(t, store.Close())

	reopened, err := NewDefaultDAOStore(dir)
	require.NoError(t, reopened.Close())
	require.NoError(t, err, "the store was not released")
}

// The other half of the ownership contract: a DAOStore built from a factory the
// caller supplied did not open that store and must not close it. Closing it
// here would pull the database out from under a caller who is still using it —
// a worse failure than the leak, because it happens while they are working.
func TestDAOStore_CloseLeavesACallerSuppliedStoreOpen(t *testing.T) {
	dir := t.TempDir()

	kv, err := daostore.NewEmbeddedKVStore(dir)
	require.NoError(t, err)
	closer, ok := kv.(io.Closer)
	require.True(t, ok, "the embedded store must be closable by its owner")
	t.Cleanup(func() { _ = closer.Close() })

	factory, err := daostore.NewFactory(kv)
	require.NoError(t, err)

	store := NewDAOStore(factory)
	require.NoError(t, store.Close())

	// Still locked, so still open: the caller's store survived.
	_, err = daostore.NewEmbeddedKVStore(dir)
	require.Error(t, err, "Close closed a store it did not open")
}

// A constructor that fails must not strand the database it opened. The caller
// gets no handle back, so anything left open is unreachable — and Pebble's
// directory lock outliving a failed constructor means the retry fails for a
// different reason than the one being retried.
func TestNewDefaultDAOStore_ClosesTheStoreWhenTheFactoryFails(t *testing.T) {
	dir := t.TempDir()

	original := newFactory
	newFactory = func(kvstore.KVStore) (*daostore.Factory, error) {
		return nil, errors.New("injected factory failure")
	}
	t.Cleanup(func() { newFactory = original })

	store, err := NewDefaultDAOStore(dir)
	require.Error(t, err)
	require.Nil(t, store)

	// The proof is that the directory is immediately reusable.
	reopened, err := daostore.NewEmbeddedKVStore(dir)
	require.NoError(t, err, "the failed constructor left the store open")
	closer, ok := reopened.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())
}

func TestDAOStore_ImplementsStoreInterface(t *testing.T) {
	// Verify DAOStore satisfies the Store interface at compile time.
	var _ Store = (*DAOStore)(nil)
}

func TestNewDefaultDAOStore_CreatesStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	require.NotNil(t, store)
	require.NotNil(t, store.Factory())
	defer func() { _ = store.Close() }()
}

func TestNewDefaultDAOStore_InvalidPath(t *testing.T) {
	parent := t.TempDir()
	// Create a FILE at the target directory path so the embedded KV store cannot
	// initialise — PebbleDB requires a directory, not a file.
	conflictFile := parent + "/conflict"
	require.NoError(t, os.WriteFile(conflictFile, []byte("x"), 0644))

	_, err := NewDefaultDAOStore(conflictFile)
	assert.Error(t, err)
}

func TestDAOStore_CredentialsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// No credentials initially -- returns error (not found).
	creds, _ := store.GetCredentials()
	assert.Nil(t, creds)

	// Save credentials.
	err = store.SaveCredentials(&Credentials{
		Number:   "+15555550100",
		UUID:     "test-uuid",
		DeviceID: 1,
		Password: mustSecurePassword("test-password"),
	})
	require.NoError(t, err)

	// Load credentials.
	creds, err = store.GetCredentials()
	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, "+15555550100", creds.Number)
	assert.Equal(t, "test-uuid", creds.UUID)
	assert.Equal(t, uint32(1), creds.DeviceID)
	assert.Equal(t, "test-password", creds.Password.Plaintext())
}

func TestDAOStore_SaveCredentials_UpdateExisting(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// First save — creates the settings entity.
	require.NoError(t, store.SaveCredentials(&Credentials{
		Number:   "+15555550100",
		UUID:     "first-uuid",
		DeviceID: 1,
		Password: mustSecurePassword("pw1"),
	}))

	// Second save — updates the existing entity (covers the "existing != nil" branch).
	require.NoError(t, store.SaveCredentials(&Credentials{
		Number:   "+15555550200",
		UUID:     "second-uuid",
		DeviceID: 2,
		Password: mustSecurePassword("pw2"),
	}))

	got, err := store.GetCredentials()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "second-uuid", got.UUID)
}

func TestDAOStore_ContactsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// No contacts initially.
	contacts, err := store.GetContacts()
	require.NoError(t, err)
	assert.Empty(t, contacts)

	// Save a contact.
	err = store.SaveContact(&Contact{
		UUID:      "contact-uuid",
		Number:    "+15555550200",
		GivenName: "Alice",
	})
	require.NoError(t, err)

	// List contacts.
	contacts, err = store.GetContacts()
	require.NoError(t, err)
	require.Len(t, contacts, 1)
	assert.Equal(t, "contact-uuid", contacts[0].UUID)
	assert.Equal(t, "Alice", contacts[0].GivenName)

	// Delete contact.
	err = store.DeleteContact("+15555550200")
	require.NoError(t, err)

	contacts, err = store.GetContacts()
	require.NoError(t, err)
	assert.Empty(t, contacts)
}

func TestDAOStore_MessagesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// Save messages (each needs a unique GUID since the entity has a unique index on GUID).
	err = store.SaveMessage(&Message{
		Timestamp:   1000,
		Source:      "sender-uuid",
		Destination: "conv-1",
		Body:        "hello",
	})
	require.NoError(t, err)

	time.Sleep(time.Millisecond) // ensure unique entity ID from UnixNanoGenerator
	err = store.SaveMessage(&Message{
		Timestamp:   2000,
		Source:      "sender-uuid",
		Destination: "conv-1",
		Body:        "world",
	})
	t.Logf("second message save err: %v", err)
	require.NoError(t, err)

	// Get messages.
	messages, err := store.GetMessages("conv-1", 10)
	require.NoError(t, err)
	require.Len(t, messages, 2)
}

func TestDAOStore_GroupsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// Save group.
	err = store.SaveGroup(&Group{
		ID:   "group-1",
		Name: "Test Group",
	})
	require.NoError(t, err)

	// List groups.
	groups, err := store.GetGroups()
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, "group-1", groups[0].ID)
	assert.Equal(t, "Test Group", groups[0].Name)
}

func TestDAOStore_StickerPacksRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// Empty initially.
	packs, err := store.GetStickerPacks()
	require.NoError(t, err)
	assert.Empty(t, packs)

	// Save a pack.
	err = store.SaveStickerPack(&InstalledStickerPack{
		PackID:  "deadbeef1234",
		PackKey: "aabbccdd",
		URL:     "https://signal.art/stickers",
		Title:   "Test Pack",
	})
	require.NoError(t, err)

	// List packs.
	packs, err = store.GetStickerPacks()
	require.NoError(t, err)
	require.Len(t, packs, 1)
	assert.Equal(t, "deadbeef1234", packs[0].PackID)
	assert.Equal(t, "Test Pack", packs[0].Title)

	// Upsert by PackID.
	err = store.SaveStickerPack(&InstalledStickerPack{
		PackID: "deadbeef1234",
		Title:  "Updated Pack",
	})
	require.NoError(t, err)
	packs, err = store.GetStickerPacks()
	require.NoError(t, err)
	require.Len(t, packs, 1)
	assert.Equal(t, "Updated Pack", packs[0].Title)

	// Delete pack.
	err = store.DeleteStickerPack("deadbeef1234")
	require.NoError(t, err)
	packs, err = store.GetStickerPacks()
	require.NoError(t, err)
	assert.Empty(t, packs)
}

func TestDAOStore_SaveStickerPack_RejectsEmptyID(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	err = store.SaveStickerPack(nil)
	assert.Error(t, err)

	err = store.SaveStickerPack(&InstalledStickerPack{})
	assert.Error(t, err)
}

func TestDAOStore_DeleteStickerPack_Idempotent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	// Deleting a non-existent pack should not error.
	assert.NoError(t, store.DeleteStickerPack("nonexistent"))
}

func TestUnmarshalCredentials_InvalidJSON(t *testing.T) {
	var creds Credentials
	if err := unmarshalCredentials("not-json", &creds); err == nil {
		t.Fatal("expected an error for malformed credential JSON")
	}
}

// Decoding into credentials that already hold a password must wipe the
// previous protected allocation rather than abandon it.
func TestUnmarshalCredentials_DestroysReplacedPassword(t *testing.T) {
	creds := &Credentials{Password: mustSecurePassword("old-password")}
	first := creds.Password

	value := `{"number":"+15551234567","uuid":"u","pni":"p","password":"new-password","deviceId":2}`
	if err := unmarshalCredentials(value, creds); err != nil {
		t.Fatalf("unmarshalCredentials: %v", err)
	}
	if got := creds.Password.Plaintext(); got != "new-password" {
		t.Errorf("password = %q, want %q", got, "new-password")
	}
	if !first.IsDestroyed() {
		t.Error("the replaced password must be wiped, not abandoned")
	}
	if creds.DeviceID != 2 {
		t.Errorf("deviceID = %d, want 2", creds.DeviceID)
	}
}

// A stored credential with no password leaves the field untouched.
func TestUnmarshalCredentials_NoPassword(t *testing.T) {
	var creds Credentials
	value := `{"number":"+15551234567","uuid":"u","pni":"p","password":"","deviceId":1}`
	if err := unmarshalCredentials(value, &creds); err != nil {
		t.Fatalf("unmarshalCredentials: %v", err)
	}
	if creds.Password != nil {
		t.Error("expected no password to be sealed")
	}
}
