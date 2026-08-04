package signal

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		Password: NewSecurePassword("test-password"),
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
		Password: NewSecurePassword("pw1"),
	}))

	// Second save — updates the existing entity (covers the "existing != nil" branch).
	require.NoError(t, store.SaveCredentials(&Credentials{
		Number:   "+15555550200",
		UUID:     "second-uuid",
		DeviceID: 2,
		Password: NewSecurePassword("pw2"),
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
