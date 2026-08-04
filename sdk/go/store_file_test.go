package signal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileStore_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "store")
	store, err := NewFileStore(dir)
	require.NoError(t, err)
	require.NotNil(t, store)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("expected directory to be created")
	}
}

func TestNewFileStore_ExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)
	require.NotNil(t, store)
}

func TestNewFileStore_MkdirAllError(t *testing.T) {
	parent := t.TempDir()
	// Create a regular file at the path NewFileStore wants as a directory.
	conflictFile := parent + "/conflict"
	require.NoError(t, os.WriteFile(conflictFile, []byte("x"), 0644))

	// Trying to create a directory inside a file is an error on all POSIX systems.
	_, err := NewFileStore(conflictFile + "/subdir")
	assert.Error(t, err)
}

func TestFileStore_WriteJSON_MarshalError(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	// chan int cannot be encoded by encoding/json — should return an error.
	err = store.writeJSON(store.path("bad.json"), make(chan int))
	assert.Error(t, err)
}

// --- Credentials ---

func TestFileStore_GetCredentials_NotFound(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	creds, err := store.GetCredentials()
	require.NoError(t, err)
	assert.Nil(t, creds)
}

func TestFileStore_CredentialsRoundTrip(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	creds := &Credentials{
		Number:   "+15550000001",
		UUID:     "test-uuid",
		PNI:      "test-pni",
		DeviceID: 1,
		Password: secrets.NewSecureString("my-secret-password"),
	}
	require.NoError(t, store.SaveCredentials(creds))

	got, err := store.GetCredentials()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "+15550000001", got.Number)
	assert.Equal(t, "test-uuid", got.UUID)
	assert.Equal(t, "test-pni", got.PNI)
	assert.Equal(t, uint32(1), got.DeviceID)
	// Password loaded from auth token file.
	require.NotNil(t, got.Password)
	assert.Equal(t, "my-secret-password", got.Password.Plaintext())
}

func TestFileStore_SaveCredentials_NilPassword(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	creds := &Credentials{
		Number:   "+15550000001",
		DeviceID: 1,
		// Password intentionally nil.
	}
	require.NoError(t, store.SaveCredentials(creds))

	got, err := store.GetCredentials()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "+15550000001", got.Number)
}

// --- Contacts ---

func TestFileStore_GetContacts_Empty(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	contacts, err := store.GetContacts()
	require.NoError(t, err)
	assert.Empty(t, contacts)
}

func TestFileStore_ContactsRoundTrip(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	c1 := &Contact{Number: "+15550000001", Name: "Alice", GivenName: "Alice"}
	c2 := &Contact{Number: "+15550000002", Name: "Bob"}

	require.NoError(t, store.SaveContact(c1))
	require.NoError(t, store.SaveContact(c2))

	contacts, err := store.GetContacts()
	require.NoError(t, err)
	assert.Len(t, contacts, 2)
}

func TestFileStore_SaveContact_UpdateExisting(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.SaveContact(&Contact{Number: "+15550000001", Name: "Old"}))
	require.NoError(t, store.SaveContact(&Contact{Number: "+15550000001", Name: "New"}))

	contacts, err := store.GetContacts()
	require.NoError(t, err)
	require.Len(t, contacts, 1)
	assert.Equal(t, "New", contacts[0].Name)
}

func TestFileStore_DeleteContact_Success(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.SaveContact(&Contact{Number: "+15550000001"}))
	require.NoError(t, store.SaveContact(&Contact{Number: "+15550000002"}))

	require.NoError(t, store.DeleteContact("+15550000001"))

	contacts, err := store.GetContacts()
	require.NoError(t, err)
	require.Len(t, contacts, 1)
	assert.Equal(t, "+15550000002", contacts[0].Number)
}

func TestFileStore_DeleteContact_NotFound(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	// Deleting non-existent contact writes empty list — no error.
	require.NoError(t, store.DeleteContact("+15559999999"))
}

// --- Messages ---

func TestFileStore_GetMessages_Empty(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	msgs, err := store.GetMessages("conv-1", 10)
	require.NoError(t, err)
	assert.Empty(t, msgs)
}

func TestFileStore_MessagesRoundTrip(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	// Outgoing messages: Source="" so key = Destination.
	for i := 0; i < 3; i++ {
		require.NoError(t, store.SaveMessage(&Message{
			Timestamp:   int64(i + 1),
			Destination: "conv-1",
			Body:        "msg",
		}))
	}

	msgs, err := store.GetMessages("conv-1", 10)
	require.NoError(t, err)
	assert.Len(t, msgs, 3)
}

func TestFileStore_GetMessages_WithLimit(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	// Outgoing messages: Source="" so key = Destination.
	for i := 0; i < 5; i++ {
		require.NoError(t, store.SaveMessage(&Message{
			Timestamp:   int64(i + 1),
			Destination: "conv-limit",
		}))
	}

	msgs, err := store.GetMessages("conv-limit", 3)
	require.NoError(t, err)
	assert.Len(t, msgs, 3)
}

func TestFileStore_GetMessages_IncomingBySource(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	// Incoming messages: Source is set → key = Source.
	require.NoError(t, store.SaveMessage(&Message{
		Timestamp: 100,
		Source:    "alice-uuid",
		Body:      "hello",
	}))

	// Retrieve by source UUID.
	msgs, err := store.GetMessages("alice-uuid", 10)
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
}

func TestFileStore_SaveMessage_GroupConversation(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.SaveMessage(&Message{
		Timestamp: 100,
		GroupID:   "group-123",
		Body:      "group message",
	}))

	msgs, err := store.GetMessages("group-123", 10)
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
}

// --- Groups ---

func TestFileStore_GetGroups_Empty(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	groups, err := store.GetGroups()
	require.NoError(t, err)
	assert.Empty(t, groups)
}

func TestFileStore_GroupsRoundTrip(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.SaveGroup(&Group{ID: "g1", Name: "Group 1"}))
	require.NoError(t, store.SaveGroup(&Group{ID: "g2", Name: "Group 2"}))

	groups, err := store.GetGroups()
	require.NoError(t, err)
	assert.Len(t, groups, 2)
}

func TestFileStore_SaveGroup_UpdateExisting(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.SaveGroup(&Group{ID: "g1", Name: "Old"}))
	require.NoError(t, store.SaveGroup(&Group{ID: "g1", Name: "New"}))

	groups, err := store.GetGroups()
	require.NoError(t, err)
	require.Len(t, groups, 1)
	assert.Equal(t, "New", groups[0].Name)
}

// --- Sticker Packs ---

func TestFileStore_GetStickerPacks_Empty(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	packs, err := store.GetStickerPacks()
	require.NoError(t, err)
	assert.Empty(t, packs)
}

func TestFileStore_StickerPacksRoundTrip(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	pack := &InstalledStickerPack{PackID: "abc123", PackKey: "deadbeef", URL: "https://signal.art/abc"}
	require.NoError(t, store.SaveStickerPack(pack))

	packs, err := store.GetStickerPacks()
	require.NoError(t, err)
	require.Len(t, packs, 1)
	assert.Equal(t, "abc123", packs[0].PackID)
	assert.Equal(t, "deadbeef", packs[0].PackKey)
}

func TestFileStore_SaveStickerPack_RejectsEmptyID(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	err = store.SaveStickerPack(&InstalledStickerPack{})
	assert.Error(t, err)
}

func TestFileStore_SaveStickerPack_UpdateExisting(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.SaveStickerPack(&InstalledStickerPack{PackID: "p1", URL: "old"}))
	require.NoError(t, store.SaveStickerPack(&InstalledStickerPack{PackID: "p1", URL: "new"}))

	packs, err := store.GetStickerPacks()
	require.NoError(t, err)
	require.Len(t, packs, 1)
	assert.Equal(t, "new", packs[0].URL)
}

func TestFileStore_DeleteStickerPack_Success(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.SaveStickerPack(&InstalledStickerPack{PackID: "p1"}))
	require.NoError(t, store.SaveStickerPack(&InstalledStickerPack{PackID: "p2"}))

	require.NoError(t, store.DeleteStickerPack("p1"))

	packs, err := store.GetStickerPacks()
	require.NoError(t, err)
	require.Len(t, packs, 1)
	assert.Equal(t, "p2", packs[0].PackID)
}

func TestFileStore_DeleteStickerPack_NotFound(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	// No file yet — idempotent.
	assert.NoError(t, store.DeleteStickerPack("missing"))
}

func TestFileStore_Close(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	assert.NoError(t, store.Close())
}

// --- Additional coverage tests ---

func TestFileStore_WriteJSON_MkdirAllError(t *testing.T) {
	// Pass a path whose parent is a regular file so os.MkdirAll fails,
	// covering the MkdirAll-error return in writeJSON.
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	// Create a file that blocks directory creation.
	conflictFile := filepath.Join(dir, "conflict")
	require.NoError(t, os.WriteFile(conflictFile, []byte("x"), 0644))

	// Attempt to write inside the file (not a directory).
	err = store.writeJSON(filepath.Join(conflictFile, "nested.json"), "data")
	assert.Error(t, err)
}

func TestFileStore_SaveCredentials_WriteJSONFails(t *testing.T) {
	// Make rootDir read-only so WriteFile inside writeJSON fails.  This covers
	// the "return err" branch after writeJSON returns an error in SaveCredentials.
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	require.NoError(t, os.Chmod(dir, 0500))
	defer func() { _ = os.Chmod(dir, 0700) }()

	creds := &Credentials{Number: "+15550000001", DeviceID: 1}
	err = store.SaveCredentials(creds)
	assert.Error(t, err)
}

func TestFileStore_SaveCredentials_AuthTokenIsDirectory(t *testing.T) {
	// Create a directory where .auth_token would be written so os.WriteFile
	// fails, covering the zeroing loop and error-return inside SaveCredentials.
	store, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, os.Mkdir(store.path(".auth_token"), 0700))

	creds := &Credentials{
		Number:   "+15550000001",
		DeviceID: 1,
		Password: secrets.NewSecureString("super-secret"),
	}
	err = store.SaveCredentials(creds)
	assert.Error(t, err)
}

func TestFileStore_GetContacts_ReadError(t *testing.T) {
	// Write invalid JSON to contacts.json so readJSON fails with a non-IsNotExist
	// error, covering the "return nil, err" branch in GetContacts.
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "contacts.json"), []byte("not-json!"), 0600))

	_, err = store.GetContacts()
	assert.Error(t, err)
}

func TestFileStore_GetGroups_ReadError(t *testing.T) {
	// Same pattern as TestFileStore_GetContacts_ReadError but for GetGroups.
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "groups.json"), []byte("not-json!"), 0600))

	_, err = store.GetGroups()
	assert.Error(t, err)
}
