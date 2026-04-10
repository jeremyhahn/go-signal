package signal

import (
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
	defer store.Close()
}

func TestDAOStore_CredentialsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer store.Close()

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

func TestDAOStore_ContactsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewDefaultDAOStore(dir)
	require.NoError(t, err)
	defer store.Close()

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
	defer store.Close()

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
	defer store.Close()

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
