//go:build desktop

package bindings

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// TestNewContactBindings verifies construction.
func TestNewContactBindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NotNil(t, b)
	})
}

// TestContactBindings_ListContacts tests listing all local contacts.
func TestContactBindings_ListContacts(t *testing.T) {
	t.Run("EmptyStore", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		contacts, err := b.ListContacts()
		require.NoError(t, err)
		assert.Empty(t, contacts)
	})
	t.Run("ReturnsAllContacts", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID:      "uuid-a",
			E164:      "+15550001111",
			GivenName: "Alice",
		}))
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID:      "uuid-b",
			E164:      "+15550002222",
			GivenName: "Bob",
		}))
		contacts, err := b.ListContacts()
		require.NoError(t, err)
		assert.Len(t, contacts, 2)
	})
}

// TestContactBindings_GetContact tests lookup by UUID.
func TestContactBindings_GetContact(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID: "uuid-found",
			E164: "+15550003333",
		}))
		got, err := b.GetContact("uuid-found")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "uuid-found", got.UUID)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		_, err := b.GetContact("uuid-ghost")
		require.Error(t, err)
	})
}

// TestContactBindings_GetContactByPhone tests lookup by E.164 phone number.
func TestContactBindings_GetContactByPhone(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID: "uuid-phone",
			E164: "+15550004444",
		}))
		got, err := b.GetContactByPhone("+15550004444")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "+15550004444", got.E164)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		_, err := b.GetContactByPhone("+10000000000")
		require.Error(t, err)
	})
}

// TestContactBindings_SaveContact tests creating and idempotently updating a contact.
func TestContactBindings_SaveContact(t *testing.T) {
	t.Run("SavesNewContact", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		c := &entities.ContactEntity{
			UUID:      "uuid-new",
			E164:      "+15550005555",
			GivenName: "Carol",
		}
		require.NoError(t, b.SaveContact(c))

		got, err := b.GetContact("uuid-new")
		require.NoError(t, err)
		assert.Equal(t, "Carol", got.GivenName)
	})
	t.Run("UpdatesExistingContact", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		c := &entities.ContactEntity{
			UUID:      "uuid-upd",
			E164:      "+15550006666",
			GivenName: "Dave",
		}
		require.NoError(t, b.SaveContact(c))

		// Update the given name.
		c.GivenName = "David"
		require.NoError(t, b.SaveContact(c))

		got, err := b.GetContact("uuid-upd")
		require.NoError(t, err)
		assert.Equal(t, "David", got.GivenName)
	})
}

// TestContactBindings_DeleteContact tests deleting a contact.
func TestContactBindings_DeleteContact(t *testing.T) {
	t.Run("DeletesExistingContact", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID: "uuid-del",
			E164: "+15550007777",
		}))
		require.NoError(t, b.DeleteContact("uuid-del"))

		_, err := b.GetContact("uuid-del")
		require.Error(t, err)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		err := b.DeleteContact("uuid-missing")
		require.Error(t, err)
	})
}

// TestContactBindings_BlockContact tests marking a contact as blocked.
func TestContactBindings_BlockContact(t *testing.T) {
	t.Run("BlocksExistingContact", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID: "uuid-blk",
			E164: "+15550011111",
		}))
		require.NoError(t, b.BlockContact("uuid-blk"))

		contact, err := b.GetContact("uuid-blk")
		require.NoError(t, err)
		assert.True(t, contact.IsBlocked)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		err := b.BlockContact("uuid-nobody")
		require.Error(t, err)
	})
}

// TestContactBindings_UnblockContact tests removing the blocked state.
func TestContactBindings_UnblockContact(t *testing.T) {
	t.Run("UnblocksExistingContact", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID:      "uuid-ublk",
			E164:      "+15550022222",
			IsBlocked: true,
		}))
		require.NoError(t, b.UnblockContact("uuid-ublk"))

		contact, err := b.GetContact("uuid-ublk")
		require.NoError(t, err)
		assert.False(t, contact.IsBlocked)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		err := b.UnblockContact("uuid-nobody")
		require.Error(t, err)
	})
}

// TestContactBindings_SyncContacts tests server contact synchronisation.
func TestContactBindings_SyncContacts(t *testing.T) {
	t.Run("EmptyServerContacts", func(t *testing.T) {
		// stubBindStore returns nil contacts → no-op sync.
		b := NewContactBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.SyncContacts())

		contacts, err := b.ListContacts()
		require.NoError(t, err)
		assert.Empty(t, contacts)
	})
	t.Run("MergesServerContactsIntoDAO", func(t *testing.T) {
		// Pre-populate an existing contact to exercise the "merge" branch.
		factory := newTestBindFactory(t)
		b := NewContactBindings(newBindClient(t), factory)
		require.NoError(t, b.SaveContact(&entities.ContactEntity{
			UUID:       "uuid-sc-1",
			E164:       "+15551001001",
			AvatarPath: "/img/avatar.png", // should be preserved
		}))

		// Client store has two contacts including the one already in DAO.
		client := newBindClientWithContacts(t, []signal.Contact{
			{UUID: "uuid-sc-1", Number: "+15551001001", GivenName: "Eve"},
			{UUID: "uuid-sc-2", Number: "+15551002002", GivenName: "Frank"},
		})
		b2 := NewContactBindings(client, factory)
		require.NoError(t, b2.SyncContacts())

		contacts, err := b2.ListContacts()
		require.NoError(t, err)
		assert.Len(t, contacts, 2)
	})
}
