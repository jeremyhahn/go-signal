//go:build desktop

package bindings

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// ContactBindings provides contact operations to the frontend.
type ContactBindings struct {
	client  *signal.Client
	factory *daostore.Factory
}

// NewContactBindings creates contact bindings.
func NewContactBindings(client *signal.Client, f *daostore.Factory) *ContactBindings {
	return &ContactBindings{client: client, factory: f}
}

// ListContacts returns all locally stored contacts.
func (b *ContactBindings) ListContacts() ([]*entities.ContactEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.factory.Contacts.Find(ctx).
		OrderBy("GivenName").
		Execute()
}

// GetContact returns a contact by UUID.
func (b *ContactBindings) GetContact(uuid string) (*entities.ContactEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.factory.Contacts.QueryOneByIndex(ctx, "UUID", uuid)
}

// GetContactByPhone returns a contact by phone number.
func (b *ContactBindings) GetContactByPhone(e164 string) (*entities.ContactEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.factory.Contacts.QueryOneByIndex(ctx, "E164", e164)
}

// SaveContact creates or updates a local contact.
func (b *ContactBindings) SaveContact(contact *entities.ContactEntity) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if contact exists by UUID.
	existing, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", contact.UUID)
	if err == nil && existing != nil {
		contact.ID = existing.ID
	}
	return b.factory.Contacts.Save(ctx, contact)
}

// DeleteContact removes a contact from local storage.
func (b *ContactBindings) DeleteContact(uuid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	contact, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", uuid)
	if err != nil {
		return err
	}
	return b.factory.Contacts.Delete(ctx, contact)
}

// BlockContact marks a contact as blocked and notifies the server.
func (b *ContactBindings) BlockContact(uuid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Update local state.
	contact, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", uuid)
	if err != nil {
		return err
	}
	contact.IsBlocked = true
	if err := b.factory.Contacts.Save(ctx, contact); err != nil {
		return err
	}

	// Notify server.
	return b.client.Block(ctx, uuid)
}

// UnblockContact removes the blocked state.
func (b *ContactBindings) UnblockContact(uuid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	contact, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", uuid)
	if err != nil {
		return err
	}
	contact.IsBlocked = false
	if err := b.factory.Contacts.Save(ctx, contact); err != nil {
		return err
	}

	return b.client.Unblock(ctx, uuid)
}

// SyncContacts fetches the contact list from the server and merges
// with local storage.
func (b *ContactBindings) SyncContacts() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverContacts, err := b.client.ListContacts(ctx)
	if err != nil {
		return err
	}

	for _, sc := range serverContacts {
		entity := &entities.ContactEntity{
			UUID:        sc.UUID,
			E164:        sc.Number,
			GivenName:   sc.GivenName,
			FamilyName:  sc.FamilyName,
			ProfileName: sc.Name,
			IsBlocked:   sc.Blocked,
		}

		existing, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", sc.UUID)
		if err == nil && existing != nil {
			entity.ID = existing.ID
			entity.AvatarPath = existing.AvatarPath
			entity.IsVerified = existing.IsVerified
			entity.ProfileKey = existing.ProfileKey
		}

		_ = b.factory.Contacts.Save(ctx, entity)
	}

	return nil
}
