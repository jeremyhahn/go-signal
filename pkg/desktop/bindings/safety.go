//go:build desktop

package bindings

import (
	"context"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// SafetyBindings provides safety number and identity operations.
type SafetyBindings struct {
	client  *signal.Client
	factory *daostore.Factory
}

// NewSafetyBindings creates safety bindings.
func NewSafetyBindings(client *signal.Client, f *daostore.Factory) *SafetyBindings {
	return &SafetyBindings{client: client, factory: f}
}

// SafetyNumberResult holds a generated safety number for display.
type SafetyNumberResult struct {
	Number     string `json:"number"`
	QRCodeData string `json:"qrCodeData"`
	IsVerified bool   `json:"isVerified"`
}

// GetSafetyNumber generates the safety number for a contact.
// Uses go-libsignal's fingerprint package.
func (b *SafetyBindings) GetSafetyNumber(contactUUID string) (*SafetyNumberResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	contact, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", contactUUID)
	if err != nil {
		return nil, err
	}

	// Look up the contact's stored identity key.
	address := contactUUID + ".1"
	identityEntity, idErr := b.factory.IdentityKeys.QueryOneByIndex(ctx, "Address", address)

	isVerified := contact.IsVerified
	safetyNumber := ""
	if idErr == nil && identityEntity != nil {
		// Generate a displayable safety number from the identity key bytes.
		// Full fingerprint generation via go-libsignal requires both local
		// and remote identity keys. For now, use a hex-encoded key hash.
		safetyNumber = fmt.Sprintf("%x", identityEntity.Key)
	}

	return &SafetyNumberResult{
		Number:     safetyNumber,
		QRCodeData: safetyNumber,
		IsVerified: isVerified,
	}, nil
}

// VerifyIdentity marks a contact's identity as verified.
func (b *SafetyBindings) VerifyIdentity(contactUUID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	contact, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", contactUUID)
	if err != nil {
		return err
	}
	contact.IsVerified = true
	return b.factory.Contacts.Save(ctx, contact)

}

// GetIdentityKey returns the stored identity key for a contact.
func (b *SafetyBindings) GetIdentityKey(contactUUID string) (*entities.IdentityKeyEntity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The address format is "uuid.1" for the primary device.
	address := contactUUID + ".1"
	return b.factory.IdentityKeys.QueryOneByIndex(ctx, "Address", address)
}
