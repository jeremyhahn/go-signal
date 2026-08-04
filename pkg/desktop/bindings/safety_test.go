//go:build desktop

package bindings

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// seedContact saves a ContactEntity and returns it.
func seedContact(t *testing.T, b *SafetyBindings, uuid, e164 string) *entities.ContactEntity {
	t.Helper()
	c := &entities.ContactEntity{
		UUID:       uuid,
		E164:       e164,
		GivenName:  "Test",
		FamilyName: "User",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, b.factory.Contacts.Save(ctx, c))
	return c
}

// TestNewSafetyBindings verifies construction.
func TestNewSafetyBindings(t *testing.T) {
	t.Run("WithClientAndFactory", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))
		require.NotNil(t, b)
	})
}

// TestSafetyBindings_GetSafetyNumber tests safety number generation.
func TestSafetyBindings_GetSafetyNumber(t *testing.T) {
	t.Run("ContactWithNoIdentityKey", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))
		seedContact(t, b, "uuid-001", "+15550001111")

		result, err := b.GetSafetyNumber("uuid-001")
		require.NoError(t, err)
		require.NotNil(t, result)
		// No identity key — safety number is empty, not verified.
		assert.Equal(t, "", result.Number)
		assert.False(t, result.IsVerified)
	})
	t.Run("ContactWithIdentityKey", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))
		seedContact(t, b, "uuid-002", "+15550002222")

		// Seed the identity key for address "uuid-002.1".
		ctx := context.Background()
		ik := &entities.IdentityKeyEntity{
			Address: "uuid-002.1",
			Key:     []byte{0xde, 0xad, 0xbe, 0xef},
		}
		require.NoError(t, b.factory.IdentityKeys.Save(ctx, ik))

		result, err := b.GetSafetyNumber("uuid-002")
		require.NoError(t, err)
		require.NotNil(t, result)
		// Safety number is the hex encoding of the key bytes.
		assert.Equal(t, "deadbeef", result.Number)
	})
	t.Run("ContactNotFound", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))
		_, err := b.GetSafetyNumber("uuid-missing")
		require.Error(t, err)
	})
}

// TestSafetyBindings_VerifyIdentity tests marking a contact as verified.
func TestSafetyBindings_VerifyIdentity(t *testing.T) {
	t.Run("MarksContactVerified", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))
		seedContact(t, b, "uuid-ver", "+15550003333")

		require.NoError(t, b.VerifyIdentity("uuid-ver"))

		ctx := context.Background()
		contact, err := b.factory.Contacts.QueryOneByIndex(ctx, "UUID", "uuid-ver")
		require.NoError(t, err)
		assert.True(t, contact.IsVerified)
	})
	t.Run("ContactNotFound", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))
		err := b.VerifyIdentity("uuid-ghost")
		require.Error(t, err)
	})
}

// TestSafetyBindings_GetIdentityKey tests identity key retrieval.
func TestSafetyBindings_GetIdentityKey(t *testing.T) {
	t.Run("ReturnsStoredKey", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))

		ctx := context.Background()
		ik := &entities.IdentityKeyEntity{
			Address: "uuid-ik.1",
			Key:     []byte{0x01, 0x02},
		}
		require.NoError(t, b.factory.IdentityKeys.Save(ctx, ik))

		got, err := b.GetIdentityKey("uuid-ik")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "uuid-ik.1", got.Address)
		assert.Equal(t, []byte{0x01, 0x02}, got.Key)
	})
	t.Run("NotFoundReturnsError", func(t *testing.T) {
		b := NewSafetyBindings(newBindClient(t), newTestBindFactory(t))
		_, err := b.GetIdentityKey("uuid-no-key")
		require.Error(t, err)
	})
}
