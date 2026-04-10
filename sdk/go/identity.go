package signal

import (
	"context"
	"fmt"
)

// ListIdentities returns known identity keys for contacts from local storage.
func (c *Client) ListIdentities(ctx context.Context) ([]Identity, error) {
	// Identity keys are stored in the crypto stores (IdentityKeyStore).
	// For DAOStore, query the identity_keys DAO directly.
	if daoStore, ok := c.store.(*DAOStore); ok {
		entities, err := daoStore.Factory().IdentityKeys.Find(ctx).Execute()
		if err != nil {
			return nil, err
		}
		identities := make([]Identity, len(entities))
		for i, e := range entities {
			identities[i] = Identity{
				UUID:        e.Address,
				Fingerprint: fmt.Sprintf("%x", e.Key),
				TrustLevel:  "TRUSTED_UNVERIFIED",
			}
			if e.VerifiedStatus > 0 {
				identities[i].TrustLevel = "TRUSTED_VERIFIED"
			}
		}
		return identities, nil
	}
	return nil, nil
}

// TrustIdentity marks an identity key as trusted in local storage.
func (c *Client) TrustIdentity(ctx context.Context, number string) error {
	if daoStore, ok := c.store.(*DAOStore); ok {
		entity, err := daoStore.Factory().IdentityKeys.QueryOneByIndex(ctx, "Address", number+".1")
		if err != nil {
			return fmt.Errorf("identity not found for %s", number)
		}
		entity.VerifiedStatus = 1
		return daoStore.Factory().IdentityKeys.Save(ctx, entity)
	}
	return fmt.Errorf("identity trust requires DAOStore")
}
