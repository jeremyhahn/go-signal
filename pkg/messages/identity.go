package messages

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// identityResolver is the subset of *accounts.AccountsManager the message layer needs.
type identityResolver interface {
	Get(ctx context.Context, uuid string) (*accounts.Account, error)
	GetByPNI(ctx context.Context, pni string) (*accounts.Account, error)
}

// ResolveDestinationAccount returns the account for (identityType, uuid), via Get for ACI and GetByPNI for PNI.
func ResolveDestinationAccount(ctx context.Context, r identityResolver, identityType accounts.IdentityType, uuid string) (*accounts.Account, error) {
	switch identityType {
	case accounts.IdentityTypePNI:
		return r.GetByPNI(ctx, uuid)
	default:
		// Treat the zero value as ACI for backwards compatibility with
		// senders that predate PNI addressing.
		return r.Get(ctx, uuid)
	}
}

// StorageNamespace returns the recipient's ACI or PNI, whichever the envelope addresses, so the two queues never collide.
func (e *Envelope) StorageNamespace() string {
	return e.DestinationUUID
}
