package messages

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// identityResolver is the subset of *accounts.AccountsManager the
// message layer uses to turn an (identityType, uuid) pair into an
// account. It exists so the messages package does not import the full
// AccountsManager surface.
type identityResolver interface {
	Get(ctx context.Context, uuid string) (*accounts.Account, error)
	GetByPNI(ctx context.Context, pni string) (*accounts.Account, error)
}

// ResolveDestinationAccount returns the Signal account addressed by
// (identityType, uuid). The ACI path goes through Get; the PNI path
// goes through GetByPNI. Using this helper keeps every message
// handler routing messages identically regardless of identity.
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

// StorageNamespace returns the UUID string to use as the storage
// namespace for the envelope. For ACI-addressed envelopes this is the
// recipient's ACI (Account.UUID); for PNI-addressed envelopes it is
// the recipient's PNI. The store keys messages under this string
// directly so ACI and PNI queues never collide.
func (e *Envelope) StorageNamespace() string {
	return e.DestinationUUID
}
