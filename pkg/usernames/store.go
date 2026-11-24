package usernames

import "context"

// UsernameStore defines the storage interface for username operations.
type UsernameStore interface {
	// ReserveHash attempts to reserve one of the provided username hashes for
	// the given account UUID. It returns the selected hash and a reservation
	// token that must be presented during confirmation.
	ReserveHash(ctx context.Context, uuid string, hashes [][]byte) ([]byte, string, error)

	// ConfirmHash confirms a previously reserved username hash. The provided
	// token must match the reservation token returned by ReserveHash.
	ConfirmHash(ctx context.Context, uuid string, hash []byte, token string) error

	// LookupByHash looks up the account UUID associated with a confirmed
	// username hash. Returns UsernameNotFoundError if no mapping exists.
	LookupByHash(ctx context.Context, hash []byte) (string, error)

	// DeleteHash removes the confirmed username hash for the given account
	// UUID.
	DeleteHash(ctx context.Context, uuid string) error

	// HashForUUID returns the confirmed username hash currently associated
	// with the given account UUID, or [*UsernameNotFoundError] if the account
	// has no confirmed hash. Used by [Manager.SetLink] to enforce Java's
	// invariant that an account must have a confirmed username before it
	// can publish a link.
	HashForUUID(ctx context.Context, uuid string) ([]byte, error)

	// SetLink stores or replaces the username link for the given account.
	SetLink(ctx context.Context, link *UsernameLink) error

	// GetLink retrieves a username link by its handle UUID.
	GetLink(ctx context.Context, handle string) (*UsernameLink, error)

	// LinkForUUID returns the currently published link for the given account
	// UUID, or [*UsernameNotFoundError] if none is stored. Used to support
	// Java's "keep link handle" rotation semantic — the caller can re-use
	// the same handle when only the encrypted blob changes.
	LinkForUUID(ctx context.Context, uuid string) (*UsernameLink, error)

	// DeleteLink removes the username link for the given account UUID.
	DeleteLink(ctx context.Context, uuid string) error

	// DeleteExpiredReservations removes every reservation whose TTL
	// has elapsed. Returns the number of rows removed. Idempotent;
	// safe to call from a background sweeper on any cadence.
	DeleteExpiredReservations(ctx context.Context) (int, error)
}
