package messages

import (
	"context"
	"time"
)

// MessageStore defines the storage interface for Signal message envelopes.
type MessageStore interface {
	// Insert persists a new message envelope for delivery.
	Insert(ctx context.Context, destinationUUID string, destinationDevice uint64, envelope *Envelope) (uint64, error)

	// GetMessagesForDevice retrieves all pending messages for a specific device.
	GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) ([]*Envelope, error)

	// Delete removes a specific message by destination and server GUID.
	Delete(ctx context.Context, destinationUUID string, serverGUID string) error

	// DeleteForDevice removes all messages for a specific device.
	DeleteForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) error

	// DeleteForAccount removes all messages for an entire account.
	DeleteForAccount(ctx context.Context, uuid string) error

	// RemoveExpired deletes messages whose per-row expires_at is strictly
	// before the supplied cutoff. Returns the number of rows removed.
	// Backends that do not yet record an expiration timestamp (memory,
	// qrdb today) return (0, nil) — the operation is a no-op rather than
	// an error so the worker can run uniformly across all backends.
	// Mirrors Java Signal-Server's RemoveExpiredMessagesCommand sweep.
	RemoveExpired(ctx context.Context, before time.Time) (int64, error)

	// HasMessagesForDevice reports whether the device has at least
	// one pending envelope. Implementations MUST avoid loading the
	// full envelope set — e.g. postgres uses `SELECT 1 ... LIMIT 1`
	// and qrdb returns after the first hit. Used by the idle-device
	// notifier so a fleet-wide scan does not pay the full
	// GetMessagesForDevice cost on every account×device pair.
	HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) (bool, error)
}
