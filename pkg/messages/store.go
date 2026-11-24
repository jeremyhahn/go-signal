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

	// RemoveExpired deletes messages whose expires_at is before cutoff and returns the count; backends without expiry return (0, nil).
	RemoveExpired(ctx context.Context, before time.Time) (int64, error)

	// HasMessagesForDevice reports whether the device has a pending envelope; implementations must not load the envelopes.
	HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) (bool, error)
}
