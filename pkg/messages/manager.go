package messages

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// DeliveryCallback is invoked after a message is successfully stored, allowing
// real-time delivery to connected WebSocket clients.
type DeliveryCallback func(uuid string, deviceID uint64, envelope *Envelope)

// deliveryCallbackHolder is a typed wrapper so atomic.Value can hold a
// DeliveryCallback without an interface{} nil-pointer ambiguity.
type deliveryCallbackHolder struct {
	fn DeliveryCallback
}

// MessagesManager coordinates message storage and retrieval operations. It wraps
// a MessageStore implementation and provides higher-level business logic such as
// server-side envelope metadata assignment.
//
// deliveryCallback is stored in an atomic.Value so that SetDeliveryCallback
// and the read in Insert can run concurrently without a mutex.
type MessagesManager struct {
	store            MessageStore
	deliveryCallback atomic.Value // holds *deliveryCallbackHolder
}

// NewMessagesManager creates a new MessagesManager backed by the provided
// MessageStore.
func NewMessagesManager(store MessageStore) *MessagesManager {
	return &MessagesManager{store: store}
}

// SetDeliveryCallback registers a callback that is invoked after each message
// is successfully stored. This is used to trigger real-time WebSocket delivery.
// It is safe to call concurrently with Insert.
func (m *MessagesManager) SetDeliveryCallback(fn DeliveryCallback) {
	m.deliveryCallback.Store(&deliveryCallbackHolder{fn: fn})
}

// Insert persists a message envelope for delivery to the specified destination
// device. The server assigns a unique GUID and timestamp to the envelope before
// storage. If a delivery callback is registered, it is invoked after successful
// storage.
func (m *MessagesManager) Insert(ctx context.Context, destinationUUID string, destinationDeviceID uint64, envelope *Envelope) error {
	if envelope == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "envelope must not be nil")
	}

	envelope.ServerGUID = uuid.New().String()
	envelope.ServerTimestamp = uint64(time.Now().UnixMilli())
	envelope.DestinationUUID = destinationUUID

	if _, err := m.store.Insert(ctx, destinationUUID, destinationDeviceID, envelope); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "failed to insert message", err)
	}

	if h, ok := m.deliveryCallback.Load().(*deliveryCallbackHolder); ok && h != nil && h.fn != nil {
		h.fn(destinationUUID, destinationDeviceID, envelope)
	}

	return nil
}

// GetMessagesForDevice retrieves pending message envelopes for the specified
// destination device. Results are ordered by server timestamp ascending.
// A limit of zero or negative returns all pending messages.
func (m *MessagesManager) GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) ([]*Envelope, error) {
	envelopes, err := m.store.GetMessagesForDevice(ctx, destinationUUID, destinationDeviceID)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "failed to get messages for device", err)
	}
	return envelopes, nil
}

// Delete removes a specific message envelope identified by its server-assigned
// GUID. This operation is idempotent.
func (m *MessagesManager) Delete(ctx context.Context, destinationUUID string, serverGUID string) error {
	if serverGUID == "" {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "server GUID must not be empty")
	}
	if err := m.store.Delete(ctx, destinationUUID, serverGUID); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "failed to delete message", err)
	}
	return nil
}

// DeleteForDevice removes all pending message envelopes for the specified
// destination device.
func (m *MessagesManager) DeleteForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) error {
	if err := m.store.DeleteForDevice(ctx, destinationUUID, destinationDeviceID); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "failed to delete messages for device", err)
	}
	return nil
}

// DeleteForAccount removes all pending messages for an account.
func (m *MessagesManager) DeleteForAccount(ctx context.Context, uuid string) error {
	if err := m.store.DeleteForAccount(ctx, uuid); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "failed to delete messages for account", err)
	}
	return nil
}
