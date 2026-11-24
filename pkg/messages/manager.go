package messages

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"

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

// MessagesManager wraps a MessageStore, assigning envelope metadata and rehydrating multi-recipient messages; its callback and MRM cache are atomic.
type MessagesManager struct {
	store            MessageStore
	logger           *slog.Logger
	deliveryCallback atomic.Value // holds *deliveryCallbackHolder
	mrmCache         atomic.Value // holds *mrmCacheHolder
}

// mrmCacheHolder wraps the optional MRM cache so atomic.Value can hold it
// without an interface{} nil-pointer ambiguity.
type mrmCacheHolder struct {
	cache *MRMCache
}

// NewMessagesManager creates a new MessagesManager backed by the provided
// MessageStore.
func NewMessagesManager(store MessageStore) *MessagesManager {
	return &MessagesManager{
		store:  store,
		logger: slog.Default().With(slog.String("component", "messages-manager")),
	}
}

// SetMRMCache sets the cache used to rehydrate SharedMrmKey envelopes; nil disables MRM. Safe concurrently with reads.
func (m *MessagesManager) SetMRMCache(c *MRMCache) {
	m.mrmCache.Store(&mrmCacheHolder{cache: c})
}

// loadMRMCache returns the configured MRM cache or nil if none is wired.
func (m *MessagesManager) loadMRMCache() *MRMCache {
	if h, ok := m.mrmCache.Load().(*mrmCacheHolder); ok && h != nil {
		return h.cache
	}
	return nil
}

// SetDeliveryCallback registers a callback that is invoked after each message
// is successfully stored. This is used to trigger real-time WebSocket delivery.
// It is safe to call concurrently with Insert.
func (m *MessagesManager) SetDeliveryCallback(fn DeliveryCallback) {
	m.deliveryCallback.Store(&deliveryCallbackHolder{fn: fn})
}

// Insert stores an envelope for the destination device with a server GUID and timestamp, then calls the delivery callback.
func (m *MessagesManager) Insert(ctx context.Context, destinationUUID string, destinationDeviceID uint64, envelope *Envelope) error {
	if envelope == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "envelope must not be nil")
	}

	// Keep a caller-provided ServerGUID for the loop detector.
	if envelope.ServerGUID == "" {
		envelope.ServerGUID = uuid.New().String()
	}
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

// HasMessagesForDevice reports whether the device has a pending envelope, without loading any.
func (m *MessagesManager) HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) (bool, error) {
	return m.store.HasMessagesForDevice(ctx, destinationUUID, destinationDeviceID)
}

// GetMessagesForDevice returns the device's pending envelopes in server-timestamp order, rehydrating MRM references and dropping stale ones.
func (m *MessagesManager) GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) ([]*Envelope, error) {
	envelopes, err := m.store.GetMessagesForDevice(ctx, destinationUUID, destinationDeviceID)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "failed to get messages for device", err)
	}

	cache := m.loadMRMCache()
	if cache == nil {
		return envelopes, nil
	}

	out := envelopes[:0]
	for _, env := range envelopes {
		if env == nil || len(env.SharedMrmKey) == 0 {
			out = append(out, env)
			continue
		}
		rehydrated, err := m.rehydrateMRM(ctx, cache, env)
		if err != nil {
			m.logger.Warn("mrm rehydrate failed; dropping envelope",
				slog.String("uuid", destinationUUID),
				slog.Uint64("deviceId", destinationDeviceID),
				slog.String("serverGuid", env.ServerGUID),
				slog.String("error", err.Error()))
			// Best-effort: remove the stale envelope from durable storage
			// so it doesn't keep retrying. Errors here are logged and
			// swallowed since the user-facing read already succeeded.
			if env.ServerGUID != "" {
				if delErr := m.store.Delete(ctx, destinationUUID, env.ServerGUID); delErr != nil {
					m.logger.Debug("mrm stale envelope delete failed",
						slog.String("serverGuid", env.ServerGUID),
						slog.String("error", delErr.Error()))
				}
			}
			continue
		}
		out = append(out, rehydrated)
	}
	return out, nil
}

// rehydrateMRM replaces Content with the recipient's reconstructed SealedSender v2 message and clears the MRM fields.
func (m *MessagesManager) rehydrateMRM(ctx context.Context, cache *MRMCache, env *Envelope) (*Envelope, error) {
	data, view, err := cache.Get(ctx, string(env.SharedMrmKey), string(env.SharedMrmRecipientView))
	if err != nil {
		// ErrMRMDataMissing → stale, treat as drop.
		if errors.Is(err, ErrMRMDataMissing) {
			return nil, err
		}
		return nil, err
	}
	if view == nil {
		// Data present but this recipient's view has already been removed;
		// the envelope is a duplicate of an already-delivered message.
		return nil, ErrMRMDataMissing
	}

	content, err := sealed.MessageForRecipient(data, view)
	if err != nil {
		return nil, err
	}

	rehydrated := *env
	rehydrated.Content = content
	rehydrated.SharedMrmKey = nil
	rehydrated.SharedMrmRecipientView = nil
	return &rehydrated, nil
}

// Delete removes the envelope with the given server GUID; idempotent.
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

// RemoveExpired deletes envelopes whose expires_at is before cutoff and returns the count; backends without expiry return (0, nil).
func (m *MessagesManager) RemoveExpired(ctx context.Context, before time.Time) (int64, error) {
	n, err := m.store.RemoveExpired(ctx, before)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "failed to remove expired messages", err)
	}
	return n, nil
}
