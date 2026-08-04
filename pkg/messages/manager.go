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

// MessagesManager coordinates message storage and retrieval operations. It wraps
// a MessageStore implementation and provides higher-level business logic such as
// server-side envelope metadata assignment and (when configured) shared
// multi-recipient message rehydration.
//
// deliveryCallback and mrmCache are stored in atomic.Values so that
// SetDeliveryCallback / SetMRMCache and the read paths in Insert /
// GetMessagesForDevice can run concurrently without a mutex.
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

// SetMRMCache wires the multi-recipient message cache used to rehydrate
// envelopes that carry a SharedMrmKey reference. When unset (nil), envelopes
// referencing an MRM payload are returned to callers as-is and they are
// expected to handle the cache lookup themselves; in practice this means
// MRM is disabled for the deployment. Safe to call concurrently with reads.
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

// Insert persists a message envelope for delivery to the specified destination
// device. The server assigns a unique GUID and timestamp to the envelope before
// storage. If a delivery callback is registered, it is invoked after successful
// storage.
func (m *MessagesManager) Insert(ctx context.Context, destinationUUID string, destinationDeviceID uint64, envelope *Envelope) error {
	if envelope == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "envelope must not be nil")
	}

	// Preserve a caller-provided ServerGUID so the handler-side loop
	// detector can Check the same GUID it later sees Recorded — only mint
	// a new GUID when the caller hasn't supplied one.
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

// GetMessagesForDevice retrieves pending message envelopes for the specified
// destination device. Results are ordered by server timestamp ascending.
// A limit of zero or negative returns all pending messages.
//
// Envelopes that carry a SharedMrmKey are rehydrated from the MRM cache
// before being returned: their Content is set to the recipient's reconstructed
// SealedSender v2 ReceivedMessage and SharedMrmKey/SharedMrmRecipientView are
// cleared. If the shared MRM data has been evicted (TTL expired, or every
// view was already delivered), the envelope is silently dropped from the
// returned slice and best-effort deleted from the durable store, mirroring
// Java's `getMessageWithSharedMrmData` stale-MRM handling.
// HasMessagesForDevice reports whether the device has at least one
// pending envelope. Cheaper than GetMessagesForDevice — backends
// implement it as a LIMIT 1 (postgres) or key-existence check
// (memory/qrdb) so a fleet-wide scan never pays the
// envelope-marshalling cost.
func (m *MessagesManager) HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) (bool, error) {
	return m.store.HasMessagesForDevice(ctx, destinationUUID, destinationDeviceID)
}

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

// rehydrateMRM joins an envelope's referenced shared MRM data with its
// recipient view header, replacing Content with the reconstructed SealedSender
// v2 ReceivedMessage. SharedMrmKey/SharedMrmRecipientView are cleared on the
// returned envelope so downstream callers see a self-contained message.
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

// RemoveExpired deletes every persisted envelope whose per-row expires_at is
// strictly before the supplied cutoff. Returns the count of rows removed.
// Backends that do not record an expiration timestamp (today: memory, qrdb)
// report (0, nil), so the sweep is a uniform no-op there.
func (m *MessagesManager) RemoveExpired(ctx context.Context, before time.Time) (int64, error) {
	n, err := m.store.RemoveExpired(ctx, before)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "failed to remove expired messages", err)
	}
	return n, nil
}
