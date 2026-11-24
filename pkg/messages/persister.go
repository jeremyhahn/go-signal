package messages

import (
	"context"
	"errors"
	"log/slog"
)

// PersisterDeviceLister returns the (uuid, device) pairs with messages in the cache queue.
type PersisterDeviceLister interface {
	ListPendingDevices(ctx context.Context) ([]DeviceRef, error)
}

// DeviceRef identifies a single per-device message queue.
type DeviceRef struct {
	UUID     string
	DeviceID uint64
}

// MessagePersister moves envelopes from a CacheQueue to a durable MessageStore; replicas need leader election to avoid racing on a device.
type MessagePersister struct {
	queue        *CacheQueue
	store        MessageStore
	listDevices  PersisterDeviceLister
	logger       *slog.Logger
	maxPerDevice int64
}

// PersisterConfig holds construction options.
type PersisterConfig struct {
	// Queue is the cache-side staging area drained by the persister.
	Queue *CacheQueue
	// Store is the durable destination.
	Store MessageStore
	// Devices reports which (uuid, device) pairs need draining.
	Devices PersisterDeviceLister
	// Logger receives per-tick diagnostics. Defaults to slog.Default.
	Logger *slog.Logger
	// MaxPerDevice caps envelopes drained per device per tick; zero means 100.
	MaxPerDevice int64
}

// NewMessagePersister constructs a MessagePersister.
func NewMessagePersister(cfg PersisterConfig) *MessagePersister {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	max := cfg.MaxPerDevice
	if max <= 0 {
		max = 100
	}
	return &MessagePersister{
		queue:        cfg.Queue,
		store:        cfg.Store,
		listDevices:  cfg.Devices,
		logger:       logger,
		maxPerDevice: max,
	}
}

// RunOnce drains every pending device once.
func (p *MessagePersister) RunOnce(ctx context.Context) error {
	if p.queue == nil || p.store == nil || p.listDevices == nil {
		return errors.New("messages/persister: queue, store, and devices are required")
	}

	devices, err := p.listDevices.ListPendingDevices(ctx)
	if err != nil {
		return &PersisterError{Op: "messages/persister: list devices", Cause: err}
	}
	for _, d := range devices {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.drainDevice(ctx, d); err != nil {
			// Log the per-device failure but continue with the others —
			// one slow or unhealthy device must not block the rest.
			p.logger.ErrorContext(ctx, "messages/persister: device drain failed",
				slog.String("uuid", d.UUID),
				slog.Uint64("device", d.DeviceID),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}

// drainDevice pulls up to maxPerDevice envelopes for one device and
// persists them, removing each from the cache after the durable Insert
// returns nil.
func (p *MessagePersister) drainDevice(ctx context.Context, d DeviceRef) error {
	envs, err := p.queue.Drain(ctx, d.UUID, d.DeviceID, p.maxPerDevice)
	if err != nil {
		return &PersisterError{Op: "drain", Cause: err}
	}
	for _, env := range envs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := p.store.Insert(ctx, d.UUID, d.DeviceID, env); err != nil {
			return &PersisterError{Op: "store insert", Key: env.ServerGUID, Cause: err}
		}
		if err := p.queue.Remove(ctx, d.UUID, d.DeviceID, env.ServerGUID); err != nil {
			// Already persisted; a failed cache removal is re-persisted next tick, which GUID idempotency absorbs.
			p.logger.WarnContext(ctx, "messages/persister: cache remove failed; envelope will be re-persisted on next tick",
				slog.String("guid", env.ServerGUID),
				slog.String("uuid", d.UUID),
				slog.Uint64("device", d.DeviceID),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}
