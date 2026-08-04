package messages

import (
	"context"
	"errors"
	"log/slog"
)

// PersisterDeviceLister returns the (uuid, device) pairs that
// currently have messages in the cache queue. The MessagePersister
// iterates this list each tick to find work to do.
//
// In production this is backed by a Redis SCAN over a presence-tracking
// set; for tests an in-memory implementation suffices.
type PersisterDeviceLister interface {
	ListPendingDevices(ctx context.Context) ([]DeviceRef, error)
}

// DeviceRef identifies a single per-device message queue.
type DeviceRef struct {
	UUID     string
	DeviceID uint64
}

// MessagePersister moves envelopes from a CacheQueue into a durable
// MessageStore. One Persister.RunOnce call drains every device with
// pending messages once, batched by max-per-device. The continuous
// worker in pkg/workers wraps RunOnce in its loop.
//
// The persister is goroutine-safe but does not guarantee single-flight:
// if two replicas run RunOnce concurrently for the same device they
// race. Leader election (via the worker scheduler's lease) prevents
// that in production deployments.
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
	// Devices reports which (uuid, device) pairs need draining. A
	// production implementation is backed by Redis SCAN; tests can
	// supply a fixed list.
	Devices PersisterDeviceLister
	// Logger receives per-tick diagnostics. Defaults to slog.Default.
	Logger *slog.Logger
	// MaxPerDevice caps the number of envelopes drained from one
	// device per tick. Zero defaults to 100 — small enough to keep
	// individual ticks short, large enough to make progress under
	// load.
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

// RunOnce drains every pending device exactly once. The intended call
// site is the continuous worker loop in pkg/workers — RunOnce returns
// quickly when there's nothing to do, so the worker's idle yield is
// what paces things in steady state.
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
			// The envelope is durably persisted; failing to remove it
			// from the cache means the next tick re-persists it. The
			// MessageStore handles the duplicate via GUID idempotency
			// (qrdb's mirror key is stable per GUID), so this is a
			// degraded mode rather than a data-loss path. Log and
			// continue.
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
