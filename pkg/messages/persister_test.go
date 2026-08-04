package messages

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	cachememory "github.com/jeremyhahn/go-signal/pkg/cache/memory"
)

// ---- Test stubs ----

// fixedDeviceLister returns a static slice on every call.
type fixedDeviceLister struct {
	devices []DeviceRef
	err     error
}

func (l *fixedDeviceLister) ListPendingDevices(_ context.Context) ([]DeviceRef, error) {
	if l.err != nil {
		return nil, l.err
	}
	return l.devices, nil
}

// recordingMessageStore records every Insert and lets tests inject
// errors. It's not a full MessageStore — only the methods the
// persister calls are implemented; the rest panic if hit, so failing
// tests are obvious.
type recordingMessageStore struct {
	mu        sync.Mutex
	inserts   []*Envelope
	insertErr error
	insertSeq uint64
}

func (s *recordingMessageStore) Insert(_ context.Context, _ string, _ uint64, env *Envelope) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.insertErr != nil {
		return 0, s.insertErr
	}
	s.insertSeq++
	cp := *env
	s.inserts = append(s.inserts, &cp)
	return s.insertSeq, nil
}

func (s *recordingMessageStore) GetMessagesForDevice(_ context.Context, _ string, _ uint64) ([]*Envelope, error) {
	panic("recordingMessageStore: GetMessagesForDevice not used")
}
func (s *recordingMessageStore) Delete(_ context.Context, _, _ string) error {
	panic("recordingMessageStore: Delete not used")
}
func (s *recordingMessageStore) DeleteForDevice(_ context.Context, _ string, _ uint64) error {
	panic("recordingMessageStore: DeleteForDevice not used")
}
func (s *recordingMessageStore) DeleteForAccount(_ context.Context, _ string) error {
	panic("recordingMessageStore: DeleteForAccount not used")
}
func (s *recordingMessageStore) RemoveExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (s *recordingMessageStore) HasMessagesForDevice(_ context.Context, _ string, _ uint64) (bool, error) {
	return false, nil
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---- Persister behaviour ----

func TestMessagePersister_RunOnce_DrainsToStoreAndClearsCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := cachememory.New()
	defer func() { _ = c.Close() }()

	q := NewCacheQueue(c, 0)
	store := &recordingMessageStore{}
	devices := &fixedDeviceLister{devices: []DeviceRef{{UUID: "u1", DeviceID: 1}}}

	// Stage three envelopes.
	for _, env := range []*Envelope{newEnv("a", 1), newEnv("b", 2), newEnv("c", 3)} {
		if err := q.Enqueue(ctx, "u1", 1, env); err != nil {
			t.Fatal(err)
		}
	}

	p := NewMessagePersister(PersisterConfig{
		Queue:   q,
		Store:   store,
		Devices: devices,
		Logger:  quietLogger(),
	})
	if err := p.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// All three landed in the store.
	if len(store.inserts) != 3 {
		t.Fatalf("expected 3 store inserts, got %d", len(store.inserts))
	}
	// Cache is empty.
	n, _ := q.Len(ctx, "u1", 1)
	if n != 0 {
		t.Fatalf("expected cache drained, len=%d", n)
	}
}

func TestMessagePersister_RunOnce_PreservesDrainOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := cachememory.New()
	defer func() { _ = c.Close() }()

	q := NewCacheQueue(c, 0)
	store := &recordingMessageStore{}
	devices := &fixedDeviceLister{devices: []DeviceRef{{UUID: "u1", DeviceID: 1}}}

	// Insert out of order; the queue sorts them by ServerTimestamp.
	for _, env := range []*Envelope{newEnv("c", 30), newEnv("a", 10), newEnv("b", 20)} {
		_ = q.Enqueue(ctx, "u1", 1, env)
	}
	p := NewMessagePersister(PersisterConfig{Queue: q, Store: store, Devices: devices, Logger: quietLogger()})
	if err := p.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(store.inserts) != 3 {
		t.Fatalf("expected 3 inserts, got %d", len(store.inserts))
	}
	if store.inserts[0].ServerGUID != "a" || store.inserts[1].ServerGUID != "b" || store.inserts[2].ServerGUID != "c" {
		t.Fatalf("persister did not preserve queue order: %v", store.inserts)
	}
}

func TestMessagePersister_RunOnce_NoDevices_Noop(t *testing.T) {
	t.Parallel()
	c := cachememory.New()
	defer func() { _ = c.Close() }()

	p := NewMessagePersister(PersisterConfig{
		Queue:   NewCacheQueue(c, 0),
		Store:   &recordingMessageStore{},
		Devices: &fixedDeviceLister{}, // empty
		Logger:  quietLogger(),
	})
	if err := p.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce no-op: %v", err)
	}
}

func TestMessagePersister_RunOnce_ListDevicesError_Propagated(t *testing.T) {
	t.Parallel()
	c := cachememory.New()
	defer func() { _ = c.Close() }()

	boom := errors.New("list boom")
	p := NewMessagePersister(PersisterConfig{
		Queue:   NewCacheQueue(c, 0),
		Store:   &recordingMessageStore{},
		Devices: &fixedDeviceLister{err: boom},
		Logger:  quietLogger(),
	})
	err := p.RunOnce(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("expected list-devices error to propagate, got %v", err)
	}
}

func TestMessagePersister_RunOnce_StoreError_LogsButContinues(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := cachememory.New()
	defer func() { _ = c.Close() }()

	q := NewCacheQueue(c, 0)
	for _, env := range []*Envelope{newEnv("a", 1)} {
		_ = q.Enqueue(ctx, "u1", 1, env)
		_ = q.Enqueue(ctx, "u2", 1, env)
	}

	store := &recordingMessageStore{insertErr: errors.New("store boom")}
	devices := &fixedDeviceLister{devices: []DeviceRef{
		{UUID: "u1", DeviceID: 1},
		{UUID: "u2", DeviceID: 1},
	}}

	p := NewMessagePersister(PersisterConfig{Queue: q, Store: store, Devices: devices, Logger: quietLogger()})

	// Per-device errors should not bubble up — they are logged and we
	// move on to the next device. RunOnce returns nil even though
	// every device failed.
	if err := p.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce should swallow per-device errors, got %v", err)
	}
	// Cache still has the messages because Insert failed.
	n1, _ := q.Len(ctx, "u1", 1)
	n2, _ := q.Len(ctx, "u2", 1)
	if n1 != 1 || n2 != 1 {
		t.Fatalf("expected cached messages to remain after store error: u1=%d u2=%d", n1, n2)
	}
}

func TestMessagePersister_RunOnce_RequiredFieldsMissing_Errors(t *testing.T) {
	t.Parallel()
	p := NewMessagePersister(PersisterConfig{
		// no Queue / Store / Devices
		Logger: quietLogger(),
	})
	if err := p.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when persister is unconfigured")
	}
}

func TestMessagePersister_RunOnce_ContextCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := cachememory.New()
	defer func() { _ = c.Close() }()
	q := NewCacheQueue(c, 0)
	_ = q.Enqueue(context.Background(), "u1", 1, newEnv("a", 1))

	p := NewMessagePersister(PersisterConfig{
		Queue:   q,
		Store:   &recordingMessageStore{},
		Devices: &fixedDeviceLister{devices: []DeviceRef{{UUID: "u1", DeviceID: 1}}},
		Logger:  quietLogger(),
	})

	// A cancelled context returned from the lister loop should
	// produce a context error from RunOnce.
	err := p.RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestMessagePersister_DefaultMaxPerDevice(t *testing.T) {
	t.Parallel()
	p := NewMessagePersister(PersisterConfig{
		Queue:   NewCacheQueue(cachememory.New(), 0),
		Store:   &recordingMessageStore{},
		Devices: &fixedDeviceLister{},
		// MaxPerDevice unset
		Logger: quietLogger(),
	})
	if p.maxPerDevice != 100 {
		t.Fatalf("expected default 100, got %d", p.maxPerDevice)
	}
}
