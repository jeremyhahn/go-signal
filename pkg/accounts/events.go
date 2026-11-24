package accounts

import (
	"context"
	"sync"
	"sync/atomic"
)

// DirectoryEventKind classifies an account mutation; Created and Updated both mean upsert on the wire.
type DirectoryEventKind int

const (
	// DirectoryEventCreated is published when an account is created.
	DirectoryEventCreated DirectoryEventKind = 1
	// DirectoryEventUpdated is published when an existing account's
	// state changes in a way directory consumers care about (number,
	// PNI, discoverability, deletion of a displaced number-holder).
	DirectoryEventUpdated DirectoryEventKind = 2
	// DirectoryEventDeleted is published when an account is removed.
	DirectoryEventDeleted DirectoryEventKind = 3
)

// DirectoryEvent is one mutation in the directory change log.
type DirectoryEvent struct {
	// Seq is a process-monotonic sequence number assigned at Publish
	// time. Subscribers use it as an opaque resume cursor.
	Seq uint64
	// Kind classifies the mutation.
	Kind DirectoryEventKind
	// UUID is the affected account's UUID (always populated, including
	// for Deleted events).
	UUID string
	// Account is the post-mutation snapshot for Created/Updated, or
	// nil for Deleted.
	Account *Account
}

// DirectoryEventBus is a concurrent in-process pub-sub for account mutations; it keeps no history, and Seq is monotonic so consumers can detect gaps.
type DirectoryEventBus struct {
	nextSeq atomic.Uint64

	mu   sync.Mutex
	subs map[*Subscription]struct{}
}

// NewDirectoryEventBus constructs an empty bus.
func NewDirectoryEventBus() *DirectoryEventBus {
	return &DirectoryEventBus{
		subs: make(map[*Subscription]struct{}),
	}
}

// Subscription is the consumer side of a bus subscription.
type Subscription struct {
	bus      *DirectoryEventBus
	events   chan DirectoryEvent
	done     chan struct{}
	closeOne sync.Once
	// overflowed records whether the subscription was terminated
	// because the receiver was too slow. Distinct from a clean Close
	// so clients can decide to resync vs. retry.
	overflowed atomic.Bool
}

// Events returns the channel events are delivered on. The channel is
// closed after Done's channel closes — receivers should select on
// both. Buffered to the size passed to Subscribe.
func (s *Subscription) Events() <-chan DirectoryEvent { return s.events }

// Done closes when the subscription ends; check Overflowed to tell a slow-consumer detach from a clean close.
func (s *Subscription) Done() <-chan struct{} { return s.done }

// Overflowed reports whether the subscription terminated because the
// receiver fell behind. Callers must resync from a fresh snapshot
// before re-subscribing if this is true.
func (s *Subscription) Overflowed() bool { return s.overflowed.Load() }

// Close detaches the subscription from the bus and releases its
// buffer. Idempotent.
func (s *Subscription) Close() {
	s.bus.detach(s)
}

// Subscribe registers a subscriber with bufSize > 0 and returns the bus sequence as the snapshot cursor; ctx cancellation closes it.
func (b *DirectoryEventBus) Subscribe(ctx context.Context, bufSize int) (*Subscription, uint64) {
	if bufSize <= 0 {
		bufSize = 1
	}
	sub := &Subscription{
		bus:    b,
		events: make(chan DirectoryEvent, bufSize),
		done:   make(chan struct{}),
	}
	b.mu.Lock()
	currentSeq := b.nextSeq.Load()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()

	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				b.detach(sub)
			case <-sub.done:
			}
		}()
	}

	return sub, currentSeq
}

// detach removes sub from the bus, closes its event channel, and
// signals Done. Idempotent — repeat calls are no-ops.
func (b *DirectoryEventBus) detach(sub *Subscription) {
	sub.closeOne.Do(func() {
		b.mu.Lock()
		delete(b.subs, sub)
		b.mu.Unlock()
		close(sub.events)
		close(sub.done)
	})
}

// LatestSeq returns the most recently assigned sequence number, or 0
// if no events have been published yet. Useful for tests and for
// callers that want to capture "as-of" cursors without subscribing.
func (b *DirectoryEventBus) LatestSeq() uint64 { return b.nextSeq.Load() }

// Publish assigns the next sequence and fans out a shallow copy; subscribers with a full buffer are detached as Overflowed. account may be nil only for Deleted.
func (b *DirectoryEventBus) Publish(kind DirectoryEventKind, uuid string, account *Account) {
	if uuid == "" {
		return
	}
	var snapshot *Account
	if account != nil {
		// A shallow copy suffices: consumers read only UUID, Number and PNI.
		acc := *account
		snapshot = &acc
	}

	b.mu.Lock()
	// Assign the sequence under the lock so delivery order matches Seq order.
	event := DirectoryEvent{
		Seq:     b.nextSeq.Add(1),
		Kind:    kind,
		UUID:    uuid,
		Account: snapshot,
	}
	detached := make([]*Subscription, 0)
	for sub := range b.subs {
		select {
		case sub.events <- event:
		default:
			sub.overflowed.Store(true)
			detached = append(detached, sub)
		}
	}
	b.mu.Unlock()

	for _, sub := range detached {
		b.detach(sub)
	}
}
