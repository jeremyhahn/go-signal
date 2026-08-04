package accounts

import (
	"context"
	"sync"
	"sync/atomic"
)

// DirectoryEventKind classifies an account mutation for downstream
// directory consumers. Created and Updated both map to "upsert this
// row" on the wire; the distinction is kept here so future consumers
// (e.g. push-notification fan-out) can differentiate.
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

// DirectoryEventBus is an in-process publish-subscribe channel for
// account mutations. It is safe for concurrent use by an unbounded
// number of publishers and subscribers.
//
// The bus does NOT retain history. Subscribers are delivered every
// event published after Subscribe returned; events published before
// are not replayed. This is intentional — the directory protocol's
// production pattern is "snapshot via ListAll, then live-tail" and
// retention on the publisher would duplicate state that already
// exists in the underlying store.
//
// Resume tokens carried in DirectoryEvent.Seq are still monotonic so
// downstream consumers can detect gaps and either resync from the
// snapshot or surface the inconsistency.
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

// Done closes when the subscription terminates (Close called, the
// bus detached the subscriber due to overflow, or the subscribing
// context was cancelled). Always check Overflowed afterwards to
// distinguish slow-consumer overflow from clean shutdown.
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

// Subscribe registers a new subscriber with the given buffer size.
// Returns the subscription and the bus's current sequence number at
// registration time — callers should treat that value as the
// "snapshot as-of" cursor when reconciling against a parallel
// ListAll snapshot.
//
// bufSize must be > 0. A larger buffer tolerates slower consumers
// at the cost of memory; a smaller buffer detaches faster under
// load. Production deployments typically use 1024.
//
// The subscription is automatically closed when ctx is cancelled.
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

// Publish assigns a fresh sequence number to event and fans it out
// to every live subscriber. Subscribers whose buffer is full at
// publish time are detached and marked Overflowed; this prevents one
// slow consumer from blocking publishers.
//
// kind must be one of DirectoryEventCreated, DirectoryEventUpdated,
// DirectoryEventDeleted. account may be nil for Deleted events; it
// must be non-nil for the other two kinds and is shallow-copied
// before fan-out so subsequent mutations on the caller's copy do
// not race with subscribers.
func (b *DirectoryEventBus) Publish(kind DirectoryEventKind, uuid string, account *Account) {
	if uuid == "" {
		return
	}
	var snapshot *Account
	if account != nil {
		// Shallow copy is enough — directory consumers only read
		// UUID/Number/PNI which are scalars. Devices and other
		// pointer-typed fields are not read by the directory
		// surface, so aliasing them is fine.
		acc := *account
		snapshot = &acc
	}

	b.mu.Lock()
	// Assign the sequence number under the lock so that the order in which
	// events are delivered to subscribers matches their Seq order. Assigning
	// it before acquiring the lock allowed a publisher holding seq=N to be
	// preempted by one holding seq=N+1, delivering N+1 first and causing
	// consumers to interpret the gap as a missed event.
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
