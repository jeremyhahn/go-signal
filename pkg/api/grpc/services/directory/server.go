// Package directory implements signald's internal gRPC
// DirectoryService that cdsi calls on startup to populate its local
// lookup index. Per the Phase 4.3 plan, cdsi never reaches into
// signald's account storage directly — every read goes through this
// surface so production deployments can run the two binaries with
// signald + cdsi on separate hosts joined by mTLS gRPC.
package directory

import (
	"context"
	"encoding/binary"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
)

// AccountSource is the read surface the gRPC server consumes. signald
// implements it on top of accounts.AccountsManager; tests use the
// in-memory MemorySource below.
type AccountSource interface {
	// ListAll streams every directory entry to fn. fn returns an error
	// to abort early. Implementations must not assume ordering and may
	// re-emit entries if the underlying snapshot races with writes.
	ListAll(ctx context.Context, fn func(DirectoryEntry) error) error
}

// DirectoryEntry is the value the AccountSource yields. Wire-mapped
// directly onto dirpb.DirectoryEntry by the gRPC server.
type DirectoryEntry struct {
	E164      uint64
	ACI       [16]byte
	PNI       [16]byte
	AccessKey [16]byte
}

// ChangeEventKind classifies a live mutation. UPSERT means "store
// this entry"; DELETE means "drop the row for this UUID".
type ChangeEventKind int

const (
	// ChangeEventUpsert means create-or-update the entry.
	ChangeEventUpsert ChangeEventKind = 1
	// ChangeEventDelete means drop the entry identified by UUID.
	ChangeEventDelete ChangeEventKind = 2
)

// ChangeEvent is one mutation delivered by an EventSource. UUID is
// always populated; Entry is populated for Upsert and zero for
// Delete. Seq is a monotonic cursor consumers can persist as a
// resume token.
type ChangeEvent struct {
	Seq   uint64
	Kind  ChangeEventKind
	UUID  string
	Entry DirectoryEntry
}

// EventSubscription is the consumer side of a server-side
// subscription handed to the gRPC Subscribe handler.
type EventSubscription interface {
	// Events delivers live mutations until the subscription
	// terminates. The channel is closed when Done closes.
	Events() <-chan ChangeEvent
	// Done closes when the subscription terminates (consumer
	// cancelled, slow-consumer detach, source shutdown).
	Done() <-chan struct{}
	// Overflowed reports whether the subscription terminated due
	// to slow-consumer overflow. Set before Done closes.
	Overflowed() bool
	// Close detaches the subscription. Idempotent.
	Close()
}

// EventSource is the optional change-event surface that drives the
// Subscribe RPC. signald implements it on top of the accounts event
// bus. When NewServer is constructed without an EventSource,
// Subscribe returns codes.Unimplemented — consumers fall back to
// periodic ListEntries polling.
type EventSource interface {
	// Subscribe returns a live subscription and the "as-of"
	// sequence number captured at subscription time. Events
	// published after that point arrive on the returned channel.
	// The buffer parameter bounds the per-subscriber in-flight
	// event queue; production callers use 1024+.
	Subscribe(ctx context.Context, buffer int) (EventSubscription, uint64)
}

// defaultSubscribeBuffer is the per-subscriber event-channel
// capacity used when no override is supplied via
// WithSubscribeBuffer. 1024 absorbs typical traffic bursts without
// pinning excessive heap per active stream.
const defaultSubscribeBuffer = 1024

// Server implements dirpb.DirectoryServiceServer.
type Server struct {
	dirpb.UnimplementedDirectoryServiceServer
	source        AccountSource
	events        EventSource
	subBufferSize int
	keepAlive     time.Duration
}

// NewServer constructs a Server backed by source. The optional
// EventSource activates live change replication on Subscribe; pass
// nil to fall back to Unimplemented (clients must poll ListEntries).
func NewServer(source AccountSource, opts ...ServerOption) *Server {
	if source == nil {
		panic("directory: AccountSource is required")
	}
	s := &Server{
		source:        source,
		subBufferSize: defaultSubscribeBuffer,
		keepAlive:     30 * time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ServerOption configures a Server at construction time.
type ServerOption func(*Server)

// WithEventSource wires an EventSource for live Subscribe replication.
func WithEventSource(es EventSource) ServerOption {
	return func(s *Server) { s.events = es }
}

// WithSubscribeBuffer overrides the per-subscriber event-channel
// capacity used inside the Subscribe RPC. Increase for bursty
// deployments or slow consumers; decrease to bound per-stream
// memory. Values <= 0 leave the default in place.
func WithSubscribeBuffer(n int) ServerOption {
	return func(s *Server) {
		if n > 0 {
			s.subBufferSize = n
		}
	}
}

// WithSubscribeKeepAlive overrides the cadence at which Subscribe
// emits a resume-token-only frame during idle live phases. Clients
// rely on these frames to persist a fresh cursor without waiting
// for the next mutation. Values <= 0 leave the default in place.
func WithSubscribeKeepAlive(d time.Duration) ServerOption {
	return func(s *Server) {
		if d > 0 {
			s.keepAlive = d
		}
	}
}

// ListEntries server-streams the current directory snapshot.
func (s *Server) ListEntries(_ *dirpb.ListEntriesRequest, stream dirpb.DirectoryService_ListEntriesServer) error {
	return s.source.ListAll(stream.Context(), func(e DirectoryEntry) error {
		return stream.Send(&dirpb.DirectoryEntry{
			E164:      e.E164,
			Aci:       append([]byte(nil), e.ACI[:]...),
			Pni:       append([]byte(nil), e.PNI[:]...),
			AccessKey: append([]byte(nil), e.AccessKey[:]...),
		})
	})
}

// Subscribe drives the live change-event stream.
//
// Protocol:
//
//  1. Capture the bus's current sequence under the subscription
//     atom — events with Seq > asOf arrive on the live channel.
//  2. Stream a full ListAll snapshot as UPSERT events, tagging each
//     with the captured asOf so cdsi treats them as a coherent
//     point-in-time view.
//  3. Drain live events from the subscription channel, forwarding
//     each to the gRPC stream. Periodically emit a resume token
//     (every Nth event, plus on stream end) so reconnecting
//     consumers can resume without re-snapshotting if their cursor
//     is recent enough.
//
// resume_token in the request is the big-endian uint64 cursor the
// client last received. When present and the bus's history can
// honor it, the server skips step 2. The current implementation
// always snapshots — bus retention is left for a follow-on; clients
// already handle the conservative "treat snapshot as authoritative"
// behaviour because each entry carries a deterministic UUID/E164.
func (s *Server) Subscribe(req *dirpb.SubscribeRequest, stream dirpb.DirectoryService_SubscribeServer) error {
	if s.events == nil {
		return status.Error(codes.Unimplemented, "directory: Subscribe not configured (no EventSource)")
	}

	ctx := stream.Context()
	sub, asOf := s.events.Subscribe(ctx, s.subBufferSize)
	defer sub.Close()

	resumeFrom := decodeResumeToken(req.GetResumeToken())

	// Snapshot phase. When the client supplied a resume token and
	// it is at or past the bus's current sequence, skip the
	// snapshot — there is nothing new prior to the live tail.
	snapshotShipped := false
	if resumeFrom == 0 || resumeFrom < asOf {
		if err := s.streamSnapshot(stream, asOf); err != nil {
			return err
		}
		snapshotShipped = true
	}

	// Live phase. Resume tokens are emitted ONLY in the live phase
	// (piggy-backed on the first live event past asOf, on every
	// tokenInterval-th subsequent event, and from the keep-alive
	// ticker during idle windows). The previous design emitted a
	// resume token immediately after the snapshot — that allowed a
	// client whose snapshot got interrupted mid-stream to persist
	// the asOf cursor, then skip the snapshot on reconnect and
	// silently lose the rows it never received.
	const tokenInterval = 32
	since := asOf
	emitted := 0
	resumeTokenPending := snapshotShipped // first live frame must carry the token
	keepAlive := time.NewTicker(s.keepAlive)
	defer keepAlive.Stop()
	for {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-sub.Done():
			if sub.Overflowed() {
				return status.Error(codes.ResourceExhausted, "directory: subscription overflowed — reconnect to resync")
			}
			return nil
		case <-keepAlive.C:
			// Emit a token-only frame so idle streams still
			// give clients a fresh cursor to persist. The
			// cursor is the most recent sequence we've
			// actually delivered, which is exactly `since`.
			if err := stream.Send(&dirpb.DirectoryChangeEvent{ResumeToken: encodeResumeToken(since)}); err != nil {
				return err
			}
		case e, ok := <-sub.Events():
			if !ok {
				return nil
			}
			if e.Seq <= since {
				// Defensive: never emit retrograde events.
				continue
			}
			msg := changeEventToProto(e)
			emitted++
			if resumeTokenPending || emitted%tokenInterval == 0 {
				msg.ResumeToken = encodeResumeToken(e.Seq)
				resumeTokenPending = false
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
			since = e.Seq
		}
	}
}

// streamSnapshot ships the full directory as UPSERT events with the
// snapshot's "as-of" cursor.
func (s *Server) streamSnapshot(stream dirpb.DirectoryService_SubscribeServer, asOf uint64) error {
	return s.source.ListAll(stream.Context(), func(e DirectoryEntry) error {
		return stream.Send(&dirpb.DirectoryChangeEvent{
			Kind:  dirpb.DirectoryChangeEvent_KIND_UPSERT,
			Entry: directoryEntryToProto(e),
		})
	})
}

// changeEventToProto serializes a ChangeEvent for the wire.
func changeEventToProto(e ChangeEvent) *dirpb.DirectoryChangeEvent {
	msg := &dirpb.DirectoryChangeEvent{}
	switch e.Kind {
	case ChangeEventDelete:
		msg.Kind = dirpb.DirectoryChangeEvent_KIND_DELETE
		// Delete events still carry an Entry with at least the
		// identifying ACI so the consumer can apply it; E164 / PNI /
		// AccessKey are zero.
		msg.Entry = directoryEntryToProto(e.Entry)
	default:
		msg.Kind = dirpb.DirectoryChangeEvent_KIND_UPSERT
		msg.Entry = directoryEntryToProto(e.Entry)
	}
	return msg
}

func directoryEntryToProto(e DirectoryEntry) *dirpb.DirectoryEntry {
	return &dirpb.DirectoryEntry{
		E164:      e.E164,
		Aci:       append([]byte(nil), e.ACI[:]...),
		Pni:       append([]byte(nil), e.PNI[:]...),
		AccessKey: append([]byte(nil), e.AccessKey[:]...),
	}
}

func encodeResumeToken(seq uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return b
}

func decodeResumeToken(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// MemorySource is a slice-backed AccountSource for tests.
type MemorySource struct {
	entries []DirectoryEntry
}

// NewMemorySource constructs a MemorySource seeded with entries.
func NewMemorySource(entries []DirectoryEntry) *MemorySource {
	return &MemorySource{entries: append([]DirectoryEntry(nil), entries...)}
}

// ListAll implements AccountSource.
func (m *MemorySource) ListAll(ctx context.Context, fn func(DirectoryEntry) error) error {
	for _, e := range m.entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}
