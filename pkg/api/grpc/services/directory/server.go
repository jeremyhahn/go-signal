// Package directory implements signald's internal gRPC DirectoryService, the only path cdsi reads accounts through.
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

// ChangeEventKind classifies a live mutation: UPSERT stores an entry, DELETE drops the row for a UUID.
type ChangeEventKind int

const (
	// ChangeEventUpsert means create-or-update the entry.
	ChangeEventUpsert ChangeEventKind = 1
	// ChangeEventDelete means drop the entry identified by UUID.
	ChangeEventDelete ChangeEventKind = 2
)

// ChangeEvent is one mutation; Entry is zero for Delete and Seq is a monotonic resume cursor.
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

// EventSource drives Subscribe; without one Subscribe returns Unimplemented and consumers poll ListEntries.
type EventSource interface {
	// Subscribe returns a live subscription and the sequence it was taken at; buffer bounds the per-subscriber queue.
	Subscribe(ctx context.Context, buffer int) (EventSubscription, uint64)
}

// defaultSubscribeBuffer is the per-subscriber event-channel capacity.
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

// WithSubscribeBuffer overrides the per-subscriber event-channel capacity; values <= 0 keep the default.
func WithSubscribeBuffer(n int) ServerOption {
	return func(s *Server) {
		if n > 0 {
			s.subBufferSize = n
		}
	}
}

// WithSubscribeKeepAlive overrides the idle resume-token frame interval; values <= 0 keep the default.
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

// Subscribe streams a full snapshot as UPSERT events tagged with the captured sequence, then live events with periodic resume tokens.
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

	// Resume tokens are emitted only in the live phase, so an interrupted snapshot is never skipped on reconnect.
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
			// Token-only frame: the cursor is the last delivered sequence.
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
