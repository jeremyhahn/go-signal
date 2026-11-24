package cdsi

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// SubscribeConfig configures the live-replication loop.
type SubscribeConfig struct {
	// Client is the gRPC channel to signald's DirectoryService.
	Client dirpb.DirectoryServiceClient
	// Directory is the local index the loop applies events to.
	Directory *MemoryDirectory
	// Logger is the structured logger used for state transitions.
	// nil → slog.Default().
	Logger *slog.Logger
	// MinBackoff and MaxBackoff bound the exponential reconnect
	// schedule. Zero defaults: 1s / 30s.
	MinBackoff, MaxBackoff time.Duration
	// TokenStore persists resume tokens across reconnects + process
	// restarts. May be nil — the loop still runs but does a full
	// snapshot on every reconnect.
	TokenStore ResumeTokenStore
}

// ResumeTokenStore persists the subscribe resume cursor across reconnects and restarts; safe for concurrent use.
type ResumeTokenStore interface {
	Load(ctx context.Context) ([]byte, error)
	Save(ctx context.Context, token []byte) error
}

// MemoryResumeTokenStore is an in-process implementation. Useful for
// tests and for short-lived cdsi instances where token loss on
// restart is acceptable (the server falls back to snapshot+live).
type MemoryResumeTokenStore struct {
	mu    sync.Mutex
	token []byte
}

// NewMemoryResumeTokenStore constructs an empty in-memory store.
func NewMemoryResumeTokenStore() *MemoryResumeTokenStore {
	return &MemoryResumeTokenStore{}
}

// Load returns the most recently saved token, or nil if none.
func (s *MemoryResumeTokenStore) Load(_ context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.token...), nil
}

// Save replaces the stored token.
func (s *MemoryResumeTokenStore) Save(_ context.Context, token []byte) error {
	s.mu.Lock()
	s.token = append([]byte(nil), token...)
	s.mu.Unlock()
	return nil
}

// SubscribeAndApply replicates the directory until ctx ends, resubscribing with backoff from the saved token or a fresh snapshot; returns ctx.Err().
func SubscribeAndApply(ctx context.Context, cfg SubscribeConfig) error {
	if cfg.Client == nil {
		return errors.New("cdsi: SubscribeAndApply requires Client")
	}
	if cfg.Directory == nil {
		return errors.New("cdsi: SubscribeAndApply requires Directory")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	minBackoff := cfg.MinBackoff
	if minBackoff <= 0 {
		minBackoff = time.Second
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}

	backoff := minBackoff
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		token := loadToken(ctx, cfg.TokenStore)
		err := runOnce(ctx, cfg, token, logger)
		if err == nil || errors.Is(err, context.Canceled) {
			return ctx.Err()
		}
		if errors.Is(err, io.EOF) {
			// Server closed the stream cleanly. Reconnect
			// immediately without backoff — this is the common
			// graceful-shutdown / load-rebalance path.
			logger.Debug("directory subscribe: server closed stream; reconnecting")
			backoff = minBackoff
			continue
		}

		logger.WarnContext(ctx, "directory subscribe disconnected",
			slog.Any("error", err),
			slog.Duration("backoff", backoff))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runOnce subscribes once and forwards events until the stream
// ends. The caller handles reconnect / backoff.
func runOnce(ctx context.Context, cfg SubscribeConfig, token []byte, logger *slog.Logger) error {
	stream, err := cfg.Client.Subscribe(ctx, &dirpb.SubscribeRequest{ResumeToken: token})
	if err != nil {
		return err
	}

	// On a fresh subscription, clear local state before the first Recv so the snapshot is authoritative; keep it when resuming.
	if token == nil {
		if err := cfg.Directory.Replace(ctx, nil); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "cdsi: clear directory before fresh subscribe", err)
		}
	}

	// Track UUID to E.164 so ACI-only DELETE events can be applied.
	uuidIndex := make(map[[16]byte]uint64)

	// Repeated token save failures end the stream to force a reconnect.
	consecutiveTokenSaveFailures := 0
	const maxTokenSaveFailures = 5

	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		if err != nil {
			// Server signalled overflow → drop token, take a fresh snapshot.
			if status.Code(err) == codes.ResourceExhausted && cfg.TokenStore != nil {
				_ = cfg.TokenStore.Save(ctx, nil)
			}
			return err
		}
		if ev.GetEntry() != nil || ev.GetKind() != dirpb.DirectoryChangeEvent_KIND_UNSPECIFIED {
			applyEvent(cfg.Directory, ev, uuidIndex)
		}
		if t := ev.GetResumeToken(); len(t) > 0 && cfg.TokenStore != nil {
			if err := cfg.TokenStore.Save(ctx, t); err != nil {
				consecutiveTokenSaveFailures++
				logger.WarnContext(ctx, "persist resume token",
					slog.Int("consecutiveFailures", consecutiveTokenSaveFailures),
					slog.Any("error", err),
					slog.Uint64("seq", binary.BigEndian.Uint64(padTo8(t))))
				if consecutiveTokenSaveFailures >= maxTokenSaveFailures {
					return signalerrors.New(signalerrors.ErrInternal, "cdsi: token store has failed "+strconv.Itoa(consecutiveTokenSaveFailures)+" consecutive Save calls — aborting stream to trigger reconnect")
				}
			} else {
				consecutiveTokenSaveFailures = 0
			}
		}
	}
}

// applyEvent mutates dir based on a single change-event proto.
func applyEvent(dir *MemoryDirectory, ev *dirpb.DirectoryChangeEvent, uuidIndex map[[16]byte]uint64) {
	entry := protoEntry(ev.GetEntry())
	switch ev.GetKind() {
	case dirpb.DirectoryChangeEvent_KIND_UPSERT:
		dir.Upsert(entry)
		if entry.ACI != ([16]byte{}) {
			uuidIndex[entry.ACI] = entry.E164
		}
	case dirpb.DirectoryChangeEvent_KIND_DELETE:
		// Prefer E164 carried in the entry; fall back to ACI lookup.
		e164 := entry.E164
		if e164 == 0 && entry.ACI != ([16]byte{}) {
			if existing, ok := uuidIndex[entry.ACI]; ok {
				e164 = existing
			}
		}
		if e164 != 0 {
			dir.Delete(e164)
		}
		if entry.ACI != ([16]byte{}) {
			delete(uuidIndex, entry.ACI)
		}
	}
}

func protoEntry(p *dirpb.DirectoryEntry) Entry {
	entry := Entry{}
	if p == nil {
		return entry
	}
	entry.E164 = p.GetE164()
	copy(entry.ACI[:], p.GetAci())
	copy(entry.PNI[:], p.GetPni())
	copy(entry.AccessKey[:], p.GetAccessKey())
	return entry
}

func loadToken(ctx context.Context, store ResumeTokenStore) []byte {
	if store == nil {
		return nil
	}
	t, err := store.Load(ctx)
	if err != nil {
		return nil
	}
	return t
}

// padTo8 right-pads (or truncates to) 8 bytes so logging code can
// uint64-decode tokens without panicking on malformed values. Pure
// logging aid — the wire-side decoder lives in the directory server.
func padTo8(b []byte) []byte {
	if len(b) == 8 {
		return b
	}
	out := make([]byte, 8)
	if len(b) > 8 {
		copy(out, b[len(b)-8:])
	} else {
		copy(out[8-len(b):], b)
	}
	return out
}
