package workers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/cache"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// CacheLeaser is a Leaser backed by pkg/cache.Client. It uses the cache's
// Lock primitive (SET NX EX in Redis terms) to gate worker execution
// across replicas.
type CacheLeaser struct {
	cache cache.Client
	// prefix namespaces lease keys so they don't collide with other uses
	// of the same cache. Defaults to "workers:lease:".
	prefix string

	// tokens maps a lease key to the token this instance holds. Token
	// matching prevents releasing a lease the TTL had already expired
	// and another replica re-acquired.
	mu     sync.Mutex
	tokens map[string]string
}

// NewCacheLeaser constructs a CacheLeaser. prefix is optional; pass "" for
// the default.
func NewCacheLeaser(c cache.Client, prefix string) *CacheLeaser {
	if prefix == "" {
		prefix = "workers:lease:"
	}
	return &CacheLeaser{
		cache:  c,
		prefix: prefix,
		tokens: make(map[string]string),
	}
}

// Acquire tries to set the lease. On success it records the token so a
// later Release only succeeds for this holder.
func (l *CacheLeaser) Acquire(ctx context.Context, key string, ttl time.Duration) error {
	token, err := newToken()
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "workers: token", err)
	}
	fullKey := l.prefix + key
	if err := l.cache.Lock(ctx, fullKey, token, ttl); err != nil {
		if errors.Is(err, cache.ErrLockNotAcquired) {
			return ErrLeaderElectionFailed
		}
		return err
	}
	l.mu.Lock()
	l.tokens[fullKey] = token
	l.mu.Unlock()
	return nil
}

// Release unlocks the lease only when the stored token matches. Called
// after the worker run completes; if the TTL had already expired it's a
// safe no-op.
func (l *CacheLeaser) Release(ctx context.Context, key string) error {
	fullKey := l.prefix + key
	l.mu.Lock()
	token, ok := l.tokens[fullKey]
	delete(l.tokens, fullKey)
	l.mu.Unlock()
	if !ok {
		return nil
	}
	return l.cache.Unlock(ctx, fullKey, token)
}

// newToken returns a random 16-byte hex string.
func newToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
