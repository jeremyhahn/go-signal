package secrets

import (
	"context"
	"sync"
	"time"
)

// CachingResolver caches another resolver's results for a TTL, so kms:// rotations take effect without a restart; the wrapped resolver must be concurrency-safe.
type CachingResolver struct {
	underlying SecretResolver
	ttl        time.Duration
	clock      func() time.Time

	mu      sync.Mutex
	entries map[string]cachedEntry
}

type cachedEntry struct {
	secret    *SecureString
	expiresAt time.Time
}

// NewCachingResolver wraps r with a TTL cache. ttl must be > 0;
// passing zero or negative is a programmer error and panics so a
// mis-configured wire doesn't silently leak stale credentials forever.
func NewCachingResolver(r SecretResolver, ttl time.Duration) *CachingResolver {
	if ttl <= 0 {
		panic("secrets: CachingResolver TTL must be positive")
	}
	if r == nil {
		panic("secrets: underlying resolver is required")
	}
	return &CachingResolver{
		underlying: r,
		ttl:        ttl,
		clock:      time.Now,
		entries:    make(map[string]cachedEntry),
	}
}

// Scheme proxies to the underlying resolver.
func (c *CachingResolver) Scheme() string { return c.underlying.Scheme() }

// Resolve returns a fresh copy of the cached secret, re-fetching after the TTL; the caller destroys its copy, the cache owns the master.
func (c *CachingResolver) Resolve(ctx context.Context, uri string) (*SecureString, error) {
	c.mu.Lock()
	if entry, ok := c.entries[uri]; ok && c.clock().Before(entry.expiresAt) {
		dup, err := NewOptionalSecureString(entry.secret.Plaintext())
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return dup, nil
	}
	c.mu.Unlock()

	// Miss or expired: fetch without the lock; concurrent misses may fetch twice.
	fresh, err := c.underlying.Resolve(ctx, uri)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if old, ok := c.entries[uri]; ok && old.secret != fresh {
		old.secret.Destroy()
	}
	c.entries[uri] = cachedEntry{
		secret:    fresh,
		expiresAt: c.clock().Add(c.ttl),
	}
	// Hand the caller an independent copy; the cache keeps and owns `fresh`.
	dup, err := NewOptionalSecureString(fresh.Plaintext())
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return dup, nil
}

// Invalidate forces the next Resolve to re-fetch.
func (c *CachingResolver) Invalidate(uri string) {
	c.mu.Lock()
	if entry, ok := c.entries[uri]; ok {
		entry.secret.Destroy()
		delete(c.entries, uri)
	}
	c.mu.Unlock()
}
