package secrets

import (
	"context"
	"sync"
	"time"
)

// CachingResolver wraps another SecretResolver and caches its
// resolutions for a fixed TTL. After TTL expiry the next Resolve call
// re-fetches from the underlying resolver — this is how
// kms:// secrets pick up rotations: ops rotates the KMS-side key, the
// cache TTL elapses, the chat-server re-fetches and the new material
// goes live without a restart.
//
// One CachingResolver instance is shared across all callers; the
// underlying resolver MUST be safe for concurrent use (every shipping
// resolver is).
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

// Resolve returns a cached value when the TTL has not elapsed and
// otherwise delegates to the underlying resolver. The freshly fetched
// secret replaces the cached one; the previous SecureString is
// destroyed so its bytes don't sit in memory past the rotation point.
//
// Each call returns a fresh, independent copy of the cached secret. The cache
// retains sole ownership of the master entry (destroyed only on eviction,
// replacement, or Invalidate); callers own and must Destroy the copy they
// receive. Returning the shared instance would let the first caller's
// Destroy() poison the cache, after which later resolutions of the same URI
// would silently yield an empty secret.
func (c *CachingResolver) Resolve(ctx context.Context, uri string) (*SecureString, error) {
	c.mu.Lock()
	if entry, ok := c.entries[uri]; ok && c.clock().Before(entry.expiresAt) {
		// Clone, not a Plaintext round-trip: a cached secret that will not
		// open is an error here, where Plaintext's empty string would be
		// copied into an unset secret and reported as a successful resolve.
		dup, err := entry.secret.Clone(ctx)
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return dup, nil
	}
	c.mu.Unlock()

	// Cache miss or expired entry: re-fetch from the underlying
	// resolver. We don't hold the lock across the (potentially slow)
	// fetch — concurrent misses on the same URI may produce
	// duplicate fetches, but each caller still gets a correct fresh
	// secret. Single-flight is the next-level optimisation.
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
	dup, err := fresh.Clone(ctx)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return dup, nil
}

// Invalidate forces the next Resolve to re-fetch. Production
// deployments tie this to an out-of-band signal (signal HUP, admin
// endpoint, etc.) so an emergency rotation doesn't need to wait for
// the TTL.
func (c *CachingResolver) Invalidate(uri string) {
	c.mu.Lock()
	if entry, ok := c.entries[uri]; ok {
		entry.secret.Destroy()
		delete(c.entries, uri)
	}
	c.mu.Unlock()
}
