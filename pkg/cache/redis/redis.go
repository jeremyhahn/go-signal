// Package redis implements cache.Client against a real Redis server via
// github.com/redis/go-redis/v9.
package redis

import (
	"context"
	"errors"
	"time"

	redisv9 "github.com/redis/go-redis/v9"

	"github.com/jeremyhahn/go-signal/pkg/cache"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Client wraps a *redis.Client to satisfy cache.Client.
type Client struct {
	rdb *redisv9.Client
}

// Compile-time interface check.
var _ cache.Client = (*Client)(nil)

// Config holds connection parameters for the Redis client.
type Config struct {
	// URL is the Redis connection URL, e.g. "redis://localhost:6379/0".
	URL string
	// Password is the AUTH password (may be empty).
	Password string
	// DB is the database index to select after connecting.
	DB int
	// DialTimeout bounds the initial TCP dial.
	DialTimeout time.Duration
	// ReadTimeout / WriteTimeout bound per-operation I/O.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// New returns a Client connected according to cfg. It does not perform a
// connection test — callers should call Ping to verify.
func New(cfg Config) (*Client, error) {
	opts, err := redisv9.ParseURL(cfg.URL)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "redis: parse URL", err)
	}
	if cfg.Password != "" {
		opts.Password = cfg.Password
	}
	if cfg.DB != 0 {
		opts.DB = cfg.DB
	}
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = cfg.DialTimeout
	}
	if cfg.ReadTimeout > 0 {
		opts.ReadTimeout = cfg.ReadTimeout
	}
	if cfg.WriteTimeout > 0 {
		opts.WriteTimeout = cfg.WriteTimeout
	}
	return &Client{rdb: redisv9.NewClient(opts)}, nil
}

// NewFromClient wraps an externally-constructed *redis.Client so callers
// who need custom options (e.g. TLS, cluster mode) can configure their
// own client and still get our Client interface on top.
func NewFromClient(rdb *redisv9.Client) *Client {
	return &Client{rdb: rdb}
}

// --- Keyed values -----------------------------------------------------

// Set stores a value with optional TTL.
func (c *Client) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.rdb.Set(ctx, key, value, ttl).Err()
}

// Get retrieves a value. Maps redis.Nil to cache.ErrKeyNotFound.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := c.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, redisv9.Nil) {
		return nil, cache.ErrKeyNotFound
	}
	return v, err
}

// Del removes one or more keys.
func (c *Client) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.rdb.Del(ctx, keys...).Err()
}

// Exists reports presence of a key.
func (c *Client) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, key).Result()
	return n > 0, err
}

// Expire updates TTL on an existing key.
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return c.rdb.Expire(ctx, key, ttl).Result()
}

// TTL returns the remaining TTL; zero when the key has no expiration or
// does not exist (Redis returns -1 and -2 respectively — we normalize to 0).
func (c *Client) TTL(ctx context.Context, key string) (time.Duration, error) {
	d, err := c.rdb.TTL(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, nil
	}
	return d, nil
}

// --- Counters ---------------------------------------------------------

// Incr atomically increments by 1.
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
	return c.rdb.Incr(ctx, key).Result()
}

// IncrBy atomically increments by delta.
func (c *Client) IncrBy(ctx context.Context, key string, delta int64) (int64, error) {
	return c.rdb.IncrBy(ctx, key, delta).Result()
}

// --- Distributed locks ------------------------------------------------

// Lock acquires a distributed lock using SET NX EX semantics.
// SetArgs with Mode "NX" is used in place of the deprecated SetNX method.
// When the key already exists, Redis returns nil; go-redis surfaces this as
// redisv9.Nil which we map to cache.ErrLockNotAcquired.
func (c *Client) Lock(ctx context.Context, key, token string, ttl time.Duration) error {
	_, err := c.rdb.SetArgs(ctx, key, token, redisv9.SetArgs{
		Mode: "NX",
		TTL:  ttl,
	}).Result()
	if errors.Is(err, redisv9.Nil) {
		return cache.ErrLockNotAcquired
	}
	return err
}

// unlockScript releases a lock only when the stored token matches. Running
// this as a Lua script ensures the compare-and-delete is atomic on the
// Redis side.
const unlockScript = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`

// Unlock releases a lock if and only if the value matches token.
func (c *Client) Unlock(ctx context.Context, key, token string) error {
	_, err := c.rdb.Eval(ctx, unlockScript, []string{key}, token).Result()
	if errors.Is(err, redisv9.Nil) {
		return nil
	}
	return err
}

// --- Sorted sets ------------------------------------------------------

// ZAdd inserts scored members.
func (c *Client) ZAdd(ctx context.Context, key string, members ...cache.ScoredMember) error {
	if len(members) == 0 {
		return nil
	}
	zs := make([]redisv9.Z, len(members))
	for i, m := range members {
		zs[i] = redisv9.Z{Score: m.Score, Member: m.Member}
	}
	return c.rdb.ZAdd(ctx, key, zs...).Err()
}

// ZRange returns members by index.
func (c *Client) ZRange(ctx context.Context, key string, start, stop int64) ([][]byte, error) {
	vals, err := c.rdb.ZRange(ctx, key, start, stop).Result()
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(vals))
	for i, v := range vals {
		out[i] = []byte(v)
	}
	return out, nil
}

// ZRem removes members.
func (c *Client) ZRem(ctx context.Context, key string, members ...[]byte) error {
	if len(members) == 0 {
		return nil
	}
	args := make([]interface{}, len(members))
	for i, m := range members {
		args[i] = m
	}
	return c.rdb.ZRem(ctx, key, args...).Err()
}

// ZCard returns cardinality.
func (c *Client) ZCard(ctx context.Context, key string) (int64, error) {
	return c.rdb.ZCard(ctx, key).Result()
}

// --- Hashes -----------------------------------------------------------

// HSet sets a hash field.
func (c *Client) HSet(ctx context.Context, key, field string, value []byte) error {
	return c.rdb.HSet(ctx, key, field, value).Err()
}

// HGet retrieves a hash field.
func (c *Client) HGet(ctx context.Context, key, field string) ([]byte, error) {
	v, err := c.rdb.HGet(ctx, key, field).Bytes()
	if errors.Is(err, redisv9.Nil) {
		return nil, cache.ErrKeyNotFound
	}
	return v, err
}

// HDel removes hash fields.
func (c *Client) HDel(ctx context.Context, key string, fields ...string) error {
	if len(fields) == 0 {
		return nil
	}
	return c.rdb.HDel(ctx, key, fields...).Err()
}

// HLen returns the number of fields in the hash at key.
func (c *Client) HLen(ctx context.Context, key string) (int64, error) {
	return c.rdb.HLen(ctx, key).Result()
}

// --- Pub/sub ----------------------------------------------------------

// Publish delivers a message to subscribers.
func (c *Client) Publish(ctx context.Context, channel string, message []byte) (int64, error) {
	return c.rdb.Publish(ctx, channel, message).Result()
}

// Subscribe returns a subscription delivering messages from channels.
func (c *Client) Subscribe(ctx context.Context, channels ...string) (cache.Subscription, error) {
	ps := c.rdb.Subscribe(ctx, channels...)
	// Wait for the subscribe confirmation so the caller can assume the
	// subscription is active when Subscribe returns.
	if _, err := ps.Receive(ctx); err != nil {
		_ = ps.Close()
		return nil, err
	}
	out := make(chan cache.Message, 64)
	done := make(chan struct{})
	go func() {
		defer close(out)
		ch := ps.Channel()
		for {
			select {
			case <-done:
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				out <- cache.Message{Channel: msg.Channel, Payload: []byte(msg.Payload)}
			}
		}
	}()
	return &subscription{ps: ps, out: out, done: done}, nil
}

type subscription struct {
	ps     *redisv9.PubSub
	out    chan cache.Message
	done   chan struct{}
	closed bool
}

func (s *subscription) Channel() <-chan cache.Message { return s.out }

func (s *subscription) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.done)
	return s.ps.Close()
}

// --- Scripts ----------------------------------------------------------

// Eval runs a Lua script.
func (c *Client) Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
	return c.rdb.Eval(ctx, script, keys, args...).Result()
}

// --- Lifecycle -------------------------------------------------------

// Ping checks connectivity.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// Close releases the underlying connection pool.
func (c *Client) Close() error {
	return c.rdb.Close()
}
