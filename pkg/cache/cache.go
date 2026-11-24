package cache

import (
	"context"
	"errors"
	"time"
)

// ErrKeyNotFound is returned when a Get-style operation finds no entry.
// Operations that naturally express absence (Exists, TTL, Len) do not use
// this sentinel — they return zero values instead.
var ErrKeyNotFound = errors.New("cache: key not found")

// ErrLockNotAcquired is returned by Lock when the underlying SET NX did
// not acquire the lock. This is the expected path when another instance
// already holds the lock; callers should not treat it as a failure.
var ErrLockNotAcquired = errors.New("cache: lock not acquired")

// Client is the Redis-shaped cache interface the go-signal services
// depend on. Implementations must be safe for concurrent use from many
// goroutines.
//
// Methods take a [context.Context] for cancellation and deadline
// propagation. TTL-bearing operations accept a duration; passing zero means
// no expiration.
type Client interface {
	// --- Keyed values -----------------------------------------------------

	// Set stores value at key, with an optional TTL. A zero ttl disables
	// expiration.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Get retrieves the value stored at key. Returns ErrKeyNotFound when
	// the key is absent or has expired.
	Get(ctx context.Context, key string) ([]byte, error)

	// Del removes one or more keys. Deleting a missing key is not an error.
	Del(ctx context.Context, keys ...string) error

	// Exists reports whether key has a non-expired value.
	Exists(ctx context.Context, key string) (bool, error)

	// Expire updates the TTL of an existing key. Returns (false, nil) when
	// the key does not exist.
	Expire(ctx context.Context, key string, ttl time.Duration) (bool, error)

	// TTL returns the remaining TTL on key. A zero duration is returned
	// when the key does not exist or has no expiration; callers can
	// disambiguate via Exists if needed.
	TTL(ctx context.Context, key string) (time.Duration, error)

	// --- Counters ---------------------------------------------------------

	// Incr atomically increments the integer value stored at key by one
	// and returns the new value. If the key does not exist it is set to
	// 1 with no TTL; callers must Expire it explicitly for rate-limit
	// semantics.
	Incr(ctx context.Context, key string) (int64, error)

	// IncrBy atomically increments the integer stored at key by delta and
	// returns the new value.
	IncrBy(ctx context.Context, key string, delta int64) (int64, error)

	// --- Distributed locks -----------------------------------------------

	// Lock attempts to acquire a lock by setting key to token with the
	// given TTL, only if the key does not already exist (SET NX EX).
	// Returns ErrLockNotAcquired when another holder owns it.
	Lock(ctx context.Context, key, token string, ttl time.Duration) error

	// Unlock releases a lock previously acquired by Lock, but only if the
	// current value matches the given token. Releasing another holder's
	// lock (which would indicate TTL expiration) is a no-op.
	Unlock(ctx context.Context, key, token string) error

	// --- Sorted sets (per-device message queues) --------------------------

	// ZAdd inserts members into the sorted set at key with the given score.
	ZAdd(ctx context.Context, key string, members ...ScoredMember) error

	// ZRange returns members in the sorted set at key in [start, stop]
	// index order (0 = first, -1 = last), ordered by ascending score.
	ZRange(ctx context.Context, key string, start, stop int64) ([][]byte, error)

	// ZRem removes members from the sorted set at key.
	ZRem(ctx context.Context, key string, members ...[]byte) error

	// ZCard returns the number of members in the sorted set at key, or 0
	// if absent.
	ZCard(ctx context.Context, key string) (int64, error)

	// --- Hashes (MRM shared payloads) ------------------------------------

	// HSet sets hash field to value at key.
	HSet(ctx context.Context, key, field string, value []byte) error

	// HGet retrieves a hash field. Returns ErrKeyNotFound when the hash or
	// field is absent.
	HGet(ctx context.Context, key, field string) ([]byte, error)

	// HDel removes one or more fields from the hash at key.
	HDel(ctx context.Context, key string, fields ...string) error

	// HLen returns the number of fields in the hash at key.
	HLen(ctx context.Context, key string) (int64, error)

	// --- Pub/sub ---------------------------------------------------------

	// Publish delivers message on channel. Returns the number of
	// subscribers that received it.
	Publish(ctx context.Context, channel string, message []byte) (int64, error)

	// Subscribe returns a subscription that delivers messages published to
	// the given channels. Callers must Close the subscription when done.
	Subscribe(ctx context.Context, channels ...string) (Subscription, error)

	// --- Scripts ---------------------------------------------------------

	// Eval runs a Lua script with the given keys and args. Script
	// evaluation is atomic on the Redis side; the memory implementation
	// emulates this with a big mutex.
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) (interface{}, error)

	// --- Lifecycle -------------------------------------------------------

	// Ping checks connectivity. Used by readiness probes.
	Ping(ctx context.Context) error

	// Close releases resources held by the client.
	Close() error
}

// ScoredMember is a (score, value) pair used by ZAdd.
type ScoredMember struct {
	Score  float64
	Member []byte
}

// Subscription is a pub/sub subscription returned by Subscribe.
type Subscription interface {
	// Channel delivers messages published to any subscribed channel.
	// When the subscription is closed the channel is closed.
	Channel() <-chan Message

	// Close ends the subscription and closes the channel.
	Close() error
}

// Message is a pub/sub message.
type Message struct {
	Channel string
	Payload []byte
}
