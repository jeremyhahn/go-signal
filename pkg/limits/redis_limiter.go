package limits

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/cache"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// RedisTokenBucketLimiter is a token-bucket limiter whose state lives
// in Redis (or any pkg/cache.Client backend). Unlike
// TokenBucketLimiter — which holds buckets in a process-local sync.Map
// — this implementation shares the bucket across every signald
// replica so a request bouncing across instances still consumes from
// the same allowance. Java's reference rate-limiter uses the same
// Lua-script atomic-decrement pattern.
//
// The Lua script is the only place the state machine runs: it reads
// the (tokens, lastRefill) tuple, advances tokens by elapsed-time *
// refill-rate (clamped to BucketSize), decrements by n, and writes
// back. The entire sequence is atomic on the Redis side; concurrent
// callers from different replicas can't race.
type RedisTokenBucketLimiter struct {
	cfg    BucketConfig
	cache  cache.Client
	prefix string
	// nowMillis is injectable for tests; production uses time.Now.
	nowMillis func() int64
}

// RedisLimiterConfig configures a RedisTokenBucketLimiter.
type RedisLimiterConfig struct {
	Bucket BucketConfig
	// Cache is the backing cache.Client (Redis in production,
	// miniredis-backed pkg/cache/redis client in tests).
	Cache cache.Client
	// KeyPrefix namespaces bucket keys so multiple limiters can share
	// one Redis without collision. Defaults to "ratelimit:".
	KeyPrefix string
}

// NewRedisTokenBucketLimiter constructs a Redis-backed limiter.
// Returns an error when required wiring is missing.
func NewRedisTokenBucketLimiter(cfg RedisLimiterConfig) (*RedisTokenBucketLimiter, error) {
	if cfg.Cache == nil {
		return nil, errors.New("limits: cache is required")
	}
	if cfg.Bucket.BucketSize <= 0 {
		return nil, errors.New("limits: BucketSize must be > 0")
	}
	if cfg.Bucket.RefillRate <= 0 {
		return nil, errors.New("limits: RefillRate must be > 0")
	}
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "ratelimit:"
	}
	return &RedisTokenBucketLimiter{
		cfg:       cfg.Bucket,
		cache:     cfg.Cache,
		prefix:    prefix,
		nowMillis: func() int64 { return time.Now().UnixMilli() },
	}, nil
}

// luaTokenBucket runs one atomic update against a bucket key.
//
// KEYS[1] = "ratelimit:<key>"
// ARGV[1] = capacity (max tokens, integer)
// ARGV[2] = refill rate (tokens per second, float)
// ARGV[3] = nowMillis (int64 wall clock)
// ARGV[4] = requested tokens (integer)
//
// Returns: { allowed (0|1), tokens_remaining (int), retry_after_ms (int) }
//
// The bucket persists as a Redis hash with fields {tokens, lastRefill}.
// First-touch buckets start full. Per Redis Lua atomicity, no other
// caller can race the read/refill/decrement/write sequence.
const luaTokenBucket = `
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])
local nowMs    = tonumber(ARGV[3])
local want     = tonumber(ARGV[4])

local bucket = redis.call('HMGET', key, 'tokens', 'lastRefill')
local tokens = tonumber(bucket[1])
local lastMs = tonumber(bucket[2])
if tokens == nil then
  tokens = capacity
  lastMs = nowMs
end

-- Refill: add (elapsed_seconds * rate) tokens, clamped to capacity.
local elapsedMs = nowMs - lastMs
if elapsedMs < 0 then elapsedMs = 0 end
tokens = tokens + (elapsedMs / 1000.0) * rate
if tokens > capacity then tokens = capacity end

local allowed = 0
local retryAfterMs = 0
if tokens >= want then
  tokens = tokens - want
  allowed = 1
else
  local deficit = want - tokens
  -- Time (ms) required for the deficit to refill.
  retryAfterMs = math.ceil((deficit / rate) * 1000.0)
end

redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', nowMs)
-- TTL keeps long-idle buckets from accumulating forever. Refill
-- happens lazily on next call anyway, so dropping a stale bucket
-- only costs the next caller a "start full" reset.
redis.call('PEXPIRE', key, 3600000)

return { allowed, math.floor(tokens), retryAfterMs }
`

// Allow implements RateLimiter.
func (l *RedisTokenBucketLimiter) Allow(ctx context.Context, key string) error {
	return l.AllowN(ctx, key, 1)
}

// AllowN implements RateLimiter.
func (l *RedisTokenBucketLimiter) AllowN(ctx context.Context, key string, n int) error {
	if n <= 0 {
		return nil
	}
	fullKey := l.prefix + key
	res, err := l.cache.Eval(ctx, luaTokenBucket,
		[]string{fullKey},
		l.cfg.BucketSize,
		l.cfg.RefillRate,
		l.nowMillis(),
		n,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "limits: redis eval", err)
	}
	allowed, tokensLeft, retryMs, err := parseLuaResult(res)
	if err != nil {
		return err
	}
	if allowed == 1 {
		return nil
	}
	_ = tokensLeft
	retrySec := int64(retryMs / 1000)
	if retryMs > 0 && retryMs%1000 != 0 {
		retrySec++
	}
	if retrySec < 1 {
		retrySec = 1
	}
	return &signalerrors.RateLimitedError{
		RetryAfterSeconds: retrySec,
	}
}

// parseLuaResult decodes the {allowed, tokens, retryAfterMs} triple
// the Lua script returns. Different Redis client libraries (go-redis,
// miniredis, etc.) hand back slightly different concrete types so we
// accept the common shapes.
func parseLuaResult(res interface{}) (allowed, tokens, retryMs int64, err error) {
	arr, ok := res.([]interface{})
	if !ok {
		return 0, 0, 0, signalerrors.New(signalerrors.ErrInternal, fmt.Sprintf("limits: unexpected eval result type %T", res))
	}
	if len(arr) != 3 {
		return 0, 0, 0, signalerrors.New(signalerrors.ErrInternal, "limits: eval result has "+strconv.Itoa(len(arr))+" fields, want 3")
	}
	for i, v := range arr {
		n, parseErr := toInt64(v)
		if parseErr != nil {
			return 0, 0, 0, signalerrors.Wrap(signalerrors.ErrInternal, "limits: field "+strconv.Itoa(i), parseErr)
		}
		switch i {
		case 0:
			allowed = n
		case 1:
			tokens = n
		case 2:
			retryMs = n
		}
	}
	return allowed, tokens, retryMs, nil
}

// toInt64 normalises Redis-eval return values which can be int64,
// float64, or stringified numbers across client libraries.
func toInt64(v interface{}) (int64, error) {
	switch x := v.(type) {
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	case float64:
		return int64(x), nil
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return 0, signalerrors.New(signalerrors.ErrInvalidArgument, "not numeric: "+strconv.Quote(x))
		}
		return n, nil
	default:
		return 0, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("unexpected type %T", v))
	}
}
