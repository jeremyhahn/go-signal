package limits

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	redisv9 "github.com/redis/go-redis/v9"

	cacheredis "github.com/jeremyhahn/go-signal/pkg/cache/redis"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

func newRedisCache(t *testing.T) (*cacheredis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return cacheredis.NewFromClient(rdb), mr
}

func TestNewRedisTokenBucketLimiter_Validation(t *testing.T) {
	c, _ := newRedisCache(t)
	if _, err := NewRedisTokenBucketLimiter(RedisLimiterConfig{}); err == nil {
		t.Error("missing cache should fail")
	}
	if _, err := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{RefillRate: 1},
	}); err == nil {
		t.Error("BucketSize<=0 should fail")
	}
	if _, err := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{BucketSize: 5},
	}); err == nil {
		t.Error("RefillRate<=0 should fail")
	}
}

func TestRedisLimiter_StartsFullThenExhausts(t *testing.T) {
	c, _ := newRedisCache(t)
	l, err := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{BucketSize: 3, RefillRate: 0.1}, // slow refill
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := int64(1_700_000_000_000)
	l.nowMillis = func() int64 { return now }
	ctx := context.Background()

	// 3 tokens available; 3 calls succeed.
	for i := 0; i < 3; i++ {
		if err := l.Allow(ctx, "alice"); err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}
	// 4th call exceeds — RateLimitedError.
	err = l.Allow(ctx, "alice")
	var rl *signalerrors.RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("expected RateLimitedError; got %v", err)
	}
	if rl.RetryAfterSeconds < 1 {
		t.Errorf("RetryAfterSeconds = %d, want >= 1", rl.RetryAfterSeconds)
	}
}

func TestRedisLimiter_RefillsOverTime(t *testing.T) {
	c, _ := newRedisCache(t)
	l, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{BucketSize: 2, RefillRate: 1.0}, // 1 token/s
	})
	now := int64(1_700_000_000_000)
	l.nowMillis = func() int64 { return now }
	ctx := context.Background()

	// Drain both tokens.
	_ = l.Allow(ctx, "bob")
	_ = l.Allow(ctx, "bob")
	if err := l.Allow(ctx, "bob"); err == nil {
		t.Fatal("expected exhaustion")
	}

	// Advance 2 seconds → 2 tokens refilled, 2 calls succeed.
	now += 2000
	for i := 0; i < 2; i++ {
		if err := l.Allow(ctx, "bob"); err != nil {
			t.Errorf("post-refill call %d: %v", i, err)
		}
	}
	// 3rd call again exhausted.
	if err := l.Allow(ctx, "bob"); err == nil {
		t.Error("expected exhaustion after refill drain")
	}
}

func TestRedisLimiter_PerKeyIsolation(t *testing.T) {
	c, _ := newRedisCache(t)
	l, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{BucketSize: 1, RefillRate: 0.01},
	})
	ctx := context.Background()
	// Each key gets its own bucket.
	if err := l.Allow(ctx, "alice"); err != nil {
		t.Errorf("alice first: %v", err)
	}
	if err := l.Allow(ctx, "bob"); err != nil {
		t.Errorf("bob first: %v", err)
	}
	if err := l.Allow(ctx, "alice"); err == nil {
		t.Error("alice second should exhaust")
	}
	if err := l.Allow(ctx, "bob"); err == nil {
		t.Error("bob second should exhaust")
	}
}

func TestRedisLimiter_SharedAcrossInstances(t *testing.T) {
	c1, mr := newRedisCache(t)
	// Second cache client against the same broker — represents a
	// second signald replica.
	rdb2 := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb2.Close() })
	c2 := cacheredis.NewFromClient(rdb2)

	l1, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c1,
		Bucket: BucketConfig{BucketSize: 3, RefillRate: 0.01},
	})
	l2, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c2,
		Bucket: BucketConfig{BucketSize: 3, RefillRate: 0.01},
	})
	ctx := context.Background()

	// Two tokens via l1, one via l2 — 3 tokens consumed total.
	_ = l1.Allow(ctx, "shared")
	_ = l1.Allow(ctx, "shared")
	if err := l2.Allow(ctx, "shared"); err != nil {
		t.Errorf("l2 third: %v", err)
	}
	// Fourth call (from either instance) should fail.
	if err := l1.Allow(ctx, "shared"); err == nil {
		t.Error("l1 fourth should exhaust — bucket state must be shared")
	}
}

func TestRedisLimiter_AllowNRespectsRequestedCount(t *testing.T) {
	c, _ := newRedisCache(t)
	l, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{BucketSize: 10, RefillRate: 0.01},
	})
	ctx := context.Background()
	if err := l.AllowN(ctx, "carol", 7); err != nil {
		t.Errorf("AllowN(7) on fresh bucket: %v", err)
	}
	// 3 remain; AllowN(5) should fail.
	if err := l.AllowN(ctx, "carol", 5); err == nil {
		t.Error("expected exhaustion when requesting more than remaining")
	}
	// AllowN(3) succeeds exactly.
	if err := l.AllowN(ctx, "carol", 3); err != nil {
		t.Errorf("AllowN(3) remaining: %v", err)
	}
}

func TestRedisLimiter_AllowNZeroIsNoop(t *testing.T) {
	c, _ := newRedisCache(t)
	l, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{BucketSize: 5, RefillRate: 1},
	})
	if err := l.AllowN(context.Background(), "x", 0); err != nil {
		t.Errorf("AllowN(0) should be no-op; got %v", err)
	}
}

func TestRedisLimiter_AllowN_EvalError_WrapsError(t *testing.T) {
	c, mr := newRedisCache(t)
	l, err := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache:  c,
		Bucket: BucketConfig{BucketSize: 5, RefillRate: 1},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mr.Close() // force Redis connection error on the next Eval call
	if err := l.AllowN(context.Background(), "x", 1); err == nil {
		t.Error("expected error when Redis is unavailable")
	}
}

// --------------------------------------------------------------------------
// parseLuaResult: error branches (called directly; same package)
// --------------------------------------------------------------------------

func TestParseLuaResult_NonArray_ReturnsError(t *testing.T) {
	_, _, _, err := parseLuaResult("not-an-array")
	if err == nil {
		t.Error("expected error for non-array result")
	}
}

func TestParseLuaResult_WrongLength_ReturnsError(t *testing.T) {
	_, _, _, err := parseLuaResult([]interface{}{int64(1), int64(2)}) // only 2 fields
	if err == nil {
		t.Error("expected error for result with wrong field count")
	}
}

func TestParseLuaResult_InvalidField_ReturnsError(t *testing.T) {
	_, _, _, err := parseLuaResult([]interface{}{int64(1), "not-a-number!", int64(0)})
	if err == nil {
		t.Error("expected error when field cannot be parsed as int64")
	}
}

func TestParseLuaResult_ValidAllFieldTypes(t *testing.T) {
	// Ensure parseLuaResult accepts the concrete types toInt64 handles.
	allowed, tokens, retryMs, err := parseLuaResult([]interface{}{int64(1), int64(5), int64(0)})
	if err != nil {
		t.Fatalf("parseLuaResult: %v", err)
	}
	if allowed != 1 || tokens != 5 || retryMs != 0 {
		t.Errorf("got (%d, %d, %d), want (1, 5, 0)", allowed, tokens, retryMs)
	}
}

// --------------------------------------------------------------------------
// toInt64: all concrete type branches (called directly; same package)
// --------------------------------------------------------------------------

func TestToInt64_AllTypes(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want int64
		err  bool
	}{
		{"int64", int64(42), 42, false},
		{"int", int(17), 17, false},
		{"float64", float64(3.7), 3, false}, // truncated toward zero
		{"string_valid", "123", 123, false},
		{"string_invalid", "not-a-number", 0, true},
		{"unexpected_type", true, 0, true}, // bool is not handled
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toInt64(tc.in)
			if tc.err && err == nil {
				t.Errorf("expected error for input %v (%T)", tc.in, tc.in)
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.err && got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRedisLimiter_KeyPrefixIsolation(t *testing.T) {
	c, _ := newRedisCache(t)
	l1, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache: c, KeyPrefix: "messages:",
		Bucket: BucketConfig{BucketSize: 1, RefillRate: 0.01},
	})
	l2, _ := NewRedisTokenBucketLimiter(RedisLimiterConfig{
		Cache: c, KeyPrefix: "registrations:",
		Bucket: BucketConfig{BucketSize: 1, RefillRate: 0.01},
	})
	ctx := context.Background()
	// Same logical key under different prefixes is two independent buckets.
	if err := l1.Allow(ctx, "alice"); err != nil {
		t.Errorf("messages alice first: %v", err)
	}
	if err := l2.Allow(ctx, "alice"); err != nil {
		t.Errorf("registrations alice first: %v", err)
	}
	if err := l1.Allow(ctx, "alice"); err == nil {
		t.Error("messages alice second should exhaust")
	}
}
