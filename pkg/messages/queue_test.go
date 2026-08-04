package messages

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/cache"
	cachememory "github.com/jeremyhahn/go-signal/pkg/cache/memory"
)

// queueWithCache returns a fresh CacheQueue backed by an in-memory cache
// and the cache itself so tests can poke at it directly.
func queueWithCache(t *testing.T, ttl time.Duration) (*CacheQueue, cache.Client) {
	t.Helper()
	c := cachememory.New()
	t.Cleanup(func() { _ = c.Close() })
	return NewCacheQueue(c, ttl), c
}

func newEnv(guid string, ts uint64) *Envelope {
	return &Envelope{
		ServerGUID:      guid,
		ServerTimestamp: ts,
		Content:         []byte("ciphertext-" + guid),
	}
}

// ---- Enqueue ----

func TestCacheQueue_Enqueue_NilOrEmpty(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	if err := q.Enqueue(context.Background(), "u1", 1, nil); err == nil {
		t.Fatal("expected error for nil envelope")
	}
	if err := q.Enqueue(context.Background(), "u1", 1, &Envelope{}); err == nil {
		t.Fatal("expected error for empty ServerGUID")
	}
}

func TestCacheQueue_EnqueueAndDrain_OrderedByTimestamp(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	ctx := context.Background()

	// Enqueue out of order; Drain should return them sorted by ts.
	for _, env := range []*Envelope{
		newEnv("c", 30),
		newEnv("a", 10),
		newEnv("b", 20),
	} {
		if err := q.Enqueue(ctx, "u1", 1, env); err != nil {
			t.Fatal(err)
		}
	}

	got, err := q.Drain(ctx, "u1", 1, 10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 envelopes, got %d", len(got))
	}
	if got[0].ServerGUID != "a" || got[1].ServerGUID != "b" || got[2].ServerGUID != "c" {
		t.Fatalf("Drain not ordered by timestamp: %+v", got)
	}
}

func TestCacheQueue_Enqueue_AssignsScoreWhenZero(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	ctx := context.Background()

	// Envelope with zero ServerTimestamp must still land in the queue.
	if err := q.Enqueue(ctx, "u1", 1, &Envelope{ServerGUID: "g", ServerTimestamp: 0}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	got, _ := q.Drain(ctx, "u1", 1, 10)
	if len(got) != 1 || got[0].ServerGUID != "g" {
		t.Fatalf("expected zero-timestamp envelope to be drainable, got %+v", got)
	}
}

func TestCacheQueue_Enqueue_TTLArmed(t *testing.T) {
	t.Parallel()
	q, c := queueWithCache(t, 50*time.Millisecond)
	ctx := context.Background()

	if err := q.Enqueue(ctx, "u1", 1, newEnv("g", 1)); err != nil {
		t.Fatal(err)
	}
	d, err := c.TTL(ctx, queueKey("u1", 1))
	if err != nil || d <= 0 {
		t.Fatalf("expected positive TTL on queue key, got d=%v err=%v", d, err)
	}
}

// ---- Drain ----

func TestCacheQueue_Drain_DefaultMax(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	ctx := context.Background()

	// Default max is 100; exercise that it returns when fewer items
	// exist.
	for i := 0; i < 5; i++ {
		_ = q.Enqueue(ctx, "u1", 1, newEnv(string(rune('a'+i)), uint64(i+1)))
	}
	got, err := q.Drain(ctx, "u1", 1, 0) // 0 → default 100
	if err != nil || len(got) != 5 {
		t.Fatalf("Drain(0): len=%d err=%v", len(got), err)
	}
}

func TestCacheQueue_Drain_RespectsMax(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_ = q.Enqueue(ctx, "u1", 1, newEnv(string(rune('a'+i)), uint64(i+1)))
	}
	got, err := q.Drain(ctx, "u1", 1, 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("Drain(2): len=%d err=%v", len(got), err)
	}
	if got[0].ServerGUID != "a" || got[1].ServerGUID != "b" {
		t.Fatalf("Drain ordering wrong: %+v", got)
	}
}

func TestCacheQueue_Drain_EmptyQueue(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	got, err := q.Drain(context.Background(), "absent", 1, 10)
	if err != nil || got != nil {
		t.Fatalf("Drain on empty: got=%v err=%v", got, err)
	}
}

func TestCacheQueue_Drain_IgnoresOrphanedZSetMembers(t *testing.T) {
	t.Parallel()
	q, c := queueWithCache(t, 0)
	ctx := context.Background()

	// Fully insert one envelope so the hash is present, then add a
	// dangling zset entry whose hash side has no value.
	_ = q.Enqueue(ctx, "u1", 1, newEnv("real", 1))
	_ = c.ZAdd(ctx, queueKey("u1", 1), cache.ScoredMember{Score: 99, Member: []byte("orphan")})

	got, err := q.Drain(ctx, "u1", 1, 10)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if len(got) != 1 || got[0].ServerGUID != "real" {
		t.Fatalf("Drain should skip orphans, got %+v", got)
	}

	// The orphan should have been swept from the zset.
	n, _ := q.Len(ctx, "u1", 1)
	if n != 1 {
		t.Fatalf("expected orphan removed; queue len = %d", n)
	}
}

// ---- Remove ----

func TestCacheQueue_Remove_Existing(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	ctx := context.Background()

	_ = q.Enqueue(ctx, "u1", 1, newEnv("a", 1))
	_ = q.Enqueue(ctx, "u1", 1, newEnv("b", 2))

	if err := q.Remove(ctx, "u1", 1, "a"); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Drain(ctx, "u1", 1, 10)
	if len(got) != 1 || got[0].ServerGUID != "b" {
		t.Fatalf("Remove failed: %+v", got)
	}
}

func TestCacheQueue_Remove_Missing_IsIdempotent(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	if err := q.Remove(context.Background(), "u1", 1, "never-existed"); err != nil {
		t.Fatalf("Remove on missing must be idempotent, got: %v", err)
	}
}

// ---- Len + HasMessages ----

func TestCacheQueue_LenAndHasMessages(t *testing.T) {
	t.Parallel()
	q, _ := queueWithCache(t, 0)
	ctx := context.Background()

	if has, _ := q.HasMessages(ctx, "u1", 1); has {
		t.Fatal("empty queue should report no messages")
	}
	_ = q.Enqueue(ctx, "u1", 1, newEnv("a", 1))
	_ = q.Enqueue(ctx, "u1", 1, newEnv("b", 2))

	n, err := q.Len(ctx, "u1", 1)
	if err != nil || n != 2 {
		t.Fatalf("Len: n=%d err=%v", n, err)
	}
	has, _ := q.HasMessages(ctx, "u1", 1)
	if !has {
		t.Fatal("HasMessages should be true after enqueue")
	}
}

// ---- Cache failure propagation ----

type erroringCache struct {
	cache.Client
	zaddErr error
	hsetErr error
}

func (e *erroringCache) ZAdd(ctx context.Context, key string, members ...cache.ScoredMember) error {
	if e.zaddErr != nil {
		return e.zaddErr
	}
	return e.Client.ZAdd(ctx, key, members...)
}

func (e *erroringCache) HSet(ctx context.Context, key, field string, value []byte) error {
	if e.hsetErr != nil {
		return e.hsetErr
	}
	return e.Client.HSet(ctx, key, field, value)
}

func TestCacheQueue_Enqueue_ZAddFailure(t *testing.T) {
	t.Parallel()
	c := cachememory.New()
	defer func() { _ = c.Close() }()
	wrapped := &erroringCache{Client: c, zaddErr: errors.New("zadd boom")}
	q := NewCacheQueue(wrapped, 0)

	err := q.Enqueue(context.Background(), "u1", 1, newEnv("g", 1))
	if err == nil {
		t.Fatal("expected zadd error to propagate")
	}
}

func TestCacheQueue_Enqueue_HSetFailure(t *testing.T) {
	t.Parallel()
	c := cachememory.New()
	defer func() { _ = c.Close() }()
	wrapped := &erroringCache{Client: c, hsetErr: errors.New("hset boom")}
	q := NewCacheQueue(wrapped, 0)

	err := q.Enqueue(context.Background(), "u1", 1, newEnv("g", 1))
	if err == nil {
		t.Fatal("expected hset error to propagate")
	}
}
