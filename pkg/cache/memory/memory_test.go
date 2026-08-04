package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

// ---- Keyed values ----

func TestClient_SetGet_Roundtrip(t *testing.T) {
	t.Parallel()
	c := New()
	if err := c.Set(ctx(t), "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := c.Get(ctx(t), "k")
	if err != nil || string(got) != "v" {
		t.Fatalf("Get: got=%s err=%v", got, err)
	}
}

func TestClient_Get_MissingReturnsErrKeyNotFound(t *testing.T) {
	t.Parallel()
	c := New()
	_, err := c.Get(ctx(t), "absent")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestClient_Set_WithTTL_Expires(t *testing.T) {
	t.Parallel()
	c := New()
	if err := c.Set(ctx(t), "k", []byte("v"), 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	_, err := c.Get(ctx(t), "k")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("expected expired key to be absent, got %v", err)
	}
}

func TestClient_Get_ReturnsIndependentCopy(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(ctx(t), "k", []byte("hello"), 0)
	first, _ := c.Get(ctx(t), "k")
	first[0] = 'X'
	second, _ := c.Get(ctx(t), "k")
	if string(second) != "hello" {
		t.Fatalf("mutation leaked: %s", second)
	}
}

func TestClient_Del_IdempotentAcrossMissing(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(ctx(t), "a", []byte("1"), 0)
	if err := c.Del(ctx(t), "a", "b", "c"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if ok, _ := c.Exists(ctx(t), "a"); ok {
		t.Fatal("a should be gone")
	}
}

func TestClient_Exists(t *testing.T) {
	t.Parallel()
	c := New()
	if ok, _ := c.Exists(ctx(t), "absent"); ok {
		t.Fatal("absent key should not exist")
	}
	_ = c.Set(ctx(t), "k", []byte("v"), 0)
	if ok, _ := c.Exists(ctx(t), "k"); !ok {
		t.Fatal("k should exist")
	}
}

func TestClient_Expire_UpdatesTTL(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(ctx(t), "k", []byte("v"), 0)
	ok, err := c.Expire(ctx(t), "k", 10*time.Millisecond)
	if err != nil || !ok {
		t.Fatalf("Expire: ok=%v err=%v", ok, err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Get(ctx(t), "k"); !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestClient_Expire_MissingKey(t *testing.T) {
	t.Parallel()
	c := New()
	ok, err := c.Expire(ctx(t), "absent", time.Second)
	if err != nil || ok {
		t.Fatalf("Expire on missing should be (false, nil); got (%v, %v)", ok, err)
	}
}

func TestClient_TTL(t *testing.T) {
	t.Parallel()
	c := New()
	// Missing key.
	d, err := c.TTL(ctx(t), "absent")
	if err != nil || d != 0 {
		t.Fatalf("TTL(absent): d=%v err=%v", d, err)
	}
	// No expiration.
	_ = c.Set(ctx(t), "k", []byte("v"), 0)
	d, _ = c.TTL(ctx(t), "k")
	if d != 0 {
		t.Fatalf("TTL(no-exp) should be 0, got %v", d)
	}
	// With expiration.
	_ = c.Set(ctx(t), "k2", []byte("v"), time.Minute)
	d, _ = c.TTL(ctx(t), "k2")
	if d <= 0 || d > time.Minute {
		t.Fatalf("TTL(k2) not within expected range: %v", d)
	}
}

// ---- Counters ----

func TestClient_Incr_FromZero(t *testing.T) {
	t.Parallel()
	c := New()
	n, err := c.Incr(ctx(t), "counter")
	if err != nil || n != 1 {
		t.Fatalf("Incr from zero: n=%d err=%v", n, err)
	}
	n, _ = c.Incr(ctx(t), "counter")
	if n != 2 {
		t.Fatalf("Incr second call: n=%d", n)
	}
}

func TestClient_IncrBy(t *testing.T) {
	t.Parallel()
	c := New()
	n, err := c.IncrBy(ctx(t), "counter", 5)
	if err != nil || n != 5 {
		t.Fatalf("IncrBy 5: n=%d err=%v", n, err)
	}
	n, _ = c.IncrBy(ctx(t), "counter", -2)
	if n != 3 {
		t.Fatalf("IncrBy -2: n=%d", n)
	}
}

func TestClient_IncrBy_NonIntegerValue(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(ctx(t), "k", []byte("not-a-number"), 0)
	if _, err := c.IncrBy(ctx(t), "k", 1); err == nil {
		t.Fatal("expected error incrementing non-integer value")
	}
}

// ---- Locks ----

func TestClient_Lock_AcquireAndReleaseRoundtrip(t *testing.T) {
	t.Parallel()
	c := New()
	if err := c.Lock(ctx(t), "lock", "token-1", time.Minute); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Second acquisition with a different holder must be refused.
	err := c.Lock(ctx(t), "lock", "token-2", time.Minute)
	if !errors.Is(err, cache.ErrLockNotAcquired) {
		t.Fatalf("expected ErrLockNotAcquired, got %v", err)
	}
	if err := c.Unlock(ctx(t), "lock", "token-1"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	// Now it can be acquired again.
	if err := c.Lock(ctx(t), "lock", "token-2", time.Minute); err != nil {
		t.Fatalf("Lock after Unlock: %v", err)
	}
}

func TestClient_Unlock_WrongToken_NoOp(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Lock(ctx(t), "lock", "token-1", time.Minute)
	if err := c.Unlock(ctx(t), "lock", "different"); err != nil {
		t.Fatalf("Unlock with wrong token should be no-op, got %v", err)
	}
	// Lock still held.
	if err := c.Lock(ctx(t), "lock", "another", time.Minute); !errors.Is(err, cache.ErrLockNotAcquired) {
		t.Fatal("lock should still be held")
	}
}

func TestClient_Lock_TTLAllowsReacquisition(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Lock(ctx(t), "lock", "t1", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if err := c.Lock(ctx(t), "lock", "t2", time.Minute); err != nil {
		t.Fatalf("expected reacquisition after TTL, got %v", err)
	}
}

// ---- Sorted sets ----

func TestClient_ZAddAndZRange(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.ZAdd(ctx(t), "queue",
		cache.ScoredMember{Score: 3, Member: []byte("c")},
		cache.ScoredMember{Score: 1, Member: []byte("a")},
		cache.ScoredMember{Score: 2, Member: []byte("b")},
	)
	got, err := c.ZRange(ctx(t), "queue", 0, -1)
	if err != nil || len(got) != 3 {
		t.Fatalf("ZRange: got=%v err=%v", got, err)
	}
	if string(got[0]) != "a" || string(got[1]) != "b" || string(got[2]) != "c" {
		t.Fatalf("zrange not score-sorted: %v", got)
	}
}

func TestClient_ZAdd_UpdatesScoreOnDuplicateMember(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.ZAdd(ctx(t), "q", cache.ScoredMember{Score: 1, Member: []byte("x")})
	_ = c.ZAdd(ctx(t), "q", cache.ScoredMember{Score: 5, Member: []byte("x")})
	n, _ := c.ZCard(ctx(t), "q")
	if n != 1 {
		t.Fatalf("duplicate member should update score, not add: %d", n)
	}
}

func TestClient_ZRange_NegativeIndexing(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.ZAdd(ctx(t), "q",
		cache.ScoredMember{Score: 1, Member: []byte("a")},
		cache.ScoredMember{Score: 2, Member: []byte("b")},
		cache.ScoredMember{Score: 3, Member: []byte("c")},
	)
	got, _ := c.ZRange(ctx(t), "q", -2, -1)
	if len(got) != 2 || string(got[0]) != "b" || string(got[1]) != "c" {
		t.Fatalf("negative indices: %v", got)
	}
}

func TestClient_ZRem_RemovesRemainingEmpty(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.ZAdd(ctx(t), "q", cache.ScoredMember{Score: 1, Member: []byte("only")})
	_ = c.ZRem(ctx(t), "q", []byte("only"))
	n, _ := c.ZCard(ctx(t), "q")
	if n != 0 {
		t.Fatalf("expected empty zset, got %d", n)
	}
	ok, _ := c.Exists(ctx(t), "q")
	if ok {
		t.Fatal("key should be deleted when zset empties")
	}
}

func TestClient_ZCard_Missing(t *testing.T) {
	t.Parallel()
	c := New()
	n, err := c.ZCard(ctx(t), "absent")
	if err != nil || n != 0 {
		t.Fatalf("ZCard(absent): n=%d err=%v", n, err)
	}
}

func TestClient_WrongType_StringVsZSet(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(ctx(t), "k", []byte("v"), 0)
	err := c.ZAdd(ctx(t), "k", cache.ScoredMember{Score: 1, Member: []byte("m")})
	if err == nil {
		t.Fatal("expected WRONGTYPE-style error")
	}
}

// ---- Hashes ----

func TestClient_HSet_HGet(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.HSet(ctx(t), "h", "f1", []byte("v1"))
	_ = c.HSet(ctx(t), "h", "f2", []byte("v2"))

	got, err := c.HGet(ctx(t), "h", "f1")
	if err != nil || string(got) != "v1" {
		t.Fatalf("HGet f1: got=%s err=%v", got, err)
	}
	n, _ := c.HLen(ctx(t), "h")
	if n != 2 {
		t.Fatalf("HLen: %d", n)
	}
}

func TestClient_HGet_MissingField(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.HSet(ctx(t), "h", "f1", []byte("v1"))
	_, err := c.HGet(ctx(t), "h", "absent")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("missing field: got %v", err)
	}
}

func TestClient_HGet_MissingKey(t *testing.T) {
	t.Parallel()
	c := New()
	_, err := c.HGet(ctx(t), "absent", "f")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("missing hash: got %v", err)
	}
}

func TestClient_HDel_RemovesLastCleansKey(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.HSet(ctx(t), "h", "f", []byte("v"))
	_ = c.HDel(ctx(t), "h", "f")
	ok, _ := c.Exists(ctx(t), "h")
	if ok {
		t.Fatal("empty hash should be deleted")
	}
}

func TestClient_HLen_Missing(t *testing.T) {
	t.Parallel()
	c := New()
	n, err := c.HLen(ctx(t), "absent")
	if err != nil || n != 0 {
		t.Fatalf("HLen(absent): n=%d err=%v", n, err)
	}
}

// ---- Pub/Sub ----

func TestClient_PubSub_DeliversMessagesToSubscribers(t *testing.T) {
	t.Parallel()
	c := New()
	sub, err := c.Subscribe(ctx(t), "ch1")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Close() }()

	delivered, err := c.Publish(ctx(t), "ch1", []byte("hello"))
	if err != nil || delivered != 1 {
		t.Fatalf("Publish: delivered=%d err=%v", delivered, err)
	}

	select {
	case msg := <-sub.Channel():
		if msg.Channel != "ch1" || string(msg.Payload) != "hello" {
			t.Fatalf("unexpected message: %+v", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for message")
	}
}

func TestClient_PubSub_NoSubscribers_DropSilent(t *testing.T) {
	t.Parallel()
	c := New()
	delivered, err := c.Publish(ctx(t), "quiet", []byte("nobody-listening"))
	if err != nil || delivered != 0 {
		t.Fatalf("publish with no subs: delivered=%d err=%v", delivered, err)
	}
}

func TestClient_PubSub_SubscriptionCloseStopsDelivery(t *testing.T) {
	t.Parallel()
	c := New()
	sub, _ := c.Subscribe(ctx(t), "ch")
	if err := sub.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Channel should be closed.
	_, ok := <-sub.Channel()
	if ok {
		t.Fatal("channel should be closed after Close")
	}

	// Further publishes deliver to nobody.
	delivered, _ := c.Publish(ctx(t), "ch", []byte("x"))
	if delivered != 0 {
		t.Fatalf("expected 0 deliveries after Close, got %d", delivered)
	}
}

// ---- Misc ----

func TestClient_Eval_NotSupported(t *testing.T) {
	t.Parallel()
	c := New()
	_, err := c.Eval(ctx(t), "return 1", nil)
	if err == nil {
		t.Fatal("expected Eval to be unsupported on memory backend")
	}
}

func TestClient_PingAndClose(t *testing.T) {
	t.Parallel()
	c := New()
	if err := c.Ping(ctx(t)); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(ctx(t)); err == nil {
		t.Fatal("expected Ping on closed client to fail")
	}
	if err := c.Set(ctx(t), "k", []byte("v"), 0); err == nil {
		t.Fatal("expected Set on closed client to fail")
	}
}

func TestClient_CloseIsIdempotent(t *testing.T) {
	t.Parallel()
	c := New()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
