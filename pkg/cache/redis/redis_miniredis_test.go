package redis

// Tests use miniredis — a pure-Go in-process Redis substitute — so no
// external Redis instance is required and tests run in memory.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	redisv9 "github.com/redis/go-redis/v9"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

// newTestClient starts a miniredis server and returns a Client wired to it
// together with the underlying miniredis handle (for time-travel helpers).
func newTestClient(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewFromClient(rdb), mr
}

func bg() context.Context { return context.Background() }

// ---- Keyed values --------------------------------------------------------

func TestRedis_SetGet_Roundtrip(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Set(bg(), "k", []byte("hello"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := c.Get(bg(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("Get: want hello got %s", got)
	}
}

func TestRedis_Get_MissingReturnsErrKeyNotFound(t *testing.T) {
	c, _ := newTestClient(t)
	_, err := c.Get(bg(), "absent")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestRedis_Set_WithTTL_Expires(t *testing.T) {
	c, mr := newTestClient(t)
	if err := c.Set(bg(), "k", []byte("v"), time.Second); err != nil {
		t.Fatal(err)
	}
	// Advance miniredis clock past the TTL.
	mr.FastForward(2 * time.Second)
	_, err := c.Get(bg(), "k")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("expected expired key to be absent, got %v", err)
	}
}

func TestRedis_Set_ZeroTTL_NeverExpires(t *testing.T) {
	c, mr := newTestClient(t)
	if err := c.Set(bg(), "k", []byte("persist"), 0); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(24 * time.Hour)
	got, err := c.Get(bg(), "k")
	if err != nil || string(got) != "persist" {
		t.Fatalf("expected key to persist, got %v / %v", got, err)
	}
}

func TestRedis_Del_Single(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.Set(bg(), "k", []byte("v"), 0)
	if err := c.Del(bg(), "k"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	_, err := c.Get(bg(), "k")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("expected key to be deleted, got %v", err)
	}
}

func TestRedis_Del_MultipleAndMissing(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.Set(bg(), "a", []byte("1"), 0)
	_ = c.Set(bg(), "b", []byte("2"), 0)
	// "c" does not exist; Del must not error.
	if err := c.Del(bg(), "a", "b", "c"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if ok, _ := c.Exists(bg(), "a"); ok {
		t.Fatal("a should be deleted")
	}
}

func TestRedis_Del_NoKeys_IsNoop(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Del(bg()); err != nil {
		t.Fatalf("Del with no keys: %v", err)
	}
}

func TestRedis_Exists_PresentAndAbsent(t *testing.T) {
	c, _ := newTestClient(t)
	if ok, _ := c.Exists(bg(), "nope"); ok {
		t.Fatal("absent key must not exist")
	}
	_ = c.Set(bg(), "k", []byte("v"), 0)
	if ok, _ := c.Exists(bg(), "k"); !ok {
		t.Fatal("present key must exist")
	}
}

func TestRedis_Expire_UpdatesTTL(t *testing.T) {
	c, mr := newTestClient(t)
	_ = c.Set(bg(), "k", []byte("v"), 0)
	ok, err := c.Expire(bg(), "k", time.Second)
	if err != nil || !ok {
		t.Fatalf("Expire: ok=%v err=%v", ok, err)
	}
	mr.FastForward(2 * time.Second)
	if _, err := c.Get(bg(), "k"); !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("expected key to expire, got %v", err)
	}
}

func TestRedis_Expire_MissingKeyReturnsFalse(t *testing.T) {
	c, _ := newTestClient(t)
	ok, err := c.Expire(bg(), "absent", time.Second)
	if err != nil || ok {
		t.Fatalf("Expire on missing: want (false,nil) got (%v,%v)", ok, err)
	}
}

func TestRedis_TTL_NoExpiration(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.Set(bg(), "k", []byte("v"), 0)
	d, err := c.TTL(bg(), "k")
	if err != nil || d != 0 {
		t.Fatalf("TTL(no-exp): d=%v err=%v", d, err)
	}
}

func TestRedis_TTL_MissingKey(t *testing.T) {
	c, _ := newTestClient(t)
	d, err := c.TTL(bg(), "absent")
	if err != nil || d != 0 {
		t.Fatalf("TTL(absent): d=%v err=%v", d, err)
	}
}

func TestRedis_TTL_WithExpiration(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.Set(bg(), "k", []byte("v"), time.Minute)
	d, err := c.TTL(bg(), "k")
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if d <= 0 || d > time.Minute {
		t.Fatalf("TTL not in range: %v", d)
	}
}

// ---- Counters ------------------------------------------------------------

func TestRedis_Incr_FromZero(t *testing.T) {
	c, _ := newTestClient(t)
	n, err := c.Incr(bg(), "ctr")
	if err != nil || n != 1 {
		t.Fatalf("Incr: n=%d err=%v", n, err)
	}
	n, _ = c.Incr(bg(), "ctr")
	if n != 2 {
		t.Fatalf("Incr second: n=%d", n)
	}
}

func TestRedis_IncrBy(t *testing.T) {
	c, _ := newTestClient(t)
	n, err := c.IncrBy(bg(), "ctr", 10)
	if err != nil || n != 10 {
		t.Fatalf("IncrBy 10: n=%d err=%v", n, err)
	}
	n, _ = c.IncrBy(bg(), "ctr", -3)
	if n != 7 {
		t.Fatalf("IncrBy -3: n=%d", n)
	}
}

// ---- Distributed locks --------------------------------------------------

func TestRedis_Lock_AcquireAndRelease(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Lock(bg(), "lk", "tok1", time.Minute); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	// Second attempt must fail.
	err := c.Lock(bg(), "lk", "tok2", time.Minute)
	if !errors.Is(err, cache.ErrLockNotAcquired) {
		t.Fatalf("expected ErrLockNotAcquired, got %v", err)
	}
	// Unlock then re-acquire.
	if err := c.Unlock(bg(), "lk", "tok1"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if err := c.Lock(bg(), "lk", "tok2", time.Minute); err != nil {
		t.Fatalf("Lock after Unlock: %v", err)
	}
}

func TestRedis_Unlock_WrongToken_NoOp(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.Lock(bg(), "lk", "tok1", time.Minute)
	// Unlocking with a wrong token must leave the lock intact.
	if err := c.Unlock(bg(), "lk", "wrong"); err != nil {
		t.Fatalf("Unlock wrong token: %v", err)
	}
	if err := c.Lock(bg(), "lk", "other", time.Minute); !errors.Is(err, cache.ErrLockNotAcquired) {
		t.Fatal("lock should still be held after wrong-token unlock")
	}
}

func TestRedis_Lock_TTLAllowsReacquisition(t *testing.T) {
	c, mr := newTestClient(t)
	_ = c.Lock(bg(), "lk", "tok1", time.Second)
	mr.FastForward(2 * time.Second)
	if err := c.Lock(bg(), "lk", "tok2", time.Minute); err != nil {
		t.Fatalf("expected reacquisition after TTL: %v", err)
	}
}

func TestRedis_Unlock_MissingKey_NoOp(t *testing.T) {
	c, _ := newTestClient(t)
	// Unlocking a key that doesn't exist must be a no-op.
	if err := c.Unlock(bg(), "absent", "tok"); err != nil {
		t.Fatalf("Unlock on absent key: %v", err)
	}
}

// ---- Sorted sets ---------------------------------------------------------

func TestRedis_ZAddAndZRange(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.ZAdd(bg(), "q",
		cache.ScoredMember{Score: 3, Member: []byte("c")},
		cache.ScoredMember{Score: 1, Member: []byte("a")},
		cache.ScoredMember{Score: 2, Member: []byte("b")},
	)
	got, err := c.ZRange(bg(), "q", 0, -1)
	if err != nil || len(got) != 3 {
		t.Fatalf("ZRange: got=%v err=%v", got, err)
	}
	if string(got[0]) != "a" || string(got[1]) != "b" || string(got[2]) != "c" {
		t.Fatalf("ZRange not score-sorted: %v", got)
	}
}

func TestRedis_ZAdd_NoMembers_IsNoop(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.ZAdd(bg(), "q"); err != nil {
		t.Fatalf("ZAdd no members: %v", err)
	}
}

func TestRedis_ZRange_EmptySet(t *testing.T) {
	c, _ := newTestClient(t)
	got, err := c.ZRange(bg(), "absent", 0, -1)
	if err != nil {
		t.Fatalf("ZRange absent: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

func TestRedis_ZRem_RemovesMembers(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.ZAdd(bg(), "q",
		cache.ScoredMember{Score: 1, Member: []byte("a")},
		cache.ScoredMember{Score: 2, Member: []byte("b")},
	)
	if err := c.ZRem(bg(), "q", []byte("a")); err != nil {
		t.Fatalf("ZRem: %v", err)
	}
	n, _ := c.ZCard(bg(), "q")
	if n != 1 {
		t.Fatalf("ZCard after ZRem: %d", n)
	}
}

func TestRedis_ZRem_NoMembers_IsNoop(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.ZAdd(bg(), "q", cache.ScoredMember{Score: 1, Member: []byte("a")})
	if err := c.ZRem(bg(), "q"); err != nil {
		t.Fatalf("ZRem no members: %v", err)
	}
}

func TestRedis_ZCard_MissingKey(t *testing.T) {
	c, _ := newTestClient(t)
	n, err := c.ZCard(bg(), "absent")
	if err != nil || n != 0 {
		t.Fatalf("ZCard absent: n=%d err=%v", n, err)
	}
}

func TestRedis_ZCard_AfterAdd(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.ZAdd(bg(), "q",
		cache.ScoredMember{Score: 1, Member: []byte("x")},
		cache.ScoredMember{Score: 2, Member: []byte("y")},
	)
	n, err := c.ZCard(bg(), "q")
	if err != nil || n != 2 {
		t.Fatalf("ZCard: n=%d err=%v", n, err)
	}
}

// ---- Hashes --------------------------------------------------------------

func TestRedis_HSetAndHGet(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.HSet(bg(), "h", "field1", []byte("val1")); err != nil {
		t.Fatalf("HSet: %v", err)
	}
	got, err := c.HGet(bg(), "h", "field1")
	if err != nil || string(got) != "val1" {
		t.Fatalf("HGet: got=%s err=%v", got, err)
	}
}

func TestRedis_HGet_MissingField(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.HSet(bg(), "h", "f1", []byte("v"))
	_, err := c.HGet(bg(), "h", "absent")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("HGet missing field: got %v", err)
	}
}

func TestRedis_HGet_MissingKey(t *testing.T) {
	c, _ := newTestClient(t)
	_, err := c.HGet(bg(), "absent", "f")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("HGet missing key: got %v", err)
	}
}

func TestRedis_HDel_RemovesFields(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.HSet(bg(), "h", "f1", []byte("v1"))
	_ = c.HSet(bg(), "h", "f2", []byte("v2"))
	if err := c.HDel(bg(), "h", "f1"); err != nil {
		t.Fatalf("HDel: %v", err)
	}
	if n, _ := c.HLen(bg(), "h"); n != 1 {
		t.Fatalf("HLen after HDel: %d", n)
	}
	_, err := c.HGet(bg(), "h", "f1")
	if !errors.Is(err, cache.ErrKeyNotFound) {
		t.Fatalf("deleted field should be absent, got %v", err)
	}
}

func TestRedis_HDel_NoFields_IsNoop(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.HSet(bg(), "h", "f", []byte("v"))
	if err := c.HDel(bg(), "h"); err != nil {
		t.Fatalf("HDel no fields: %v", err)
	}
}

func TestRedis_HLen_MissingKey(t *testing.T) {
	c, _ := newTestClient(t)
	n, err := c.HLen(bg(), "absent")
	if err != nil || n != 0 {
		t.Fatalf("HLen absent: n=%d err=%v", n, err)
	}
}

func TestRedis_HLen_MultipleFields(t *testing.T) {
	c, _ := newTestClient(t)
	_ = c.HSet(bg(), "h", "a", []byte("1"))
	_ = c.HSet(bg(), "h", "b", []byte("2"))
	_ = c.HSet(bg(), "h", "c", []byte("3"))
	n, err := c.HLen(bg(), "h")
	if err != nil || n != 3 {
		t.Fatalf("HLen: n=%d err=%v", n, err)
	}
}

// ---- Pub/sub -------------------------------------------------------------

func TestRedis_PubSub_DeliversMessage(t *testing.T) {
	c, _ := newTestClient(t)
	sub, err := c.Subscribe(bg(), "ch1")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer func() { _ = sub.Close() }()

	// Publish from the same client (miniredis routes within the same server).
	if _, err := c.Publish(bg(), "ch1", []byte("hello")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case msg, ok := <-sub.Channel():
		if !ok {
			t.Fatal("channel closed unexpectedly")
		}
		if msg.Channel != "ch1" || string(msg.Payload) != "hello" {
			t.Fatalf("unexpected message: %+v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pub/sub message")
	}
}

func TestRedis_PubSub_CloseIdempotent(t *testing.T) {
	c, _ := newTestClient(t)
	sub, err := c.Subscribe(bg(), "ch")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := sub.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close must not panic or error.
	if err := sub.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRedis_Publish_NoSubscribers(t *testing.T) {
	c, _ := newTestClient(t)
	// Publish without any subscribers; must not error.
	if _, err := c.Publish(bg(), "quiet", []byte("x")); err != nil {
		t.Fatalf("Publish no subs: %v", err)
	}
}

// ---- Lua scripts ---------------------------------------------------------

func TestRedis_Eval_SimpleScript(t *testing.T) {
	c, _ := newTestClient(t)
	// A trivial Lua script that returns the first key argument.
	res, err := c.Eval(bg(), "return KEYS[1]", []string{"mykey"})
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if res != "mykey" {
		t.Fatalf("Eval: want mykey got %v", res)
	}
}

func TestRedis_Eval_UnlockScript(t *testing.T) {
	c, _ := newTestClient(t)
	// Exercise the actual unlock Lua script to verify it runs correctly.
	_ = c.Lock(bg(), "lk", "tok", time.Minute)
	// Correct token: lock should be released.
	res, err := c.Eval(bg(), unlockScript, []string{"lk"}, "tok")
	if err != nil {
		t.Fatalf("Eval unlock: %v", err)
	}
	// Result is 1 (DEL returned 1 key deleted).
	if res.(int64) != 1 {
		t.Fatalf("Eval unlock result: %v", res)
	}
	if ok, _ := c.Exists(bg(), "lk"); ok {
		t.Fatal("lock key should be gone")
	}
}

// ---- Lifecycle -----------------------------------------------------------

func TestRedis_Ping(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Ping(bg()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestRedis_Close(t *testing.T) {
	c, _ := newTestClient(t)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// ---- New() configuration propagation ------------------------------------

func TestNew_TimeoutOverrides(t *testing.T) {
	mr := miniredis.RunT(t)
	c, err := New(Config{
		URL:          "redis://" + mr.Addr() + "/0",
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()
	opts := c.rdb.Options()
	if opts.DialTimeout != 5*time.Second {
		t.Fatalf("DialTimeout not applied: %v", opts.DialTimeout)
	}
	if opts.ReadTimeout != 3*time.Second {
		t.Fatalf("ReadTimeout not applied: %v", opts.ReadTimeout)
	}
	if opts.WriteTimeout != 3*time.Second {
		t.Fatalf("WriteTimeout not applied: %v", opts.WriteTimeout)
	}
}

func TestNew_DefaultTimeouts_NotOverridden(t *testing.T) {
	mr := miniredis.RunT(t)
	// Zero timeout values in Config must not overwrite the go-redis defaults.
	c, err := New(Config{URL: "redis://" + mr.Addr() + "/0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Ping(bg()); err != nil {
		t.Fatalf("Ping after New with defaults: %v", err)
	}
}
