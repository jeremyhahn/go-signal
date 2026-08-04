//go:build integration

package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisv9 "github.com/redis/go-redis/v9"

	"github.com/jeremyhahn/go-signal/pkg/cache"
	cacheredis "github.com/jeremyhahn/go-signal/pkg/cache/redis"
	"github.com/jeremyhahn/go-signal/pkg/workers"
)

// newMultiInstanceCache returns a cache.Client connected to mr; each
// invocation makes an independent connection so the test can simulate
// two distinct signald replicas sharing one Redis broker.
func newMultiInstanceCache(t *testing.T, mr *miniredis.Miniredis) cache.Client {
	t.Helper()
	rdb := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return cacheredis.NewFromClient(rdb)
}

// TestPhase5Multiinstance_LeaderLeasePreventsDoubleExecution drives the
// worker-coordination wire: instance-A acquires a lease via the shared
// cache, instance-B's Acquire fails with ErrLeaderElectionFailed.
// After instance-A releases (or the lease TTL expires), instance-B
// can re-acquire.
//
// This is the production-shape failover that protects continuous
// workers (message-persister, dispatch flusher, backup cleanup) from
// running on every replica at once.
func TestPhase5Multiinstance_LeaderLeasePreventsDoubleExecution(t *testing.T) {
	mr := miniredis.RunT(t)
	cacheA := newMultiInstanceCache(t, mr)
	cacheB := newMultiInstanceCache(t, mr)

	leaserA := workers.NewCacheLeaser(cacheA, "phase5:")
	leaserB := workers.NewCacheLeaser(cacheB, "phase5:")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Instance A wins the lease.
	if err := leaserA.Acquire(ctx, "leader-election", 2*time.Second); err != nil {
		t.Fatalf("A.Acquire: %v", err)
	}

	// Instance B sees a held lease and refuses.
	err := leaserB.Acquire(ctx, "leader-election", 2*time.Second)
	if !errors.Is(err, workers.ErrLeaderElectionFailed) {
		t.Errorf("B.Acquire expected ErrLeaderElectionFailed; got %v", err)
	}

	// Release on A frees the slot.
	if err := leaserA.Release(ctx, "leader-election"); err != nil {
		t.Fatalf("A.Release: %v", err)
	}
	if err := leaserB.Acquire(ctx, "leader-election", 2*time.Second); err != nil {
		t.Errorf("B.Acquire after A.Release: %v", err)
	}
}

// TestPhase5Multiinstance_LeaseExpiryAllowsReacquisition confirms the
// TTL safety net: if instance A acquires and then crashes (never calls
// Release), instance B picks up after the TTL elapses. This is the
// liveness guarantee the cache-based leaser provides — no orphaned
// "leader" state can wedge the cluster.
func TestPhase5Multiinstance_LeaseExpiryAllowsReacquisition(t *testing.T) {
	mr := miniredis.RunT(t)
	cacheA := newMultiInstanceCache(t, mr)
	cacheB := newMultiInstanceCache(t, mr)

	leaserA := workers.NewCacheLeaser(cacheA, "phase5:")
	leaserB := workers.NewCacheLeaser(cacheB, "phase5:")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := leaserA.Acquire(ctx, "ttl-test", 100*time.Millisecond); err != nil {
		t.Fatalf("A.Acquire: %v", err)
	}
	// Simulate instance A crashing without Release. miniredis honours
	// the SET PX expiry but we need to fast-forward time for the
	// expiry to fire deterministically.
	mr.FastForward(200 * time.Millisecond)

	if err := leaserB.Acquire(ctx, "ttl-test", time.Second); err != nil {
		t.Errorf("B.Acquire after A's lease expired: %v", err)
	}
}

// TestPhase5Multiinstance_PubSubDeliversAcrossInstances confirms the
// WebSocket-session-clustering wire: a Publish from cache client A is
// delivered to a Subscribe on cache client B. This is the foundation
// signald's NewSessionManagerWithCache builds on — without
// cross-instance pub/sub delivery, message-arrival notifications
// would stall when the recipient's WebSocket lands on a different
// replica.
func TestPhase5Multiinstance_PubSubDeliversAcrossInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	cacheA := newMultiInstanceCache(t, mr)
	cacheB := newMultiInstanceCache(t, mr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, err := cacheB.Subscribe(ctx, "phase5:notify")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(func() { _ = sub.Close() })

	// Wait briefly for subscription to settle before publishing.
	time.Sleep(20 * time.Millisecond)
	received := make(chan []byte, 1)
	var once sync.Once
	go func() {
		for msg := range sub.Channel() {
			once.Do(func() { received <- msg.Payload })
			return
		}
	}()

	if _, err := cacheA.Publish(ctx, "phase5:notify", []byte("wake-up")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case got := <-received:
		if string(got) != "wake-up" {
			t.Errorf("payload = %q, want %q", got, "wake-up")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not receive Publish within 2s")
	}
}

// TestPhase5Multiinstance_HighFanout exercises the durability of the
// pub/sub wire under a quick burst: 50 messages from A, 50 from B,
// both sides consume each others' traffic with no drops.
func TestPhase5Multiinstance_HighFanout(t *testing.T) {
	mr := miniredis.RunT(t)
	cacheA := newMultiInstanceCache(t, mr)
	cacheB := newMultiInstanceCache(t, mr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	subA, err := cacheA.Subscribe(ctx, "phase5:bursty")
	if err != nil {
		t.Fatalf("subA: %v", err)
	}
	t.Cleanup(func() { _ = subA.Close() })
	subB, err := cacheB.Subscribe(ctx, "phase5:bursty")
	if err != nil {
		t.Fatalf("subB: %v", err)
	}
	t.Cleanup(func() { _ = subB.Close() })
	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(2)
	countA, countB := 0, 0
	go func() {
		defer wg.Done()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case _, ok := <-subA.Channel():
				if !ok {
					return
				}
				countA++
				if countA == 100 {
					return
				}
			case <-timer.C:
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case _, ok := <-subB.Channel():
				if !ok {
					return
				}
				countB++
				if countB == 100 {
					return
				}
			case <-timer.C:
				return
			}
		}
	}()

	// Two publishers, 50 messages each.
	for i := 0; i < 50; i++ {
		if _, err := cacheA.Publish(ctx, "phase5:bursty", []byte("a")); err != nil {
			t.Fatalf("publish A[%d]: %v", i, err)
		}
		if _, err := cacheB.Publish(ctx, "phase5:bursty", []byte("b")); err != nil {
			t.Fatalf("publish B[%d]: %v", i, err)
		}
	}
	wg.Wait()
	if countA != 100 {
		t.Errorf("subA received %d/100", countA)
	}
	if countB != 100 {
		t.Errorf("subB received %d/100", countB)
	}
}
