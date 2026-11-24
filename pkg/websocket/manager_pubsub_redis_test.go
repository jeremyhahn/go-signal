package websocket

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisv9 "github.com/redis/go-redis/v9"

	cacheredis "github.com/jeremyhahn/go-signal/pkg/cache/redis"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// newMiniredisCacheClient returns a Redis-backed cache.Client wired to mr.
// Each call constructs an independent connection so callers can simulate
// distinct go-signal instances sharing the same Redis broker.
func newMiniredisCacheClient(t *testing.T, mr *miniredis.Miniredis) *cacheredis.Client {
	t.Helper()
	rdb := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return cacheredis.NewFromClient(rdb)
}

// TestNotifyMessageAvailable_CrossInstance_RealRedis: a notify on instance A flushes the session held by instance B over one miniredis.
func TestNotifyMessageAvailable_CrossInstance_RealRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	cacheA := newMiniredisCacheClient(t, mr)
	cacheB := newMiniredisCacheClient(t, mr)
	defer func() { _ = cacheA.Close() }()
	defer func() { _ = cacheB.Close() }()

	flusherB := &fakeFlusher{
		envs: []*messages.Envelope{{ID: 11, Type: messages.EnvelopeTypeCiphertext, DestinationUUID: "uuid-redis"}},
	}
	instanceA := NewSessionManagerWithCache(managerTestLogger(), cacheA, func(context.Context, string, uint64) ([]*messages.Envelope, error) {
		t.Helper()
		t.Errorf("instance A flusher should not be invoked")
		return nil, nil
	})
	instanceB := NewSessionManagerWithCache(managerTestLogger(), cacheB, flusherB.flush)

	session := newTestSession("uuid-redis", 5)
	instanceB.Register(session)
	defer instanceB.Unregister(session)

	// miniredis subscribes asynchronously; wait before publishing.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if mr.PubSubNumSub(notifyChannel("uuid-redis", 5))[notifyChannel("uuid-redis", 5)] >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := instanceA.NotifyMessageAvailable(context.Background(), "uuid-redis", 5); err != nil {
		t.Fatalf("instance A publish: %v", err)
	}

	select {
	case data := <-session.send:
		if len(data) == 0 {
			t.Error("envelope enqueued but body empty")
		}
	case <-time.After(time.Second):
		t.Fatal("instance B did not flush in response to Redis-pub/sub notify within deadline")
	}

	if got := flusherB.callCount(); got != 1 {
		t.Errorf("instance B flusher call count = %d; want 1", got)
	}
}

// TestNotifyMessageAvailable_CrossInstance_RealRedis_NoSessionElsewhere
// covers the "publish lands but nobody is subscribed" path against real
// Redis. The publish must succeed (Publish to Redis with zero subscribers
// is not an error), and neither flusher fires.
func TestNotifyMessageAvailable_CrossInstance_RealRedis_NoSessionElsewhere(t *testing.T) {
	mr := miniredis.RunT(t)
	cacheA := newMiniredisCacheClient(t, mr)
	defer func() { _ = cacheA.Close() }()

	called := false
	instanceA := NewSessionManagerWithCache(managerTestLogger(), cacheA, func(context.Context, string, uint64) ([]*messages.Envelope, error) {
		called = true
		return nil, nil
	})
	if err := instanceA.NotifyMessageAvailable(context.Background(), "uuid-nobody", 1); err != nil {
		t.Fatalf("publish with no subscribers should not error: %v", err)
	}
	// Give the system a brief moment in case any background dispatch fires.
	time.Sleep(50 * time.Millisecond)
	if called {
		t.Error("flusher must not fire when there is no local session")
	}
}
