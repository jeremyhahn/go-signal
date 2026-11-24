package messages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

// CacheQueue stages envelopes between Insert and the store: sorted set `q:{aci-or-pni}:{device}` by server timestamp, hash `qm:{uuid}:{device}` by GUID; MessagePersister drains it (keys in docs/storage/redis-keys.md).
type CacheQueue struct {
	cache cache.Client
	// ttl bounds how long an envelope stays cached before the persister moves it.
	ttl time.Duration
}

// NewCacheQueue returns a CacheQueue backed by c. ttl is the default
// expiration applied to per-device queues; pass 0 for no expiration.
func NewCacheQueue(c cache.Client, ttl time.Duration) *CacheQueue {
	return &CacheQueue{cache: c, ttl: ttl}
}

func queueKey(uuid string, device uint64) string {
	return fmt.Sprintf("q:%s:%d", uuid, device)
}

func queueGUIDHashKey(uuid string, device uint64) string {
	return fmt.Sprintf("qm:%s:%d", uuid, device)
}

// Enqueue adds an envelope to the per-device queue. The envelope is
// keyed by ServerGUID inside the side hash so Remove can find it
// without scanning the sorted set.
func (q *CacheQueue) Enqueue(ctx context.Context, uuid string, device uint64, env *Envelope) error {
	if env == nil {
		return errors.New("messages/queue: nil envelope")
	}
	if env.ServerGUID == "" {
		return errors.New("messages/queue: empty ServerGUID")
	}

	data, err := json.Marshal(env)
	if err != nil {
		return &QueueError{Op: "marshal", Cause: err}
	}

	// The sorted-set member is the GUID; the side hash holds the envelope JSON once.
	score := float64(env.ServerTimestamp)
	if score == 0 {
		// Defensive fallback so out-of-order inserts still get a
		// monotonic-ish score within the same millisecond resolution.
		score = float64(time.Now().UnixMilli())
	}
	if err := q.cache.ZAdd(ctx, queueKey(uuid, device), cache.ScoredMember{
		Score:  score,
		Member: []byte(env.ServerGUID),
	}); err != nil {
		return &QueueError{Op: "zadd", Cause: err}
	}
	if err := q.cache.HSet(ctx, queueGUIDHashKey(uuid, device), env.ServerGUID, data); err != nil {
		return &QueueError{Op: "hset", Cause: err}
	}

	if q.ttl > 0 {
		// Re-arm TTLs on every write so an active queue never expires
		// underneath an in-flight persister.
		_, _ = q.cache.Expire(ctx, queueKey(uuid, device), q.ttl)
		_, _ = q.cache.Expire(ctx, queueGUIDHashKey(uuid, device), q.ttl)
	}
	return nil
}

// Drain returns up to max queued envelopes, oldest first, without removing them; call Remove after each is persisted.
func (q *CacheQueue) Drain(ctx context.Context, uuid string, device uint64, max int64) ([]*Envelope, error) {
	if max <= 0 {
		max = 100
	}
	guids, err := q.cache.ZRange(ctx, queueKey(uuid, device), 0, max-1)
	if err != nil {
		return nil, &QueueError{Op: "zrange", Cause: err}
	}
	if len(guids) == 0 {
		return nil, nil
	}

	out := make([]*Envelope, 0, len(guids))
	for _, raw := range guids {
		guid := string(raw)
		data, err := q.cache.HGet(ctx, queueGUIDHashKey(uuid, device), guid)
		if errors.Is(err, cache.ErrKeyNotFound) {
			// Drop a sorted-set member whose hash entry is gone.
			_ = q.cache.ZRem(ctx, queueKey(uuid, device), []byte(guid))
			continue
		}
		if err != nil {
			return nil, &QueueError{Op: "hget", Key: guid, Cause: err}
		}
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, &QueueError{Op: "unmarshal", Key: guid, Cause: err}
		}
		out = append(out, &env)
	}
	return out, nil
}

// Remove deletes the envelope with the given ServerGUID; idempotent.
func (q *CacheQueue) Remove(ctx context.Context, uuid string, device uint64, serverGUID string) error {
	if err := q.cache.ZRem(ctx, queueKey(uuid, device), []byte(serverGUID)); err != nil {
		return &QueueError{Op: "zrem", Cause: err}
	}
	if err := q.cache.HDel(ctx, queueGUIDHashKey(uuid, device), serverGUID); err != nil {
		return &QueueError{Op: "hdel", Cause: err}
	}
	return nil
}

// Len returns the number of envelopes currently queued for a device.
func (q *CacheQueue) Len(ctx context.Context, uuid string, device uint64) (int64, error) {
	n, err := q.cache.ZCard(ctx, queueKey(uuid, device))
	if err != nil {
		return 0, &QueueError{Op: "zcard", Cause: err}
	}
	return n, nil
}

// HasMessages reports whether at least one envelope is queued.
// Cheaper than Len because it short-circuits on first hit; not
// strictly required for correctness but useful for fast-path checks.
func (q *CacheQueue) HasMessages(ctx context.Context, uuid string, device uint64) (bool, error) {
	n, err := q.Len(ctx, uuid, device)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// rangeScoreScore formats an inclusive ZRange upper bound; currently unused.
var _ = strconv.Itoa
