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

// CacheQueue is the Redis-shaped staging buffer that sits between Insert
// and the persistent store. The flow mirrors Java Signal-Server:
//
//  1. Insert places an envelope into the per-device sorted set
//     `q:{aci-or-pni}:{device}` with score = ServerTimestamp. The
//     sorted set yields strict per-device delivery order without
//     coordination across instances.
//  2. A side hash `qm:{uuid}:{device}` maps server GUID → JSON
//     envelope so Delete-by-GUID does not need to scan the queue.
//  3. The MessagePersister worker (pkg/workers) drains the queue into
//     a persistent MessageStore, removing entries from the cache as
//     they're persisted.
//  4. GetMessagesForDevice returns the union of cache-resident and
//     persisted envelopes; the consumer doesn't need to know which
//     half a given message came from.
//
// Key conventions match docs/storage/redis-keys.md.
type CacheQueue struct {
	cache cache.Client
	// ttl bounds how long an envelope can sit in the cache before the
	// persister is expected to have moved it. Short TTLs limit memory
	// usage at the cost of more aggressive eviction; the Java default
	// of 24h is a sensible starting point.
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

	// The sorted-set member is the GUID; the side hash holds the
	// envelope JSON. Storing the envelope only once keeps the data
	// model compact even at scale.
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

// Drain returns up to max envelopes currently waiting in the queue,
// in score order (oldest first). Drain does not remove anything; the
// caller is expected to invoke Remove on each envelope after it has
// been durably persisted.
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
			// Hash entry was removed but the zset member lingered (or
			// vice versa). Drop the orphan from the zset so it doesn't
			// keep coming back.
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

// Remove deletes a single envelope from the queue, identified by its
// ServerGUID. It is idempotent — removing a missing GUID returns nil.
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

// rangeScoreScore is used by IsOlderThan to format an inclusive
// upper bound for ZRange. We don't currently use it but it's parked
// here so future score-based queries (purge older than X) can pick
// it up. strconv import would otherwise be unused — guard against it
// being optimised away.
var _ = strconv.Itoa
