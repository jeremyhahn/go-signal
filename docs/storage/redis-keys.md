# Redis key conventions

> **Status: REFERENCE** · Last verified: 2026-10-09
> Every key and channel pattern that go-signal writes through `pkg/cache.Client`.

The cache holds cross-request state that the domain stores should not carry: hot-path counters, delivery staging queues, shared multi-recipient payloads, cross-instance notifications and worker leases. The cache interface is `pkg/cache.Client` (`pkg/cache/cache.go`); the Redis (`pkg/cache/redis`) and in-memory (`pkg/cache/memory`) implementations use the same key layout. The memory backend does not run the Lua scripts that the multi-recipient cache and the Redis rate limiter need.

## Message queue

Source: `pkg/messages/queue.go` (`CacheQueue`).

| Key pattern | Type | Purpose |
|---|---|---|
| `q:{uuid}:{device}` | sorted set | Per-device queue. Member is the server GUID, score is `ServerTimestamp`. |
| `qm:{uuid}:{device}` | hash | Maps server GUID to the JSON envelope, so delete by GUID needs no scan. |

`{uuid}` is the destination ACI or PNI. The queue TTL is the `ttl` passed to `NewCacheQueue`. The `MessagePersister` worker drains these queues into the persistent `MessageStore`.

## Multi-recipient message (MRM) payloads

Source: `pkg/messages/mrm.go` (`MRMCache`).

| Key pattern | Type | TTL | Purpose |
|---|---|---|---|
| `mrm::{<uuid>}` | hash | 7 days (`MRMTTLSeconds`) | Field `data` holds the shared SealedSenderV2 multi-recipient ciphertext. One 18-byte field per recipient holds that recipient's view. |

The braces are a literal Redis cluster hash tag, so all operations on one message route to one shard. The layout is byte-compatible with the Java `MessagesCache`.

## Rate-limit buckets

Source: `pkg/limits/redis_limiter.go` (`RedisTokenBucketLimiter`).

| Key pattern | Type | Purpose |
|---|---|---|
| `ratelimit:{key}` | hash (`tokens`, `lastRefill`) | Token-bucket state, updated by one Lua script. |

The prefix is the limiter's `KeyPrefix`, default `ratelimit:`. Bucket sizes and refill rates come from `limits` in the configuration.

## Cross-instance WebSocket wake-up

Source: `pkg/websocket/manager.go`.

| Channel pattern | Purpose |
|---|---|
| `signal:ws:notify:{uuid}:{device}` | Published when a message arrives for a device with no local session; the instance holding the session subscribes and delivers. |

## Worker leases

Source: `pkg/workers/cache_leaser.go` (`CacheLeaser`).

| Key pattern | Type | TTL | Purpose |
|---|---|---|---|
| `workers:lease:{name}` | string | `LeaseTTL`, default 30 s | Leader-election lease for the worker `name`. |

The value is a random 16-byte hex token. Release succeeds only when the held token matches, so a lease that expired and was re-acquired elsewhere is not released by its previous holder.

## Conventions

- UUIDs use the canonical `8-4-4-4-12` form.
- Every new key pattern added to the code lands here in the same change.
