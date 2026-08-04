// Package cache provides the Redis-shaped caching layer used by go-signal.
//
// The [Client] interface is the single entry point callers depend on. Two
// implementations ship:
//
//   - [memory] — in-process fake for unit tests and `make dev`. Thread-safe;
//     honours TTLs by virtue of a background sweeper goroutine.
//   - [redis]  — production-grade implementation atop github.com/redis/go-redis.
//
// The interface surface covers the operations ported from Java
// Signal-Server's Redis usage:
//
//   - Keyed values with TTL (rate-limit counters, push challenges,
//     message-availability flags).
//   - Atomic counters.
//   - Distributed locks via SET NX (leader election for workers).
//   - Sorted sets (per-device message queues).
//   - Hashes (multi-recipient message shared payloads).
//   - Pub/sub (cross-instance WebSocket delivery signals).
//
// Lua script execution is exposed as a primitive so the message-persister
// and MRM insert paths can port Java's atomic Lua scripts verbatim.
package cache
