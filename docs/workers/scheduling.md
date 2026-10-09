# Worker scheduling and leader election

> **Status: REFERENCE** · Last verified: 2026-10-09
> The `pkg/workers` scheduler: cron and continuous loops, the `Leaser` contract, `CacheLeaser` and shutdown.

The worker framework in `pkg/workers/` coordinates background jobs
across signald replicas. The design goals are:

1. A single worker never runs concurrently on two replicas, regardless
   of how many instances are deployed.
2. Failover is fast — if the current leader crashes, another replica
   takes over within one lease TTL (30 seconds by default).
3. Continuous workers (message persister, APN sender) absorb the
   steady-state workload; cron workers handle periodic cleanup.
4. Operators can invoke any worker on demand for maintenance without
   waiting for the next scheduled tick.

## Scheduler model

```
┌─────────────────────────────────────────────┐
│  signald replica N                          │
│                                             │
│  workers.Scheduler                          │
│  ┌─────────────┐   ┌──────────────────┐     │
│  │  cron loop  │   │ continuous loops │     │
│  └─────────────┘   └──────────────────┘     │
│         │                   │               │
│         ▼                   ▼               │
│  runWithLease(worker)                       │
│         │                                   │
│         ▼                                   │
│  Leaser.Acquire  ──────────┐                │
│         │                  │                │
│     success │         failed │              │
│         ▼                    ▼              │
│   worker.Run            return              │
│   (the work)         ErrLeaderElectionFailed│
│         │                                   │
│         ▼                                   │
│  Leaser.Release                             │
└─────────────────────────────────────────────┘
                 │
                 │ SET NX EX / DEL
                 ▼
         shared cache (Redis)
```

## The Leaser contract

`Leaser` exposes two methods:

```go
Acquire(ctx context.Context, key string, ttl time.Duration) error
Release(ctx context.Context, key string) error
```

`Acquire` returns `ErrLeaderElectionFailed` when another holder has
the lease; any other error is treated as transient and the worker
backs off.

`Release` is called after the worker completes. It is safe to call
even when Acquire failed — `CacheLeaser` tracks which tokens it
holds and no-ops on unknown keys.

`Release` runs on a detached context with a 5 second timeout, so a
cancelled worker context does not leak a held lease.

When `Config.Leaser` is nil (unit tests) every scheduler runs every
worker. signald always sets a `CacheLeaser` over its cache client, so
the lease is shared across replicas when the cache is Redis and is
process-local with the in-memory cache. `Config.LeaseTTL` defaults to
30 seconds.

## CacheLeaser

`workers.CacheLeaser` wraps a `cache.Client` so the Redis backend
does the heavy lifting. Lease keys are `workers:lease:{worker name}`
(the prefix is configurable) and the token is a random 16-byte hex
string. Implementation:

- Acquire calls `cache.Client.Lock(ctx, key, token, ttl)` which maps
  to Redis `SET NX` with a TTL. A held lease surfaces as
  `ErrLeaderElectionFailed`.
- On success, the token is recorded in memory against the lease key.
- Release calls `cache.Client.Unlock(ctx, key, token)` which runs a
  Lua script that `DEL`s only if the stored value matches the token.

The token mechanism prevents this race:

1. Replica A acquires lease for worker `W` with TTL 30s.
2. Replica A stalls (GC pause, slow Run body), the lease expires.
3. Replica B acquires the lease with its own token.
4. Replica A wakes up and calls Release.

Without tokens, Replica A's Release would delete Replica B's lease.
With them, it's a no-op — A's recorded token doesn't match B's.

## Schedule types

### Cron

Any schedule other than `@continuous` / `@on-demand` is added to a
`github.com/robfig/cron/v3` engine created with `cron.New()`. Standard
5-field specs (`0 3 * * *`) and `@every <duration>` shortcuts are
supported. An invalid spec makes `Start` fail. Failed runs are logged;
`ErrLeaderElectionFailed` is not.

### Continuous

`ScheduleContinuous` workers run in a loop:

1. Acquire the lease (if Leaser configured).
2. Run the worker.
3. On success, sleep 1 ms (to prevent CPU pegging for no-op bodies)
   and loop back to step 1.
4. On error, apply exponential backoff starting at 100 ms and capped
   at 30 s before looping.
5. On `ErrLeaderElectionFailed`, sleep for `LeaseTTL` before looping
   (another replica is leader and we shouldn't hammer the lease).

The 1 ms yield is invisible to real workers that block internally on
I/O (Redis `BRPOP`, sleeping on a timer). It prevents test stubs
from pegging a CPU core.

### On-demand

`ScheduleOnDemand` workers (`@on-demand`) are never started by the
scheduler. They run only through `Scheduler.RunOnce(ctx, name)`, which
executes any registered worker immediately regardless of schedule and
returns an error for an unknown name. `cmd/signald` currently exposes
only `start` and `version`, so no CLI command calls `RunOnce`.

Leader election still applies: `RunOnce` returns
`ErrLeaderElectionFailed` while another holder has the lease.

## Shutdown semantics

`Scheduler.Stop()`:

1. Cancels an internal derived context so continuous runners exit
   their loops. This happens even if the caller's original context is
   still alive, so Stop can be called unconditionally.
2. Stops the cron engine and waits for in-flight cron-scheduled
   invocations to complete.
3. Waits for every continuous runner goroutine to return via a
   `sync.WaitGroup`.

`Stop()` is idempotent; multiple calls are safe.
