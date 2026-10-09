# Workers

> **Status: REFERENCE** · Last verified: 2026-10-09
> Index of the background-worker docs for `pkg/workers`.

Background workers run on a schedule or continuously inside signald, mirroring Java Signal-Server's Dropwizard commands.

| Document | Covers |
|---|---|
| [catalog.md](catalog.md) | Every registered worker: name, schedule, behavior. |
| [scheduling.md](scheduling.md) | In-process cron, continuous loops and cache-lease leader election for multi-instance deployments. |
