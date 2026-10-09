# Worker catalog

> **Status: REFERENCE** · Last verified: 2026-10-09
> Every worker registered by `workers.RegisterDefaults`: name, schedule and what it does.

All workers live in `pkg/workers/jobs.go` except the two backup workers in `pkg/workers/backups.go`. `cmd/signald` registers them on the `Scheduler` at startup (see [scheduling.md](scheduling.md)). Each worker mirrors a Java Signal-Server command of a similar name.

## Schedule legend

- **Cron** expressions follow [robfig/cron/v3](https://pkg.go.dev/github.com/robfig/cron/v3) syntax: standard 5-field specs and `@every <duration>`.
- **Continuous** workers run in a loop with exponential backoff on error and a 1 ms yield between successful runs.
- **On-demand** workers never fire automatically. They run only through `Scheduler.RunOnce`.

## Cleanup workers

| Worker | Schedule | Behavior |
|---|---|---|
| `remove-expired-accounts` | `0 3 * * *` | Deletes accounts whose primary device `LastSeen` is older than the expiry threshold (default 120 days). |
| `remove-expired-linked-devices` | `@every 1h` | Unlinks non-primary devices whose `LastSeen` is older than the link-expiry threshold. Never touches the primary device. |
| `remove-expired-username-holds` | `@every 24h` | Sweeps expired username-hash reservations. |
| `remove-orphaned-pre-key-pages` | `@every 168h` | Sweeps pre-keys whose account no longer exists. |
| `remove-expired-messages` | `@every 5m` | Deletes stored messages whose `expires_at` has passed (`MessageStore.RemoveExpired`). |
| `remove-expired-backups` | `30 4 * * *` | Removes backups past the expiry grace. Registered only when the backup service is configured. |
| `backup-usage-recalculation` | `0 5 * * 0` | Weekly recalculation of backup usage. Registered only when the backup service is configured. |

## Device activity

| Worker | Schedule | Behavior |
|---|---|---|
| `notify-idle-devices` | `@every 1h` | Evaluates every device against the eligibility criteria and sends a wake-up push to each eligible device. |
| `unlink-idle-primary` | `@every 24h` | Deletes any account whose primary device `LastSeen` is older than the primary-idle threshold. This is an account-level sweep at a more conservative threshold than `remove-expired-accounts`. |

## Continuous services

| Worker | Schedule | Behavior |
|---|---|---|
| `message-persister` | continuous | Drains the cache message queues into the persistent message store, bounded per device per tick. |
| `process-scheduled-jobs` | continuous | Drains one batch of due jobs through the scheduled-jobs manager. |
| `scheduled-apn-sender` | continuous | Processes the APN push jobs through its own scheduled-jobs manager. |

## On-demand administrative

| Worker | Use |
|---|---|
| `generate-certificate` | Regenerates delivery and group-sender certificates. |
| `generate-zk-params` | Generates ZK group server parameters. |
| `check-dynamic-config` | Re-fetches every remote-config row from the store to validate it. |

## Notes

- Every worker listed here has a working `Run` body.
- Workers whose dependencies are not configured (for example the backup workers without the backup service) return without doing work.
