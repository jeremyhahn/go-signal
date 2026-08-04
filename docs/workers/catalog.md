# Worker catalog

Every worker currently registered by `workers.RegisterDefaults`
is listed here. Each entry mirrors a Java Signal-Server Dropwizard
command (see the "Java analogue" column) so operators familiar with
the Java deployment can map their runbooks directly.

All workers live in `pkg/workers/jobs.go`. They are registered on the
`Scheduler` returned by `workers.NewScheduler(Config{...})`.

## Schedule legend

- **Cron** expressions follow
  [robfig/cron/v3](https://pkg.go.dev/github.com/robfig/cron/v3)
  syntax: standard 5-field specs and `@every <duration>` are both
  supported.
- **Continuous** workers run in a tight loop with exponential backoff
  on error; a 1 ms yield between successful runs prevents CPU
  pegging when the body is a no-op.
- **On-demand** workers are invoked manually via
  `signald workers run <name>` and never fire automatically.

## Cleanup workers

| Worker                              | Schedule    | Java analogue                           | Reads                                    | Writes                                |
|-------------------------------------|-------------|-----------------------------------------|------------------------------------------|---------------------------------------|
| `remove-expired-accounts`           | `0 3 * * *` | `RemoveExpiredAccountsCommand`          | `accounts`                               | deletes stale accounts                |
| `remove-expired-linked-devices`     | `@every 1h` | `RemoveExpiredLinkedDevicesCommand`     | `accounts` → devices                     | unlinks idle secondary devices        |
| `remove-expired-username-holds`     | `@every 24h`| `RemoveExpiredUsernameHoldsCommand`     | `username:reservation:*`                 | deletes expired reservations          |
| `remove-orphaned-pre-key-pages`     | `@every 168h`| `RemoveOrphanedPreKeyPagesCommand`     | paged KEM pre-keys                       | prunes orphaned pages                 |

## Device activity

| Worker                         | Schedule    | Java analogue                          | Reads                     | Writes                        |
|--------------------------------|-------------|----------------------------------------|---------------------------|-------------------------------|
| `notify-idle-devices`          | `@every 1h` | `NotifyIdleDevicesCommand`             | `accounts` → device state | push notifications            |
| `unlink-idle-primary`          | `@every 24h`| `UnlinkDevicesWithIdlePrimaryCommand`  | `accounts` → device state | unlinks account's primary     |

## Continuous services

| Worker                       | Schedule     | Java analogue                                           | Reads             | Writes                        |
|------------------------------|--------------|---------------------------------------------------------|-------------------|-------------------------------|
| `message-persister`          | continuous   | `MessagePersisterServiceCommand`                        | Redis message queues | Persistent message store    |
| `process-scheduled-jobs`     | continuous   | `ProcessScheduledJobsServiceCommand`                    | `scheduledJobs`   | `scheduledJobs` (marks done)  |
| `scheduled-apn-sender`       | continuous   | `ScheduledApnPushNotificationSenderServiceCommand`      | APNs outbound queue | APNs API                    |

## On-demand administrative

| Worker                       | Java analogue                    | Use                                                    |
|------------------------------|----------------------------------|--------------------------------------------------------|
| `generate-certificate`       | `CertificateCommand`             | Regenerate delivery/group-sender certificates.         |
| `generate-zk-params`         | `ZkParamsCommand`                | Generate ZK group server parameters (deployment-time). |
| `check-dynamic-config`       | `CheckDynamicConfigurationCommand` | Validate `RemoteConfigs` after a config push.        |

## Phase 1 implementation notes

Every worker body is a stub at Phase 1 — they log and return nil. The
scheduling, leader election, and shutdown infrastructure is fully
wired; only the Run bodies are empty. Each body is filled in by the
phase that introduces its underlying data path:

- Cleanup workers: Phase 2.1 (when the relevant domain stores gain
  iteration APIs) and Phase 2.7 (usernames).
- `message-persister`: Phase 2.4.
- `notify-idle-devices` / `scheduled-apn-sender`: Phase 3.1 (push).
- `generate-certificate` / `generate-zk-params`: Phase 2.2 (ZK creds).
- `check-dynamic-config`: Phase 3.7 (dynamic config).
- `process-scheduled-jobs`: once a scheduledJobs table exists
  (Phase 2.4+).

Stubs registered early lets the operator verify the scheduling and
leader-election plumbing now, without waiting for every feature to
land.
