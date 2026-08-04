// Package workers is the background-job framework ported from Java
// Signal-Server's Dropwizard command layer.
//
// Each discrete scheduled task implements the [Worker] interface and is
// registered with a [Scheduler]. The scheduler owns a cron loop
// (github.com/robfig/cron/v3) plus an optional leader-election lease
// wrapper that gates execution to one instance at a time across a
// distributed deployment.
//
// Three execution shapes are supported:
//
//  1. Scheduled: the worker's [Worker.Schedule] returns a cron spec; the
//     scheduler fires it on the configured cadence.
//  2. Continuous: the worker's Schedule returns [ScheduleContinuous]. The
//     scheduler runs its [Worker.Run] once and, when Run returns nil,
//     re-invokes immediately. A non-nil error triggers exponential backoff
//     before the next attempt. This shape replaces the Java persistent
//     service commands (message persister, scheduled APN sender, etc.).
//  3. On-demand: Schedule returns [ScheduleOnDemand]. The scheduler does
//     not fire the worker automatically; callers trigger it explicitly
//     via [Scheduler.RunOnce]. Used for administrative commands (generate
//     certificates, etc.).
package workers
