// Package workers runs background jobs: each [Worker] is registered with a [Scheduler], which runs cron, continuous ([ScheduleContinuous]) or on-demand ([ScheduleOnDemand], via [Scheduler.RunOnce]) workers behind an optional leader lease.
package workers
