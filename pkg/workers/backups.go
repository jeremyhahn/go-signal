package workers

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

// DefaultBackupExpiryGrace is the period after the last refresh of a
// backup before [RemoveExpiredBackupsWorker] purges it. Matches Java
// Signal-Server's 30-day RemoveExpiredBackupsCommand default.
const DefaultBackupExpiryGrace = 30 * 24 * time.Hour

// RemoveExpiredBackupsWorker periodically scans the backup store for
// rows whose last_refresh / last_media_refresh has elapsed beyond
// ExpiryGrace, removes their CDN content via [service.BackupService.ExpireBackup],
// and clears the metadata. Also purges garbage-collection rows left over
// from prior incomplete deletions.
//
// Mirrors Java's RemoveExpiredBackupsCommand. DryRun=true logs intended
// deletions without applying them — useful for first-rollout validation.
type RemoveExpiredBackupsWorker struct {
	svc         *service.SignalService
	log         *slog.Logger
	ExpiryGrace time.Duration
	Segments    int
	DryRun      bool
}

// NewRemoveExpiredBackupsWorker constructs the worker. Defaults: 30-day
// grace, 1 segment, DryRun=false. svc.Backups must be non-nil; the
// worker logs and no-ops if backups are not configured.
func NewRemoveExpiredBackupsWorker(svc *service.SignalService, log *slog.Logger, grace time.Duration) *RemoveExpiredBackupsWorker {
	if grace <= 0 {
		grace = DefaultBackupExpiryGrace
	}
	if log == nil {
		log = slog.Default()
	}
	return &RemoveExpiredBackupsWorker{
		svc:         svc,
		log:         log,
		ExpiryGrace: grace,
		Segments:    1,
	}
}

// Name matches Java's `remove-expired-backups` command.
func (*RemoveExpiredBackupsWorker) Name() string { return "remove-expired-backups" }

// Schedule runs the worker once per day at 04:30 UTC, offset from the
// other midnight-aligned jobs to spread CDN load.
func (*RemoveExpiredBackupsWorker) Schedule() Schedule { return "30 4 * * *" }

// Run scans every backup for rows past the expiry grace and removes them.
func (w *RemoveExpiredBackupsWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Backups == nil {
		w.log.InfoContext(ctx, "remove-expired-backups: backup service not configured, skipping")
		return nil
	}
	purgeTime := time.Now().UTC().Add(-w.ExpiryGrace)
	var expired []backups.ExpiredBackup
	if err := w.svc.Backups.GetExpiredBackups(ctx, w.Segments, purgeTime, func(e backups.ExpiredBackup) error {
		expired = append(expired, e)
		return nil
	}); err != nil {
		return err
	}
	w.log.InfoContext(ctx, "remove-expired-backups: scan complete",
		slog.Int("count", len(expired)),
		slog.Time("purgeTime", purgeTime),
		slog.Bool("dryRun", w.DryRun),
	)
	if w.DryRun {
		return nil
	}

	var deleteErrs []error
	for _, e := range expired {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.svc.Backups.ExpireBackup(ctx, e); err != nil {
			w.log.ErrorContext(ctx, "remove-expired-backups: failed to expire backup",
				slog.String("prefix", e.PrefixToDelete),
				slog.String("expirationType", expirationTypeName(e.ExpirationType)),
				slog.Any("error", err),
			)
			deleteErrs = append(deleteErrs, err)
			continue
		}
	}
	if len(deleteErrs) > 0 {
		return errors.Join(deleteErrs...)
	}
	return nil
}

// BackupUsageRecalculationWorker re-derives the per-backup media usage
// counts by re-listing the CDN media prefix and writing the result back
// to the store. This corrects quota drift from in-flight failed copies
// and is intended to run infrequently (Java default: weekly).
//
// Mirrors Java's BackupUsageRecalculationCommand.
type BackupUsageRecalculationWorker struct {
	svc      *service.SignalService
	log      *slog.Logger
	Segments int
}

// NewBackupUsageRecalculationWorker constructs the worker.
func NewBackupUsageRecalculationWorker(svc *service.SignalService, log *slog.Logger) *BackupUsageRecalculationWorker {
	if log == nil {
		log = slog.Default()
	}
	return &BackupUsageRecalculationWorker{
		svc:      svc,
		log:      log,
		Segments: 1,
	}
}

// Name matches Java's `backup-usage-recalculation`.
func (*BackupUsageRecalculationWorker) Name() string { return "backup-usage-recalculation" }

// Schedule runs weekly at 05:00 UTC Sunday.
func (*BackupUsageRecalculationWorker) Schedule() Schedule { return "0 5 * * 0" }

// Run walks every backup row, re-computes its usage against the CDN, and
// reports drift. Errors per-row are logged and accumulated; the worker
// still completes the scan to maximize the number of rows refreshed in
// each invocation.
func (w *BackupUsageRecalculationWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Backups == nil {
		w.log.InfoContext(ctx, "backup-usage-recalculation: backup service not configured, skipping")
		return nil
	}
	var (
		drifted   int
		processed int
		errs      []error
	)
	scanErr := w.svc.Backups.ListBackupAttributes(ctx, w.Segments, func(attrs backups.StoredAttributes) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		processed++
		result, err := w.svc.Backups.RecalculateQuota(ctx, attrs)
		if err != nil {
			w.log.ErrorContext(ctx, "backup-usage-recalculation: failed to recalculate",
				slog.Any("error", err),
			)
			errs = append(errs, err)
			return nil
		}
		if result == nil {
			return nil
		}
		if result.OldUsage != result.NewUsage {
			drifted++
			w.log.InfoContext(ctx, "backup-usage-recalculation: drift detected",
				slog.Int64("oldBytes", result.OldUsage.BytesUsed),
				slog.Int64("newBytes", result.NewUsage.BytesUsed),
				slog.Int64("oldCount", result.OldUsage.NumObjects),
				slog.Int64("newCount", result.NewUsage.NumObjects),
			)
		}
		return nil
	})
	w.log.InfoContext(ctx, "backup-usage-recalculation: scan complete",
		slog.Int("processed", processed),
		slog.Int("drifted", drifted),
	)
	if scanErr != nil {
		return scanErr
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// expirationTypeName returns a stable string name for an ExpirationType,
// used in log fields so operators can filter by it.
func expirationTypeName(t backups.ExpirationType) string {
	switch t {
	case backups.ExpireAll:
		return "all"
	case backups.ExpireMedia:
		return "media"
	case backups.ExpireGarbageCollection:
		return "garbage-collection"
	default:
		return "unknown"
	}
}
