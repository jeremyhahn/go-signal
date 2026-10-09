package workers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/jobs"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/push"
	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

// This file catalogs the Worker implementations ported from Java
// Signal-Server's Dropwizard command layer.
//
// Each Worker has:
//
//   - A stable Name that matches its Java counterpart where reasonable.
//     The name doubles as the leader-election lease key, so it must not
//     change across deployments.
//   - A Schedule describing when the Scheduler fires it. Cron specs use
//     github.com/robfig/cron/v3 syntax ("@every 1h", "0 3 * * *", etc.).
//   - A Run body that does the work.
//
// Phase 1 registers every known Java command as a Worker here. Bodies
// that need storage layers that are still in development are labelled
// below; they log and return nil until the underlying support lands.
// As each subsystem is implemented through Phase 2 the body is replaced
// with real logic.

// RemoveExpiredAccountsWorker deletes accounts idle for longer than
// ExpiryThreshold. Java default is 120 days; CLAUDE.md's retention policy
// can override.
type RemoveExpiredAccountsWorker struct {
	svc             *service.SignalService
	ExpiryThreshold time.Duration
}

// NewRemoveExpiredAccountsWorker constructs the worker using the default
// 120-day threshold when threshold is zero.
func NewRemoveExpiredAccountsWorker(svc *service.SignalService, threshold time.Duration) *RemoveExpiredAccountsWorker {
	if threshold <= 0 {
		threshold = 120 * 24 * time.Hour
	}
	return &RemoveExpiredAccountsWorker{svc: svc, ExpiryThreshold: threshold}
}

// Name matches Java's `remove-expired-accounts` command.
func (*RemoveExpiredAccountsWorker) Name() string { return "remove-expired-accounts" }

// Schedule runs the worker once per day at 03:00 UTC, matching Java's
// typical deployment cadence.
func (*RemoveExpiredAccountsWorker) Schedule() Schedule { return "0 3 * * *" }

// Run scans the account store and deletes any account whose most
// recent activity was before now - ExpiryThreshold. Activity is the
// primary device's LastSeen; matches Java
// RemoveExpiredAccountsCommand.isExpired.
//
// Errors on individual deletes are logged-and-continued so a single
// poison row doesn't stall the sweep. The aggregate count is logged
// at INFO so deployments can monitor churn over time.
func (w *RemoveExpiredAccountsWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Accounts == nil {
		return nil
	}
	cutoff := time.Now().UTC().Add(-w.ExpiryThreshold)
	var doomed []string
	if err := w.svc.Accounts.ListAll(ctx, func(a *accounts.Account) error {
		if a == nil {
			return nil
		}
		primary := a.GetDevice(accounts.PrimaryDeviceID)
		if primary == nil {
			return nil
		}
		if primary.LastSeen.Before(cutoff) {
			doomed = append(doomed, a.UUID)
		}
		return nil
	}); err != nil {
		return err
	}
	removed := 0
	for _, uuid := range doomed {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.svc.Accounts.Delete(ctx, uuid); err != nil {
			slog.WarnContext(ctx, "remove-expired-accounts: delete failed",
				slog.String("uuid", uuid),
				slog.Any("error", err))
			continue
		}
		removed++
	}
	if removed > 0 {
		slog.InfoContext(ctx, "remove-expired-accounts: swept",
			slog.Int("removed", removed),
			slog.Time("cutoff", cutoff))
	}
	return nil
}

// RemoveExpiredLinkedDevicesWorker unlinks secondary devices that have
// not checked in for LinkExpiryThreshold (Java default 45 days).
type RemoveExpiredLinkedDevicesWorker struct {
	svc                 *service.SignalService
	LinkExpiryThreshold time.Duration
}

// NewRemoveExpiredLinkedDevicesWorker constructs the worker.
func NewRemoveExpiredLinkedDevicesWorker(svc *service.SignalService, threshold time.Duration) *RemoveExpiredLinkedDevicesWorker {
	if threshold <= 0 {
		threshold = 45 * 24 * time.Hour
	}
	return &RemoveExpiredLinkedDevicesWorker{svc: svc, LinkExpiryThreshold: threshold}
}

// Name matches Java's `remove-expired-linked-devices`.
func (*RemoveExpiredLinkedDevicesWorker) Name() string { return "remove-expired-linked-devices" }

// Schedule runs hourly.
func (*RemoveExpiredLinkedDevicesWorker) Schedule() Schedule { return "@every 1h" }

// Run scans every account and unlinks linked (non-primary) devices
// whose LastSeen is before now - LinkExpiryThreshold. Mirrors Java
// RemoveExpiredLinkedDevicesCommand. The primary device is never
// touched here; account-level expiry is handled by
// [RemoveExpiredAccountsWorker].
func (w *RemoveExpiredLinkedDevicesWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Accounts == nil {
		return nil
	}
	cutoff := time.Now().UTC().Add(-w.LinkExpiryThreshold)
	type victim struct {
		uuid     string
		deviceID uint64
	}
	var victims []victim
	if err := w.svc.Accounts.ListAll(ctx, func(a *accounts.Account) error {
		if a == nil {
			return nil
		}
		for _, d := range a.Devices {
			if d.ID == accounts.PrimaryDeviceID {
				continue
			}
			if d.LastSeen.Before(cutoff) {
				victims = append(victims, victim{uuid: a.UUID, deviceID: d.ID})
			}
		}
		return nil
	}); err != nil {
		return err
	}
	removed := 0
	for _, v := range victims {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := w.svc.Accounts.RemoveDevice(ctx, v.uuid, v.deviceID); err != nil {
			slog.WarnContext(ctx, "remove-expired-linked-devices: unlink failed",
				slog.String("uuid", v.uuid),
				slog.Uint64("deviceId", v.deviceID),
				slog.Any("error", err))
			continue
		}
		removed++
	}
	if removed > 0 {
		slog.InfoContext(ctx, "remove-expired-linked-devices: swept",
			slog.Int("removed", removed),
			slog.Time("cutoff", cutoff))
	}
	return nil
}

// RemoveExpiredUsernameHoldsWorker clears username hash reservations
// whose TTL has expired without confirmation.
type RemoveExpiredUsernameHoldsWorker struct {
	svc *service.SignalService
}

// NewRemoveExpiredUsernameHoldsWorker constructs the worker.
func NewRemoveExpiredUsernameHoldsWorker(svc *service.SignalService) *RemoveExpiredUsernameHoldsWorker {
	return &RemoveExpiredUsernameHoldsWorker{svc: svc}
}

// Name matches Java's `remove-expired-username-holds`.
func (*RemoveExpiredUsernameHoldsWorker) Name() string { return "remove-expired-username-holds" }

// Schedule runs daily.
func (*RemoveExpiredUsernameHoldsWorker) Schedule() Schedule { return "@every 24h" }

// Run sweeps every expired username-hash reservation. Idempotent;
// safe to run from any node on any cadence. Mirrors Java
// RemoveExpiredUsernameHoldsCommand.
func (w *RemoveExpiredUsernameHoldsWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Usernames == nil {
		return nil
	}
	removed, err := w.svc.Usernames.DeleteExpiredReservations(ctx)
	if err != nil {
		return err
	}
	if removed > 0 {
		slog.InfoContext(ctx, "remove-expired-username-holds: swept",
			slog.Int("removed", removed))
	}
	return nil
}

// RemoveOrphanedPreKeyPagesWorker collects KEM pre-key pages that no
// longer have a referencing account.
type RemoveOrphanedPreKeyPagesWorker struct {
	svc *service.SignalService
}

// NewRemoveOrphanedPreKeyPagesWorker constructs the worker.
func NewRemoveOrphanedPreKeyPagesWorker(svc *service.SignalService) *RemoveOrphanedPreKeyPagesWorker {
	return &RemoveOrphanedPreKeyPagesWorker{svc: svc}
}

// Name matches Java's `remove-orphaned-pre-key-pages`.
func (*RemoveOrphanedPreKeyPagesWorker) Name() string { return "remove-orphaned-pre-key-pages" }

// Schedule runs weekly.
func (*RemoveOrphanedPreKeyPagesWorker) Schedule() Schedule { return "@every 168h" }

// orphanPreKeySweepAbortRatio caps the fraction of transient
// (non-NotFound) lookup failures the sweep tolerates before
// aborting. Set conservatively because the action is irreversible
// — a degraded account store must not be allowed to trigger mass
// pre-key deletion.
const orphanPreKeySweepAbortRatio = 0.10

// Run scans the pre-key store for every account UUID with rows and
// deletes those whose owning account is gone from the accounts
// store. Mirrors the intent of Java's
// RemoveOrphanedPreKeyPagesCommand (which sweeps unreferenced
// DynamoDB pages) — go-signal's schema stores keys per-account
// rather than in pages, so the orphan criterion is "no matching
// account row" rather than "no current page reference."
//
// Safety invariants:
//   - Deletion fires ONLY when Accounts.Get returns a typed
//     *accounts.AccountNotFoundError. Transient errors (network,
//     timeout, cancellation) are surfaced via the
//     orphanPreKeySweepAbortRatio guard — a sweep with too many
//     ambiguous lookups aborts before deleting anything, on the
//     theory that the account store itself is degraded.
//   - Errors on individual deletes are logged and the sweep
//     continues; a poison row never stalls the whole job.
func (w *RemoveOrphanedPreKeyPagesWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Accounts == nil || w.svc.Keys == nil {
		return nil
	}
	uuids, err := w.svc.Keys.ListAccountUUIDs(ctx)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "remove-orphaned-pre-key-pages: list uuids", err)
	}
	if len(uuids) == 0 {
		return nil
	}

	// First pass: classify each UUID as ALIVE, ORPHAN, or
	// TRANSIENT. Deletion is deferred until the whole batch is
	// classified so we can abort on a degraded account store
	// before doing any destructive work.
	doomed := make([]string, 0, len(uuids))
	transientFailures := 0
	for _, uuid := range uuids {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, lookupErr := w.svc.Accounts.Get(ctx, uuid)
		if lookupErr == nil {
			continue // alive
		}
		var nf *accounts.AccountNotFoundError
		if errors.As(lookupErr, &nf) {
			doomed = append(doomed, uuid)
			continue
		}
		// Anything that is not a typed "not found" is a
		// transient failure (timeout, ctx error wrapped, network
		// blip, decode failure). Log and count — do NOT delete.
		transientFailures++
		slog.WarnContext(ctx, "remove-orphaned-pre-key-pages: transient lookup failure",
			slog.String("uuid", uuid),
			slog.Any("error", lookupErr))
	}

	// Abort if too many lookups were ambiguous. orphanPreKeySweepAbortRatio
	// is intentionally low because mass deletion is irreversible.
	if ratio := float64(transientFailures) / float64(len(uuids)); ratio > orphanPreKeySweepAbortRatio {
		slog.WarnContext(ctx, "remove-orphaned-pre-key-pages: aborting sweep — account store degraded",
			slog.Int("scanned", len(uuids)),
			slog.Int("transientFailures", transientFailures),
			slog.Float64("ratio", ratio))
		return signalerrors.New(signalerrors.ErrInternal, fmt.Sprintf("remove-orphaned-pre-key-pages: aborted (transient failure ratio %.2f exceeds %.2f)",
			ratio, orphanPreKeySweepAbortRatio))
	}

	removed := 0
	preserved := 0
	for _, uuid := range doomed {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Race guard: between the classify pass and now an
		// account with the same UUID can have been created
		// (manual re-registration, replay attack against the
		// admin API, etc.). Re-confirm not-found before any
		// destructive action; surface every state other than
		// the typed NotFound as "preserve."
		_, recheck := w.svc.Accounts.Get(ctx, uuid)
		if recheck == nil {
			preserved++
			slog.InfoContext(ctx, "remove-orphaned-pre-key-pages: account resurrected between passes — preserving keys",
				slog.String("uuid", uuid))
			continue
		}
		var nf *accounts.AccountNotFoundError
		if !errors.As(recheck, &nf) {
			preserved++
			continue
		}
		if err := w.svc.Keys.DeleteAllForAccount(ctx, uuid); err != nil {
			slog.WarnContext(ctx, "remove-orphaned-pre-key-pages: delete failed",
				slog.String("uuid", uuid),
				slog.Any("error", err))
			continue
		}
		removed++
	}
	if removed > 0 || preserved > 0 {
		slog.InfoContext(ctx, "remove-orphaned-pre-key-pages: swept",
			slog.Int("removed", removed),
			slog.Int("preserved", preserved),
			slog.Int("scanned", len(uuids)))
	}
	return nil
}

// NotifyIdleDevicesWorker wakes devices that have not connected
// recently AND have pending messages waiting. Mirrors Java's
// NotifyIdleDevicesCommand — Java schedules the notification via a
// scheduled-jobs table; we dispatch immediately through the
// PushManager because go-signal does not yet have a scheduled-jobs
// table.
//
// Eligibility (must hold all):
//   - The device has a push token (APNs or FCM).
//   - The device's LastSeen is more than NotifyInterval ago.
//   - At least one undelivered message envelope is queued for the
//     device. (Sending a wake-up push to a device with an empty
//     queue burns the APNs/FCM quota for nothing — Java's
//     IdleWakeupEligibilityChecker has the same precondition.)
type NotifyIdleDevicesWorker struct {
	svc            *service.SignalService
	pushMgr        *push.PushManager
	NotifyInterval time.Duration
}

// NewNotifyIdleDevicesWorker constructs the worker. pushMgr may be
// nil — Run becomes a no-op in that case (deployment has no push
// pipeline configured).
func NewNotifyIdleDevicesWorker(svc *service.SignalService, pushMgr *push.PushManager, interval time.Duration) *NotifyIdleDevicesWorker {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	return &NotifyIdleDevicesWorker{svc: svc, pushMgr: pushMgr, NotifyInterval: interval}
}

// Name matches Java's `notify-idle-devices`.
func (*NotifyIdleDevicesWorker) Name() string { return "notify-idle-devices" }

// Schedule runs hourly.
func (*NotifyIdleDevicesWorker) Schedule() Schedule { return "@every 1h" }

// Run scans every account, evaluates each device against the
// eligibility criteria, and dispatches a wake-up push for each
// eligible device.
func (w *NotifyIdleDevicesWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Accounts == nil || w.svc.Messages == nil || w.pushMgr == nil {
		return nil
	}
	cutoff := time.Now().UTC().Add(-w.NotifyInterval)
	sent := 0
	skipped := 0
	err := w.svc.Accounts.ListAll(ctx, func(a *accounts.Account) error {
		if a == nil {
			return nil
		}
		for _, d := range a.Devices {
			if err := ctx.Err(); err != nil {
				return err
			}
			notif, ok := buildIdleWakeup(a.UUID, &d, cutoff)
			if !ok {
				skipped++
				continue
			}
			// Skip when the device has no pending messages.
			// HasMessagesForDevice is a LIMIT-1 / key-existence
			// check — the full envelope set is never materialised
			// just to learn whether the queue is empty.
			has, err := w.svc.Messages.HasMessagesForDevice(ctx, a.UUID, d.ID)
			if err != nil {
				slog.WarnContext(ctx, "notify-idle-devices: queue probe failed",
					slog.String("uuid", a.UUID),
					slog.Uint64("deviceId", d.ID),
					slog.Any("error", err))
				continue
			}
			if !has {
				skipped++
				continue
			}
			if _, sendErr := w.pushMgr.Send(ctx, notif); sendErr != nil {
				slog.WarnContext(ctx, "notify-idle-devices: send failed",
					slog.String("uuid", a.UUID),
					slog.Uint64("deviceId", d.ID),
					slog.Any("error", sendErr))
				continue
			}
			sent++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if sent > 0 {
		slog.InfoContext(ctx, "notify-idle-devices: dispatched",
			slog.Int("sent", sent),
			slog.Int("skipped", skipped))
	}
	return nil
}

// buildIdleWakeup returns a PushNotification for the device when it
// is push-capable AND its LastSeen is before cutoff. The ok=false
// path covers devices with no push token or that are not yet idle.
func buildIdleWakeup(accountUUID string, d *accounts.Device, cutoff time.Time) (*push.PushNotification, bool) {
	if d == nil {
		return nil, false
	}
	if !d.LastSeen.Before(cutoff) {
		return nil, false
	}
	if d.ApnRegistrationID != "" {
		return &push.PushNotification{
			AccountUUID: accountUUID,
			DeviceID:    d.ID,
			DeviceToken: d.ApnRegistrationID,
			DeviceType:  push.DeviceTypeAPNs,
			Type:        push.NotificationTypeNotification,
		}, true
	}
	if d.GcmRegistrationID != "" {
		return &push.PushNotification{
			AccountUUID: accountUUID,
			DeviceID:    d.ID,
			DeviceToken: d.GcmRegistrationID,
			DeviceType:  push.DeviceTypeFCM,
			Type:        push.NotificationTypeNotification,
		}, true
	}
	return nil, false
}

// UnlinkIdlePrimaryDevicesWorker deletes accounts whose primary
// device has been idle longer than the Java primary-idle threshold
// (180 days). Distinct from [RemoveExpiredAccountsWorker] which
// applies a tighter 120-day account-level threshold by default —
// deployments may run both with different cadences.
type UnlinkIdlePrimaryDevicesWorker struct {
	svc                  *service.SignalService
	PrimaryIdleThreshold time.Duration
}

// DefaultPrimaryIdleThreshold mirrors Java
// Device.ALLOWED_PRIMARY_IDLE_MILLIS (180 days).
const DefaultPrimaryIdleThreshold = 180 * 24 * time.Hour

// NewUnlinkIdlePrimaryDevicesWorker constructs the worker. threshold
// defaults to DefaultPrimaryIdleThreshold when zero or negative.
func NewUnlinkIdlePrimaryDevicesWorker(svc *service.SignalService) *UnlinkIdlePrimaryDevicesWorker {
	return &UnlinkIdlePrimaryDevicesWorker{svc: svc, PrimaryIdleThreshold: DefaultPrimaryIdleThreshold}
}

// Name matches Java's `unlink-idle-primary`.
func (*UnlinkIdlePrimaryDevicesWorker) Name() string { return "unlink-idle-primary" }

// Schedule runs daily.
func (*UnlinkIdlePrimaryDevicesWorker) Schedule() Schedule { return "@every 24h" }

// Run scans every account; for any whose primary device's LastSeen
// is before now - PrimaryIdleThreshold, the account is deleted. An
// account cannot exist without a primary device, so this is
// functionally an account-level sweep at a more conservative
// threshold than [RemoveExpiredAccountsWorker]. Errors on individual
// deletes are logged-and-continued.
func (w *UnlinkIdlePrimaryDevicesWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Accounts == nil {
		return nil
	}
	threshold := w.PrimaryIdleThreshold
	if threshold <= 0 {
		threshold = DefaultPrimaryIdleThreshold
	}
	cutoff := time.Now().UTC().Add(-threshold)
	var doomed []string
	if err := w.svc.Accounts.ListAll(ctx, func(a *accounts.Account) error {
		if a == nil {
			return nil
		}
		primary := a.GetDevice(accounts.PrimaryDeviceID)
		if primary == nil {
			return nil
		}
		if primary.LastSeen.Before(cutoff) {
			doomed = append(doomed, a.UUID)
		}
		return nil
	}); err != nil {
		return err
	}
	removed := 0
	for _, uuid := range doomed {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.svc.Accounts.Delete(ctx, uuid); err != nil {
			slog.WarnContext(ctx, "unlink-idle-primary: delete failed",
				slog.String("uuid", uuid),
				slog.Any("error", err))
			continue
		}
		removed++
	}
	if removed > 0 {
		slog.InfoContext(ctx, "unlink-idle-primary: swept",
			slog.Int("removed", removed),
			slog.Time("cutoff", cutoff))
	}
	return nil
}

// MessagePersisterWorker drains the Redis message cache into persistent
// storage. Continuous — the worker scheduler invokes Run repeatedly with
// a small idle yield between successful runs. This is the Go port of
// Java's MessagePersisterServiceCommand.
//
// In production the *messages.MessagePersister is constructed in
// cmd/signald/start.go with the wired-up cache queue, durable
// MessageStore, and PersisterDeviceLister; the worker is just the
// scheduling shim around it. When persister is nil (e.g. in test
// fixtures that haven't wired the message pipeline) Run is a no-op
// so the worker can still be registered safely.
type MessagePersisterWorker struct {
	svc       *service.SignalService
	persister *messages.MessagePersister
}

// NewMessagePersisterWorker constructs the worker. persister may be
// nil; when it is, Run does nothing.
func NewMessagePersisterWorker(svc *service.SignalService, persister *messages.MessagePersister) *MessagePersisterWorker {
	return &MessagePersisterWorker{svc: svc, persister: persister}
}

// Name matches Java's `message-persister`.
func (*MessagePersisterWorker) Name() string { return "message-persister" }

// Schedule runs continuously.
func (*MessagePersisterWorker) Schedule() Schedule { return ScheduleContinuous }

// Run drains the cache queue once. The continuous worker loop
// re-invokes after the scheduler's idleYield, so each tick is bounded
// to MaxPerDevice envelopes per device.
func (w *MessagePersisterWorker) Run(ctx context.Context) error {
	if w.persister == nil {
		return nil
	}
	return w.persister.RunOnce(ctx)
}

// DefaultMessageExpiryGrace is the period after a per-message expires_at
// timestamp before [RemoveExpiredMessagesWorker] purges the row. Java
// Signal-Server's RemoveExpiredMessagesCommand sweeps with zero grace; we
// keep the constant configurable so deployments with skewed clocks can
// soften the cutoff if needed.
const DefaultMessageExpiryGrace = 0

// RemoveExpiredMessagesWorker periodically sweeps the messages table for
// rows whose per-row expires_at is strictly before time.Now() - ExpiryGrace.
// Today only the postgres backend records expires_at, so the worker is
// effectively a postgres-only sweep; memory and qrdb implementations return
// zero rows removed. Mirrors Java's RemoveExpiredMessagesCommand.
type RemoveExpiredMessagesWorker struct {
	svc         *service.SignalService
	ExpiryGrace time.Duration
}

// NewRemoveExpiredMessagesWorker constructs the worker. grace defaults to
// [DefaultMessageExpiryGrace] when zero.
func NewRemoveExpiredMessagesWorker(svc *service.SignalService, grace time.Duration) *RemoveExpiredMessagesWorker {
	return &RemoveExpiredMessagesWorker{svc: svc, ExpiryGrace: grace}
}

// Name matches Java's `remove-expired-messages` command name; doubles as
// the leader-election lease key.
func (*RemoveExpiredMessagesWorker) Name() string { return "remove-expired-messages" }

// Schedule runs every 5 minutes to keep the table bounded under burst
// inserts while remaining cheap on a healthy database.
func (*RemoveExpiredMessagesWorker) Schedule() Schedule { return "@every 5m" }

// Run sweeps every message whose expires_at is strictly before
// (now - ExpiryGrace). The deletion runs against whichever MessageStore is
// wired into the service; backends without an expires_at column return 0
// rows so the worker is a uniform no-op there.
func (w *RemoveExpiredMessagesWorker) Run(ctx context.Context) error {
	if w.svc == nil || w.svc.Messages == nil {
		return nil
	}
	cutoff := time.Now().UTC().Add(-w.ExpiryGrace)
	_, err := w.svc.Messages.RemoveExpired(ctx, cutoff)
	return err
}

// ScheduledJobsWorker executes items from the `scheduled_jobs` table
// at their scheduled time. Port of Java's
// ProcessScheduledJobsServiceCommand.
type ScheduledJobsWorker struct {
	svc *service.SignalService
	mgr *jobs.Manager
}

// NewScheduledJobsWorker constructs the worker. mgr may be nil —
// the deployment is responsible for wiring the persistence store +
// registering handlers before passing it in.
func NewScheduledJobsWorker(svc *service.SignalService, mgr *jobs.Manager) *ScheduledJobsWorker {
	return &ScheduledJobsWorker{svc: svc, mgr: mgr}
}

// Name matches Java's `process-scheduled-jobs`.
func (*ScheduledJobsWorker) Name() string { return "process-scheduled-jobs" }

// Schedule runs continuously.
func (*ScheduledJobsWorker) Schedule() Schedule { return ScheduleContinuous }

// Run drains one batch of due jobs through the configured
// jobs.Manager. When the manager is nil the deployment has not
// wired the scheduled-jobs subsystem and Run is a no-op.
func (w *ScheduledJobsWorker) Run(ctx context.Context) error {
	if w.mgr == nil {
		return nil
	}
	_, err := w.mgr.RunOnce(ctx, time.Now().UTC())
	return err
}

// APNPushSenderWorker drains queued APNs notifications. Port of Java's
// ScheduledApnPushNotificationSenderServiceCommand.
type APNPushSenderWorker struct {
	svc *service.SignalService
	mgr *jobs.Manager
}

// JobTypeAPNPushSend is the job type registered on the dedicated
// scheduled-jobs Manager that the APN sender drains. Producers
// (request handlers that defer a push) enqueue jobs with this Type.
const JobTypeAPNPushSend = "apn.push.send"

// NewAPNPushSenderWorker constructs the worker. mgr should be a
// jobs.Manager wired with a registered handler for
// JobTypeAPNPushSend that dispatches the payload via push.Manager.
func NewAPNPushSenderWorker(svc *service.SignalService, mgr *jobs.Manager) *APNPushSenderWorker {
	return &APNPushSenderWorker{svc: svc, mgr: mgr}
}

// Name matches Java's `scheduled-apn-sender`.
func (*APNPushSenderWorker) Name() string { return "scheduled-apn-sender" }

// Schedule runs continuously.
func (*APNPushSenderWorker) Schedule() Schedule { return ScheduleContinuous }

// Run is a thin shim over the scheduled-jobs manager that processes
// only APNs-typed jobs. Job payloads are JSON-encoded
// push.PushNotification structures; the registered handler
// dispatches them via push.PushManager.Send.
//
// The actual draining loop is delegated to jobs.Manager.RunOnce —
// the APN worker is just a separate scheduler entry so operators
// can throttle / pause it independently from the general
// process-scheduled-jobs worker (matches Java's split between
// ProcessScheduledJobsServiceCommand and
// ScheduledApnPushNotificationSenderServiceCommand).
func (w *APNPushSenderWorker) Run(ctx context.Context) error {
	if w.mgr == nil {
		return nil
	}
	_, err := w.mgr.RunOnce(ctx, time.Now().UTC())
	return err
}

// CertificateRotationWorker regenerates the delivery-certificate
// signing key on demand and installs it on the live
// CertificatesManager. Matches Java's `certificate` command: the
// operator runs it once at deployment time to mint a fresh
// Ed25519 keypair and a server-certificate id. The new public key +
// keyId are emitted via structured log so the operator can publish
// them to mobile clients and persist them in yaml config to survive
// process restart.
//
// Multi-instance safety: the scheduler's leader election prevents
// concurrent generation across the fleet. After the leader runs the
// rotation, follower instances must be restarted (or their cert
// managers receive the new key via reload) to pick up the new
// material. This matches the Java operator workflow exactly — Java's
// command is a one-shot deployment task, not a live cron.
type CertificateRotationWorker struct {
	svc        *service.SignalService
	certsMgr   *certificates.CertificatesManager
	randSource io.Reader
	nowFn      func() time.Time
}

// NewCertificateRotationWorker constructs the worker. certsMgr may
// be nil — when so Run is a no-op (operator hasn't wired the certs
// manager).
func NewCertificateRotationWorker(svc *service.SignalService, certsMgr *certificates.CertificatesManager) *CertificateRotationWorker {
	return &CertificateRotationWorker{svc: svc, certsMgr: certsMgr, randSource: rand.Reader, nowFn: time.Now}
}

// Name matches Java's `generate-certificate`.
func (*CertificateRotationWorker) Name() string { return "generate-certificate" }

// Schedule is on-demand.
func (*CertificateRotationWorker) Schedule() Schedule { return ScheduleOnDemand }

// certKeyIDEpoch is the reference point from which keyId is
// measured. Using a 2026 epoch instead of the Unix epoch buys
// 136 years of monotonic uint32 keyIds (until 2162) before the
// wire field needs to widen. The Signal certificate.id proto is
// uint32 today; this var is the contract that keeps keyIds
// monotonic and wrap-free for the deployment's lifetime.
//
// MUST NOT be mutated outside this package. Tests that need to
// stub the wall clock should override CertificateRotationWorker.nowFn
// — never the epoch. Mutating the epoch invalidates already-issued
// keyIds and is unrecoverable.
//
// It is declared `var` rather than `const` only because time.Date
// is not a const expression in Go.
var certKeyIDEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// maxCertKeyID guards against uint32 overflow when seconds-since-
// certKeyIDEpoch is large enough to wrap. After this point the
// worker refuses to issue a new key and surfaces the error so an
// operator can widen the on-wire field (proto schema change) before
// the next rotation.
const maxCertKeyID uint32 = 0xFFFFFFFF

// reservedCertificateKeyIDs mirrors Java's
// RESERVED_CERTIFICATE_IDS set in
// service/src/main/java/org/whispersystems/textsecuregcm/workers/CertificateCommand.java.
// Java reserves these for libsignal interop testing — a deployed
// keyId matching one of them would be rejected by clients. Keep
// this list in sync with the Java source; the order is irrelevant
// since the lookup is linear.
var reservedCertificateKeyIDs = []uint32{
	0xDEADC357, // libsignal "dead cert" — treated as revoked by clients
	0x7357C357, // libsignal "test cert" — signed by the testing trust root
}

// Run generates a fresh Ed25519 keypair, installs the private key on
// the CertificatesManager, and emits a structured log of the public
// key + keyId so the operator can publish the new material. keyId is
// monotonic seconds since certKeyIDEpoch so Signal clients always
// pick the most recent verifying key.
//
// Returns an error rather than wrapping silently when the keyId
// would overflow uint32. That moment is ~year 2162; long before then
// the proto field will need widening to uint64 and this code can be
// updated in lock-step.
func (w *CertificateRotationWorker) Run(ctx context.Context) error {
	if w.certsMgr == nil {
		return nil
	}
	source := w.randSource
	if source == nil {
		source = rand.Reader
	}
	now := w.nowFn
	if now == nil {
		now = time.Now
	}

	pub, priv, err := ed25519.GenerateKey(source)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "generate-certificate: generate keypair", err)
	}

	delta := now().UTC().Sub(certKeyIDEpoch).Seconds()
	if delta < 0 {
		return signalerrors.New(signalerrors.ErrInternal, "generate-certificate: clock is before certKeyIDEpoch ("+certKeyIDEpoch.Format(time.RFC3339)+") — refusing to issue a keyId that would collide with future rotations")
	}
	if delta > float64(maxCertKeyID) {
		return signalerrors.New(signalerrors.ErrInternal, fmt.Sprintf("generate-certificate: seconds-since-certKeyIDEpoch (%.0f) overflows uint32 — widen the ServerCertificate.id proto field before next rotation", delta))
	}
	keyID := uint32(delta)
	// Mirror Java's RESERVED_CERTIFICATE_IDS guard. Bump past every
	// reserved value so the keyId is monotonic and unreserved; loop
	// until no reserved hit remains so adjacent reserved IDs (e.g.
	// the 0xDEAD_xxxx cluster, should it ever grow contiguous)
	// cannot leave us still landed on a reserved value after a
	// single hop. The doc comment previously claimed this was
	// recursive but the implementation was single-hop only.
	for {
		bumped := false
		for _, reserved := range reservedCertificateKeyIDs {
			if keyID == reserved {
				keyID++
				bumped = true
				break
			}
		}
		if !bumped {
			break
		}
	}

	if err := w.certsMgr.SetEd25519SigningKey(ctx, priv, keyID); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "generate-certificate: install signing key", err)
	}

	slog.InfoContext(ctx, "generate-certificate: regenerated Ed25519 delivery-cert signing key",
		slog.Uint64("keyId", uint64(keyID)),
		slog.String("publicKey", base64.StdEncoding.EncodeToString(pub)),
		slog.String("notice", "publish the public key + keyId above to mobile clients; restart followers to pick up the new private key"))
	return nil
}

// ZKParamsWorker regenerates the ZK group parameters and installs
// them on the live CertificatesManager. On-demand; matches Java's
// `zkparams` command — the seed material is delivered via the
// configured SeedSink (typically a one-shot 0600 file) so it never
// enters the structured log stream. The INFO log carries only a
// SHA-256 fingerprint so the run is observable without leaking the
// secret.
//
// Mirrors the Java command surface:
//   - Java prints base64(serverPublicParams) and base64(serverSecretParams)
//   - go-libsignal does not yet expose bincode Serialize for the secret
//     params, but the params are derived deterministically from a
//     32-byte randomness seed via GenerateServerSecretParams. The
//     master seed is written verbatim to SeedSink (when configured)
//     so the operator can paste it into yaml `zkConfig.serverSecret`
//     and restart to reproduce identical params.
type ZKParamsWorker struct {
	svc        *service.SignalService
	certsMgr   *certificates.CertificatesManager
	randSource func([]byte) (int, error)
	// SeedSink, when non-nil, receives the 32-byte master seed
	// IMMEDIATELY after generation. The worker writes exactly 32
	// bytes (no encoding, no newline) so the sink can be a
	// 0600-mode file the operator captures and securely transports
	// out-of-band. Leave nil only in tests or dry-runs.
	SeedSink io.Writer
}

// NewZKParamsWorker constructs the worker. certsMgr may be nil — when
// so Run is a no-op (operator hasn't wired the certs manager).
func NewZKParamsWorker(svc *service.SignalService, certsMgr *certificates.CertificatesManager) *ZKParamsWorker {
	return &ZKParamsWorker{svc: svc, certsMgr: certsMgr, randSource: rand.Read}
}

// Name matches Java's `generate-zk-params`.
func (*ZKParamsWorker) Name() string { return "generate-zk-params" }

// Schedule is on-demand.
func (*ZKParamsWorker) Schedule() Schedule { return ScheduleOnDemand }

// Run generates fresh randomness, domain-separates it into per-type
// seeds, derives a new zkgroup.ServerSecretParams +
// GenericServerSecretParams, installs both on the certificates
// manager, writes the master seed to SeedSink (when configured),
// and logs only a SHA-256 fingerprint of the seed so secret
// material never enters the structured log stream.
//
// Domain separation: the master seed is *never* fed directly into
// zkgroup's randomness slot. Instead each derivation is keyed with
// a unique HKDF-style label so a future leak of one parameter set
// cannot be used to recover the other.
//
// Returns an error if SeedSink fails to accept the bytes — the
// operator cannot rotate without successful persistence and
// surfacing the error loudly is safer than installing live params
// the operator can't reproduce on the next restart.
func (w *ZKParamsWorker) Run(ctx context.Context) error {
	if w.certsMgr == nil {
		return nil
	}
	source := w.randSource
	if source == nil {
		source = rand.Read
	}

	var seed [32]byte
	if _, err := source(seed[:]); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "generate-zk-params: read randomness", err)
	}
	// Defensive: scrub the seed from local stack on return.
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	// Domain-separate before handing entropy to zkgroup. The
	// labels are part of the rotation contract — changing them
	// breaks reproducibility from the persisted master seed.
	authSeedFull := sha256.Sum256(append([]byte("go-signal.zkparams.auth.v1"), seed[:]...))
	callingSeedFull := sha256.Sum256(append([]byte("go-signal.zkparams.calling.v1"), seed[:]...))
	defer func() {
		for i := range authSeedFull {
			authSeedFull[i] = 0
		}
		for i := range callingSeedFull {
			callingSeedFull[i] = 0
		}
	}()

	var authRandomness zkgroup.RandomnessBytes
	copy(authRandomness[:], authSeedFull[:])
	authParams, err := zkgroup.GenerateServerSecretParams(authRandomness)
	for i := range authRandomness {
		authRandomness[i] = 0
	}
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "generate-zk-params: derive auth params", err)
	}

	var callingRandomness zkgroup.RandomnessBytes
	copy(callingRandomness[:], callingSeedFull[:])
	callingParams := zkgroup.GenerateGenericServerSecretParams(callingRandomness)
	for i := range callingRandomness {
		callingRandomness[i] = 0
	}

	// Persist the master seed BEFORE installing — failure here is
	// fatal, since the operator could not reproduce the live params
	// after a restart.
	if w.SeedSink != nil {
		// io.Writer contract: a writer that returns n < len(p) MUST
		// also return a non-nil error, but we don't fully trust
		// third-party implementations to honor that. A short write
		// here means the operator's reproducibility material is
		// truncated, so treat n != len(seed) as fatal even when err
		// is nil.
		n, err := w.SeedSink.Write(seed[:])
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "generate-zk-params: persist seed to sink", err)
		}
		if n != len(seed) {
			return signalerrors.New(signalerrors.ErrInternal, fmt.Sprintf("generate-zk-params: persist seed to sink: short write %d of %d bytes", n, len(seed)))
		}
	}

	w.certsMgr.SetAuthServerSecret(authParams)
	w.certsMgr.SetCallingZKParams(callingParams)

	fp := sha256.Sum256(seed[:])
	slog.InfoContext(ctx, "generate-zk-params: regenerated ZK group parameters",
		slog.String("seedFingerprint", hex.EncodeToString(fp[:8])),
		slog.Bool("seedPersisted", w.SeedSink != nil),
		slog.String("notice", "store the SeedSink output as yaml zkConfig.serverSecret; never paste this seed into logs"))
	return nil
}

// CheckDynamicConfigurationWorker validates the current remote-config
// state. On-demand, typically invoked after config pushes.
// Matches Java's `check-dynamic-config`.
type CheckDynamicConfigurationWorker struct {
	svc *service.SignalService
	mgr *remoteconfig.Manager
}

// NewCheckDynamicConfigurationWorker constructs the worker. mgr may
// be nil — when so Run is a no-op (the deployment isn't using the
// remote-config subsystem).
func NewCheckDynamicConfigurationWorker(svc *service.SignalService, mgr *remoteconfig.Manager) *CheckDynamicConfigurationWorker {
	return &CheckDynamicConfigurationWorker{svc: svc, mgr: mgr}
}

// Name matches Java's `check-dynamic-config`.
func (*CheckDynamicConfigurationWorker) Name() string { return "check-dynamic-config" }

// Schedule is on-demand.
func (*CheckDynamicConfigurationWorker) Schedule() Schedule { return ScheduleOnDemand }

// Run re-fetches every row from the configured remote-config store
// and replaces the in-memory cache. Underlying validation (empty
// names, out-of-range percentages) lives in Store.Put — Refresh
// surfaces store-side parse errors so operators see them before they
// hit live traffic.
func (w *CheckDynamicConfigurationWorker) Run(ctx context.Context) error {
	if w.mgr == nil {
		return nil
	}
	return w.mgr.Refresh(ctx)
}

// RegisterDefaults registers the standard set of workers on s. Callers
// may register additional workers before Start. Backup workers register
// only when svc.Backups is wired so deployments without the backup
// subsystem do not run no-op scans on every tick.
//
// remoteCfgMgr is consumed by the check-dynamic-config worker.
// certsMgr is consumed by the generate-certificate and
// generate-zk-params workers — pass nil to leave them as no-ops.
// pushMgr is consumed by the notify-idle-devices worker — pass nil
// when the deployment has no push pipeline.
// jobsMgr is consumed by the process-scheduled-jobs worker — pass
// nil when the deployment has not wired the scheduled-jobs store.
// apnJobsMgr is the dedicated jobs.Manager that drains the APN
// notification queue. Production deployments typically share the
// same Store between the two managers but register only the APN
// handler on apnJobsMgr so the workers' batches stay
// throttle-independent.
func RegisterDefaults(s *Scheduler, svc *service.SignalService, remoteCfgMgr *remoteconfig.Manager, certsMgr *certificates.CertificatesManager, pushMgr *push.PushManager, jobsMgr *jobs.Manager, apnJobsMgr *jobs.Manager) error {
	all := []Worker{
		NewRemoveExpiredAccountsWorker(svc, 0),
		NewRemoveExpiredLinkedDevicesWorker(svc, 0),
		NewRemoveExpiredUsernameHoldsWorker(svc),
		NewRemoveOrphanedPreKeyPagesWorker(svc),
		NewNotifyIdleDevicesWorker(svc, pushMgr, 0),
		NewUnlinkIdlePrimaryDevicesWorker(svc),
		NewMessagePersisterWorker(svc, nil),
		NewRemoveExpiredMessagesWorker(svc, 0),
		NewScheduledJobsWorker(svc, jobsMgr),
		NewAPNPushSenderWorker(svc, apnJobsMgr),
		NewCertificateRotationWorker(svc, certsMgr),
		NewZKParamsWorker(svc, certsMgr),
		NewCheckDynamicConfigurationWorker(svc, remoteCfgMgr),
	}
	if svc != nil && svc.Backups != nil {
		all = append(all,
			NewRemoveExpiredBackupsWorker(svc, nil, 0),
			NewBackupUsageRecalculationWorker(svc, nil),
		)
	}
	for _, w := range all {
		if err := s.Register(w); err != nil {
			return err
		}
	}
	return nil
}
