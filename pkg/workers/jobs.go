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

// Worker implementations; each Name is also its leader-lease key and must stay stable, and Schedule uses robfig/cron/v3 syntax.

// RemoveExpiredAccountsWorker deletes accounts idle longer than ExpiryThreshold (default 120 days).
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

// Run deletes accounts whose primary device's LastSeen is before now - ExpiryThreshold, logging and skipping failed deletes.
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

// Run unlinks non-primary devices whose LastSeen is before now - LinkExpiryThreshold.
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

// orphanPreKeySweepAbortRatio is the share of ambiguous lookups at which the sweep aborts, so a degraded account store cannot trigger mass deletion.
const orphanPreKeySweepAbortRatio = 0.10

// Run deletes pre-keys whose account is gone: only on *accounts.AccountNotFoundError, aborting before any delete past orphanPreKeySweepAbortRatio; failed deletes are logged and skipped.
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

	// Classify every UUID before deleting, so a degraded store aborts the sweep first.
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
		// Re-confirm not-found before deleting; an account may have been recreated since classification.
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

// NotifyIdleDevicesWorker pushes a wake-up to devices with a push token, idle longer than NotifyInterval, that have queued messages.
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
			// Skip devices with an empty queue; HasMessagesForDevice is an existence check.
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

// UnlinkIdlePrimaryDevicesWorker deletes accounts whose primary device is idle longer than PrimaryIdleThreshold (180 days).
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

// Run deletes accounts whose primary device's LastSeen is before now - PrimaryIdleThreshold, logging and skipping failed deletes.
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

// MessagePersisterWorker continuously drains the message cache into durable storage; a nil persister makes Run a no-op.
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

// DefaultMessageExpiryGrace is how long past expires_at [RemoveExpiredMessagesWorker] waits before purging.
const DefaultMessageExpiryGrace = 0

// RemoveExpiredMessagesWorker purges messages expired before now - ExpiryGrace; backends without expires_at remove nothing.
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

// Run deletes messages whose expires_at is before now - ExpiryGrace.
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

// Run drains APNs jobs through jobs.Manager.RunOnce, scheduled separately so it can be throttled on its own.
func (w *APNPushSenderWorker) Run(ctx context.Context) error {
	if w.mgr == nil {
		return nil
	}
	_, err := w.mgr.RunOnce(ctx, time.Now().UTC())
	return err
}

// CertificateRotationWorker generates a new delivery-certificate Ed25519 key on demand, installs it, and logs the public key and keyId; other instances need a restart or reload.
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

// certKeyIDEpoch is the origin of keyIds (seconds since it, monotonic uint32); never change it, as that invalidates issued keyIds. Tests override nowFn instead.
var certKeyIDEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// maxCertKeyID is the largest keyId; beyond it Run errors until the wire field widens.
const maxCertKeyID uint32 = 0xFFFFFFFF

// reservedCertificateKeyIDs are keyIds libsignal reserves for testing; clients reject them.
var reservedCertificateKeyIDs = []uint32{
	0xDEADC357, // libsignal "dead cert" — treated as revoked by clients
	0x7357C357, // libsignal "test cert" — signed by the testing trust root
}

// Run generates an Ed25519 key, installs it and logs the public key with keyId (seconds since certKeyIDEpoch); errors if the keyId would overflow uint32.
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
	// Step past reserved keyIds until none matches, keeping the keyId monotonic.
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

	if err := w.certsMgr.SetEd25519SigningKey(priv, keyID); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "generate-certificate: install signing key", err)
	}

	slog.InfoContext(ctx, "generate-certificate: regenerated Ed25519 delivery-cert signing key",
		slog.Uint64("keyId", uint64(keyID)),
		slog.String("publicKey", base64.StdEncoding.EncodeToString(pub)),
		slog.String("notice", "publish the public key + keyId above to mobile clients; restart followers to pick up the new private key"))
	return nil
}

// ZKParamsWorker generates new ZK group parameters on demand, installs them, writes the 32-byte master seed to SeedSink and logs only its SHA-256 fingerprint; the seed reproduces the params via zkConfig.serverSecret.
type ZKParamsWorker struct {
	svc        *service.SignalService
	certsMgr   *certificates.CertificatesManager
	randSource func([]byte) (int, error)
	// SeedSink receives exactly the 32 raw seed bytes right after generation; nil only in tests.
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

// Run derives domain-separated seeds from fresh randomness, builds and installs the server params, persists the master seed first and fails if SeedSink cannot take it.
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

	// Persist the seed before installing; without it the live params cannot be reproduced.
	if w.SeedSink != nil {
		// A short write is fatal even with a nil error.
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

// Run reloads every remote-config row into the cache, surfacing store parse errors.
func (w *CheckDynamicConfigurationWorker) Run(ctx context.Context) error {
	if w.mgr == nil {
		return nil
	}
	return w.mgr.Refresh(ctx)
}

// RegisterDefaults registers the standard workers on s; backup workers only when svc.Backups is set, and a nil manager leaves its workers as no-ops. apnJobsMgr drains only APN jobs.
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
