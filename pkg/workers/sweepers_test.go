package workers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/auth"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/push"
	"github.com/jeremyhahn/go-signal/pkg/service"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// sweeperFixture wires the minimum subsystems the sweeper workers
// touch — accounts manager + a writable in-memory store, and the
// usernames pair — so tests can seed state and observe deletions.
type sweeperFixture struct {
	svc      *service.SignalService
	accounts *accounts.AccountsManager
	store    accounts.AccountStore
	usnames  *usernames.UsernamesManager
	unStore  *memory.MemoryUsernameStore
	clock    func() time.Time
}

func newSweeperFixture() *sweeperFixture {
	store := memory.NewMemoryAccountStore()
	am := accounts.NewAccountsManager(store, 6)
	unStore := memory.NewMemoryUsernameStore()
	um := usernames.NewUsernamesManager(unStore, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc := service.NewSignalService(service.ServiceConfig{Accounts: am, Usernames: um})
	return &sweeperFixture{svc: svc, accounts: am, store: store, usnames: um, unStore: unStore}
}

// seedAccount creates an account with one primary device whose
// LastSeen is set to the requested timestamp. Bypasses validation;
// the underlying memory store accepts whatever we hand it.
func (f *sweeperFixture) seedAccount(t *testing.T, uuid, number string, primaryLastSeen time.Time, linked ...time.Time) {
	t.Helper()
	a := &accounts.Account{
		UUID:        uuid,
		Number:      number,
		PNI:         uuid + "-pni",
		IdentityKey: []byte{0x01},
		Devices: []accounts.Device{{
			ID:            accounts.PrimaryDeviceID,
			AuthTokenHash: &auth.SaltedTokenHash{},
			SignedPreKey:  &accounts.SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
			LastSeen:      primaryLastSeen,
		}},
	}
	for i, ls := range linked {
		a.Devices = append(a.Devices, accounts.Device{
			ID:            accounts.PrimaryDeviceID + uint64(i) + 1,
			AuthTokenHash: &auth.SaltedTokenHash{},
			SignedPreKey:  &accounts.SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
			LastSeen:      ls,
		})
	}
	if err := f.store.Create(context.Background(), a); err != nil {
		t.Fatalf("seed %s: %v", uuid, err)
	}
}

func TestRemoveExpiredAccountsWorker_DeletesIdleAccountsOnly(t *testing.T) {
	f := newSweeperFixture()
	now := time.Now().UTC()
	f.seedAccount(t, "fresh", "+15550000001", now.Add(-1*time.Hour))
	f.seedAccount(t, "stale", "+15550000002", now.Add(-200*24*time.Hour))

	w := NewRemoveExpiredAccountsWorker(f.svc, 120*24*time.Hour)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if _, err := f.accounts.Get(context.Background(), "fresh"); err != nil {
		t.Errorf("fresh account incorrectly removed: %v", err)
	}
	if _, err := f.accounts.Get(context.Background(), "stale"); err == nil {
		t.Error("stale account was not removed")
	}
}

func TestRemoveExpiredAccountsWorker_EmptyStoreIsNoOp(t *testing.T) {
	f := newSweeperFixture()
	w := NewRemoveExpiredAccountsWorker(f.svc, 0)
	if err := w.Run(context.Background()); err != nil {
		t.Errorf("Run on empty store: %v", err)
	}
}

func TestRemoveExpiredAccountsWorker_NilServiceIsNoOp(t *testing.T) {
	w := NewRemoveExpiredAccountsWorker(nil, 0)
	if err := w.Run(context.Background()); err != nil {
		t.Errorf("Run with nil svc: %v", err)
	}
}

func TestRemoveExpiredLinkedDevicesWorker_RemovesOnlyExpiredLinked(t *testing.T) {
	f := newSweeperFixture()
	now := time.Now().UTC()
	// Primary fresh, one linked device fresh, one linked device stale (>45d).
	f.seedAccount(t, "a", "+15551110001", now.Add(-1*time.Hour),
		now.Add(-2*time.Hour),     // device id 2 — fresh
		now.Add(-60*24*time.Hour), // device id 3 — stale
	)

	w := NewRemoveExpiredLinkedDevicesWorker(f.svc, 45*24*time.Hour)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got, err := f.accounts.Get(context.Background(), "a")
	if err != nil {
		t.Fatalf("Get post-sweep: %v", err)
	}
	if len(got.Devices) != 2 {
		t.Errorf("expected 2 devices (primary + fresh linked), got %d", len(got.Devices))
	}
	for _, d := range got.Devices {
		if d.ID == 3 {
			t.Error("stale linked device 3 still present")
		}
	}
}

func TestRemoveExpiredLinkedDevicesWorker_NeverTouchesPrimary(t *testing.T) {
	f := newSweeperFixture()
	now := time.Now().UTC()
	// Primary very old, but worker should leave it alone (account-level
	// expiry is the other worker's job).
	f.seedAccount(t, "a", "+15551110001", now.Add(-300*24*time.Hour))

	w := NewRemoveExpiredLinkedDevicesWorker(f.svc, 45*24*time.Hour)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, _ := f.accounts.Get(context.Background(), "a")
	if got == nil || got.GetDevice(accounts.PrimaryDeviceID) == nil {
		t.Errorf("primary device removed by linked-device sweeper")
	}
}

func TestRemoveExpiredUsernameHoldsWorker_SweepsExpiredReservations(t *testing.T) {
	f := newSweeperFixture()
	// Reserve a hash with a clock at t=0, then advance the clock past TTL.
	now := time.Now().UTC()
	f.unStore.SetClock(func() time.Time { return now })
	if _, _, err := f.unStore.ReserveHash(context.Background(), "a", [][]byte{{0xAA}}); err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}

	// Move clock 10 minutes ahead (TTL is 5m).
	f.unStore.SetClock(func() time.Time { return now.Add(10 * time.Minute) })

	w := NewRemoveExpiredUsernameHoldsWorker(f.svc)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Trying to confirm the now-expired hash should fail because the
	// reservation row is gone.
	err := f.unStore.ConfirmHash(context.Background(), "a", []byte{0xAA}, "any-token")
	if err == nil {
		t.Error("expected ConfirmHash to fail post-sweep")
	}
}

func TestRemoveExpiredUsernameHoldsWorker_NilServiceIsNoOp(t *testing.T) {
	w := NewRemoveExpiredUsernameHoldsWorker(nil)
	if err := w.Run(context.Background()); err != nil {
		t.Errorf("Run nil svc: %v", err)
	}
}

func TestRemoveOrphanedPreKeyPagesWorker_DeletesOrphansOnly(t *testing.T) {
	// Wire a fresh fixture and seed pre-keys for two accounts: one
	// whose account row exists, one whose row does not.
	f := newSweeperFixture()
	now := time.Now().UTC()
	f.seedAccount(t, "live-acct", "+15550000001", now.Add(-1*time.Hour))

	// Seed pre-keys directly on the memory store the manager is
	// backed by. The fixture's svc.Keys must be populated for this
	// to take effect — we override the fixture's service.
	memKeys := memory.NewMemoryPreKeyStore()
	if err := memKeys.StoreECPreKeys(context.Background(), "live-acct", 1,
		[]*keys.PreKey{{KeyID: 1, PublicKey: []byte{0xAA}}}); err != nil {
		t.Fatalf("seed live pre-keys: %v", err)
	}
	if err := memKeys.StoreECPreKeys(context.Background(), "orphan-acct", 1,
		[]*keys.PreKey{{KeyID: 1, PublicKey: []byte{0xBB}}}); err != nil {
		t.Fatalf("seed orphan pre-keys: %v", err)
	}

	km := keys.NewKeysManager(memKeys)
	svc := service.NewSignalService(service.ServiceConfig{
		Accounts:  f.accounts,
		Usernames: f.usnames,
		Keys:      km,
	})

	w := NewRemoveOrphanedPreKeyPagesWorker(svc)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got, err := memKeys.ListAccountUUIDs(context.Background())
	if err != nil {
		t.Fatalf("ListAccountUUIDs post-sweep: %v", err)
	}
	want := map[string]bool{"live-acct": false}
	for _, u := range got {
		if u == "orphan-acct" {
			t.Errorf("orphan-acct should have been swept")
		}
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}
	if !want["live-acct"] {
		t.Errorf("live-acct keys were swept incorrectly")
	}
}

func TestBuildIdleWakeup_NoTokenSkipped(t *testing.T) {
	now := time.Now().UTC()
	d := &accounts.Device{ID: 1, LastSeen: now.Add(-100 * time.Hour)}
	if _, ok := buildIdleWakeup("u", d, now.Add(-24*time.Hour)); ok {
		t.Error("expected skip when device has no push token")
	}
}

func TestBuildIdleWakeup_FreshDeviceSkipped(t *testing.T) {
	now := time.Now().UTC()
	d := &accounts.Device{ID: 1, LastSeen: now.Add(-1 * time.Minute), ApnRegistrationID: "tok"}
	if _, ok := buildIdleWakeup("u", d, now.Add(-24*time.Hour)); ok {
		t.Error("expected skip when device is not yet idle")
	}
}

func TestBuildIdleWakeup_APNsPreferredOverFCM(t *testing.T) {
	now := time.Now().UTC()
	d := &accounts.Device{
		ID: 1, LastSeen: now.Add(-100 * time.Hour),
		ApnRegistrationID: "apns-tok",
		GcmRegistrationID: "fcm-tok",
	}
	notif, ok := buildIdleWakeup("u", d, now.Add(-24*time.Hour))
	if !ok || notif == nil {
		t.Fatal("expected notification when device has tokens and is idle")
	}
	if notif.DeviceToken != "apns-tok" {
		t.Errorf("expected APNs token preference, got %q", notif.DeviceToken)
	}
}

func TestBuildIdleWakeup_FCMFallback(t *testing.T) {
	now := time.Now().UTC()
	d := &accounts.Device{
		ID: 1, LastSeen: now.Add(-100 * time.Hour),
		GcmRegistrationID: "fcm-tok",
	}
	notif, ok := buildIdleWakeup("u", d, now.Add(-24*time.Hour))
	if !ok {
		t.Fatal("expected FCM notification when only FCM token present")
	}
	if notif.DeviceToken != "fcm-tok" {
		t.Errorf("expected FCM token, got %q", notif.DeviceToken)
	}
}

func TestNotifyIdleDevicesWorker_NilPushManagerIsNoOp(t *testing.T) {
	f := newSweeperFixture()
	w := NewNotifyIdleDevicesWorker(f.svc, nil, 24*time.Hour)
	if err := w.Run(context.Background()); err != nil {
		t.Errorf("Run with nil push manager: %v", err)
	}
}

// notifyFakeMsgSvc is a minimal MessageService that answers
// HasMessagesForDevice from a caller-supplied map.
type notifyFakeMsgSvc struct {
	service.MessageService
	has map[string]bool // key: "uuid.deviceID"
}

func (s *notifyFakeMsgSvc) HasMessagesForDevice(_ context.Context, uuid string, did uint64) (bool, error) {
	return s.has[fmt.Sprintf("%s.%d", uuid, did)], nil
}

// seedAccountWithPush seeds an account whose primary device has the
// given APNs token and lastSeen time. Uses the raw store to bypass
// token-hash requirements for test brevity.
func seedAccountWithPush(t *testing.T, store accounts.AccountStore, uuid, number, apnsToken string, lastSeen time.Time) {
	t.Helper()
	a := &accounts.Account{
		UUID:        uuid,
		Number:      number,
		PNI:         uuid + "-pni",
		IdentityKey: []byte{0x01},
		Devices: []accounts.Device{{
			ID:                accounts.PrimaryDeviceID,
			AuthTokenHash:     &auth.SaltedTokenHash{},
			SignedPreKey:      &accounts.SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
			LastSeen:          lastSeen,
			ApnRegistrationID: apnsToken,
		}},
	}
	if err := store.Create(context.Background(), a); err != nil {
		t.Fatalf("seedAccountWithPush %s: %v", uuid, err)
	}
}

func TestNotifyIdleDevicesWorker_DispatchesPushForEligibleDevice(t *testing.T) {
	f := newSweeperFixture()
	now := time.Now().UTC()

	// Idle device with APNs token AND a pending message.
	seedAccountWithPush(t, f.store, "idle-apns", "+15550002001", "apns-token", now.Add(-48*time.Hour))

	msgSvc := &notifyFakeMsgSvc{
		has: map[string]bool{
			fmt.Sprintf("%s.%d", "idle-apns", accounts.PrimaryDeviceID): true,
		},
	}
	svc := &service.SignalService{
		Accounts: f.svc.Accounts,
		Messages: msgSvc,
	}
	pushMgr := push.NewPushManager(push.PushManagerConfig{})
	w := NewNotifyIdleDevicesWorker(svc, pushMgr, 24*time.Hour)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestNotifyIdleDevicesWorker_SkipsDeviceWithoutMessages(t *testing.T) {
	f := newSweeperFixture()
	now := time.Now().UTC()

	// Idle device with APNs token but NO pending messages.
	seedAccountWithPush(t, f.store, "idle-no-msg", "+15550002002", "apns-silent", now.Add(-48*time.Hour))

	// Fresh device (not yet idle) — also skipped.
	seedAccountWithPush(t, f.store, "fresh-apns", "+15550002003", "apns-fresh", now.Add(-1*time.Minute))

	msgSvc := &notifyFakeMsgSvc{has: map[string]bool{}}
	svc := &service.SignalService{
		Accounts: f.svc.Accounts,
		Messages: msgSvc,
	}
	pushMgr := push.NewPushManager(push.PushManagerConfig{})
	w := NewNotifyIdleDevicesWorker(svc, pushMgr, 24*time.Hour)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestBuildIdleWakeup_NilDevice_Skipped(t *testing.T) {
	if _, ok := buildIdleWakeup("u", nil, time.Now()); ok {
		t.Error("expected skip for nil device")
	}
}

func TestRemoveOrphanedPreKeyPagesWorker_NilServiceIsNoOp(t *testing.T) {
	w := NewRemoveOrphanedPreKeyPagesWorker(nil)
	if err := w.Run(context.Background()); err != nil {
		t.Errorf("Run nil svc: %v", err)
	}
}

// transientAccountService wraps an AccountService and rewrites every
// Get to return a non-typed error — used to verify the orphan
// sweeper does NOT delete on transient lookup failures.
type transientAccountService struct {
	inner service.AccountService
}

func (s *transientAccountService) Create(ctx context.Context, a *accounts.Account) error {
	return s.inner.Create(ctx, a)
}
func (s *transientAccountService) Get(_ context.Context, _ string) (*accounts.Account, error) {
	return nil, errors.New("network blip")
}
func (s *transientAccountService) GetByNumber(ctx context.Context, n string) (*accounts.Account, error) {
	return s.inner.GetByNumber(ctx, n)
}
func (s *transientAccountService) Update(ctx context.Context, a *accounts.Account) error {
	return s.inner.Update(ctx, a)
}
func (s *transientAccountService) Delete(ctx context.Context, u string) error {
	return s.inner.Delete(ctx, u)
}
func (s *transientAccountService) SetRegistrationLock(ctx context.Context, u, p string) error {
	return s.inner.SetRegistrationLock(ctx, u, p)
}
func (s *transientAccountService) ClearRegistrationLock(ctx context.Context, u string) error {
	return s.inner.ClearRegistrationLock(ctx, u)
}
func (s *transientAccountService) SetDeviceAttributes(ctx context.Context, u string, d uint64, attrs accounts.DeviceAttributes) (*accounts.Account, error) {
	return s.inner.SetDeviceAttributes(ctx, u, d, attrs)
}
func (s *transientAccountService) AddDevice(ctx context.Context, u string, d *accounts.Device) (*accounts.Account, error) {
	return s.inner.AddDevice(ctx, u, d)
}
func (s *transientAccountService) RemoveDevice(ctx context.Context, u string, d uint64) (*accounts.Account, error) {
	return s.inner.RemoveDevice(ctx, u, d)
}
func (s *transientAccountService) ChangeNumber(ctx context.Context, u, n string, pni []byte) (*accounts.Account, error) {
	return s.inner.ChangeNumber(ctx, u, n, pni)
}
func (s *transientAccountService) SetPhoneNumberDiscoverability(ctx context.Context, u string, d bool) error {
	return s.inner.SetPhoneNumberDiscoverability(ctx, u, d)
}
func (s *transientAccountService) GetDataReport(ctx context.Context, u string) (*accounts.DataReport, error) {
	return s.inner.GetDataReport(ctx, u)
}
func (s *transientAccountService) ListAll(ctx context.Context, fn func(*accounts.Account) error) error {
	return s.inner.ListAll(ctx, fn)
}
func (s *transientAccountService) GetByPNI(ctx context.Context, p string) (*accounts.Account, error) {
	return s.inner.GetByPNI(ctx, p)
}
func (s *transientAccountService) RecreatePreserving(ctx context.Context, a *accounts.Account) error {
	return s.inner.RecreatePreserving(ctx, a)
}
func (s *transientAccountService) ClearGcmRegistration(ctx context.Context, u string, d uint64) (*accounts.Account, error) {
	return s.inner.ClearGcmRegistration(ctx, u, d)
}
func (s *transientAccountService) ClearApnRegistration(ctx context.Context, u string, d uint64) (*accounts.Account, error) {
	return s.inner.ClearApnRegistration(ctx, u, d)
}

// resurrectingAccountService returns AccountNotFoundError on the first
// Get for a given UUID and nil (account "alive") on subsequent calls.
// Used to simulate an account being recreated between the sweep's
// classify pass and its delete pass.
type resurrectingAccountService struct {
	inner     service.AccountService
	resurrect map[string]int
	mu        sync.Mutex
}

func (s *resurrectingAccountService) Create(ctx context.Context, a *accounts.Account) error {
	return s.inner.Create(ctx, a)
}
func (s *resurrectingAccountService) Get(_ context.Context, u string) (*accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resurrect[u]++
	if s.resurrect[u] == 1 {
		return nil, &accounts.AccountNotFoundError{Identifier: u}
	}
	return &accounts.Account{UUID: u}, nil
}
func (s *resurrectingAccountService) GetByNumber(ctx context.Context, n string) (*accounts.Account, error) {
	return s.inner.GetByNumber(ctx, n)
}
func (s *resurrectingAccountService) Update(ctx context.Context, a *accounts.Account) error {
	return s.inner.Update(ctx, a)
}
func (s *resurrectingAccountService) Delete(ctx context.Context, u string) error {
	return s.inner.Delete(ctx, u)
}
func (s *resurrectingAccountService) SetRegistrationLock(ctx context.Context, u, p string) error {
	return s.inner.SetRegistrationLock(ctx, u, p)
}
func (s *resurrectingAccountService) ClearRegistrationLock(ctx context.Context, u string) error {
	return s.inner.ClearRegistrationLock(ctx, u)
}
func (s *resurrectingAccountService) SetDeviceAttributes(ctx context.Context, u string, d uint64, attrs accounts.DeviceAttributes) (*accounts.Account, error) {
	return s.inner.SetDeviceAttributes(ctx, u, d, attrs)
}
func (s *resurrectingAccountService) AddDevice(ctx context.Context, u string, d *accounts.Device) (*accounts.Account, error) {
	return s.inner.AddDevice(ctx, u, d)
}
func (s *resurrectingAccountService) RemoveDevice(ctx context.Context, u string, d uint64) (*accounts.Account, error) {
	return s.inner.RemoveDevice(ctx, u, d)
}
func (s *resurrectingAccountService) ChangeNumber(ctx context.Context, u, n string, pni []byte) (*accounts.Account, error) {
	return s.inner.ChangeNumber(ctx, u, n, pni)
}
func (s *resurrectingAccountService) SetPhoneNumberDiscoverability(ctx context.Context, u string, d bool) error {
	return s.inner.SetPhoneNumberDiscoverability(ctx, u, d)
}
func (s *resurrectingAccountService) GetDataReport(ctx context.Context, u string) (*accounts.DataReport, error) {
	return s.inner.GetDataReport(ctx, u)
}
func (s *resurrectingAccountService) ListAll(ctx context.Context, fn func(*accounts.Account) error) error {
	return s.inner.ListAll(ctx, fn)
}
func (s *resurrectingAccountService) GetByPNI(ctx context.Context, p string) (*accounts.Account, error) {
	return s.inner.GetByPNI(ctx, p)
}
func (s *resurrectingAccountService) RecreatePreserving(ctx context.Context, a *accounts.Account) error {
	return s.inner.RecreatePreserving(ctx, a)
}
func (s *resurrectingAccountService) ClearGcmRegistration(ctx context.Context, u string, d uint64) (*accounts.Account, error) {
	return s.inner.ClearGcmRegistration(ctx, u, d)
}
func (s *resurrectingAccountService) ClearApnRegistration(ctx context.Context, u string, d uint64) (*accounts.Account, error) {
	return s.inner.ClearApnRegistration(ctx, u, d)
}

func TestRemoveOrphanedPreKeyPagesWorker_PreservesResurrectedAccount(t *testing.T) {
	f := newSweeperFixture()
	memKeys := memory.NewMemoryPreKeyStore()
	if err := memKeys.StoreECPreKeys(context.Background(), "u1", 1,
		[]*keys.PreKey{{KeyID: 1, PublicKey: []byte{0xAA}}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	km := keys.NewKeysManager(memKeys)
	svc := service.NewSignalService(service.ServiceConfig{
		Accounts:  f.accounts,
		Usernames: f.usnames,
		Keys:      km,
	})
	svc.Accounts = &resurrectingAccountService{
		inner:     svc.Accounts,
		resurrect: map[string]int{},
	}

	w := NewRemoveOrphanedPreKeyPagesWorker(svc)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Pre-keys MUST still be present — recheck found a live account
	// and the worker preserved them.
	got, _ := memKeys.ListAccountUUIDs(context.Background())
	if len(got) != 1 {
		t.Errorf("expected pre-keys preserved on resurrection, got %d uuids", len(got))
	}
}

func TestRemoveOrphanedPreKeyPagesWorker_AbortsOnTransientLookupFailures(t *testing.T) {
	f := newSweeperFixture()
	memKeys := memory.NewMemoryPreKeyStore()
	_ = memKeys.StoreECPreKeys(context.Background(), "u1", 1,
		[]*keys.PreKey{{KeyID: 1, PublicKey: []byte{0xAA}}})
	_ = memKeys.StoreECPreKeys(context.Background(), "u2", 1,
		[]*keys.PreKey{{KeyID: 1, PublicKey: []byte{0xBB}}})

	km := keys.NewKeysManager(memKeys)
	svc := service.NewSignalService(service.ServiceConfig{
		Accounts:  f.accounts,
		Usernames: f.usnames,
		Keys:      km,
	})
	svc.Accounts = &transientAccountService{inner: svc.Accounts}

	w := NewRemoveOrphanedPreKeyPagesWorker(svc)
	if err := w.Run(context.Background()); err == nil {
		t.Fatal("expected abort error when all lookups are transient")
	}

	got, _ := memKeys.ListAccountUUIDs(context.Background())
	if len(got) != 2 {
		t.Errorf("expected 2 pre-key UUIDs preserved post-abort, got %d", len(got))
	}
}

func TestUnlinkIdlePrimaryDevicesWorker_DeletesOnlyVeryIdleAccounts(t *testing.T) {
	f := newSweeperFixture()
	now := time.Now().UTC()
	// Primary device idle 120d — survives (< 180d threshold).
	f.seedAccount(t, "lukewarm", "+15550000001", now.Add(-120*24*time.Hour))
	// Primary device idle 200d — deleted.
	f.seedAccount(t, "frozen", "+15550000002", now.Add(-200*24*time.Hour))

	w := NewUnlinkIdlePrimaryDevicesWorker(f.svc)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := f.accounts.Get(context.Background(), "lukewarm"); err != nil {
		t.Errorf("lukewarm incorrectly removed: %v", err)
	}
	if _, err := f.accounts.Get(context.Background(), "frozen"); err == nil {
		t.Error("frozen was not removed")
	}
}
