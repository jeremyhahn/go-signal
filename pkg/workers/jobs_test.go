package workers

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/jobs"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
	"github.com/jeremyhahn/go-signal/pkg/service"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// newTestService returns a minimally-wired SignalService for tests that
// exercise worker construction and scheduler registration. Sweeper
// workers now reach through svc; the fixture wires every manager
// they touch so Run is safe even on an empty store.
func newTestService() *service.SignalService {
	am := accounts.NewAccountsManager(memory.NewMemoryAccountStore(), 6)
	um := usernames.NewUsernamesManager(memory.NewMemoryUsernameStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	km := keys.NewKeysManager(memory.NewMemoryPreKeyStore())
	return service.NewSignalService(service.ServiceConfig{
		Accounts:  am,
		Usernames: um,
		Keys:      km,
	})
}

// Basic assertions against each worker's metadata: Name + Schedule are
// stable, Run is a no-op (returns nil). We don't assert what the Run
// bodies do beyond "don't error" because Phase 1 stubs them.

func TestDefaultWorkers_MetadataAndRun(t *testing.T) {
	t.Parallel()
	svc := newTestService()

	cases := []struct {
		worker   Worker
		name     string
		schedule Schedule
	}{
		{NewRemoveExpiredAccountsWorker(svc, 0), "remove-expired-accounts", "0 3 * * *"},
		{NewRemoveExpiredLinkedDevicesWorker(svc, 0), "remove-expired-linked-devices", "@every 1h"},
		{NewRemoveExpiredUsernameHoldsWorker(svc), "remove-expired-username-holds", "@every 24h"},
		{NewRemoveOrphanedPreKeyPagesWorker(svc), "remove-orphaned-pre-key-pages", "@every 168h"},
		{NewNotifyIdleDevicesWorker(svc, nil, 0), "notify-idle-devices", "@every 1h"},
		{NewUnlinkIdlePrimaryDevicesWorker(svc), "unlink-idle-primary", "@every 24h"},
		{NewMessagePersisterWorker(svc, nil), "message-persister", ScheduleContinuous},
		{NewScheduledJobsWorker(svc, nil), "process-scheduled-jobs", ScheduleContinuous},
		{NewAPNPushSenderWorker(svc, nil), "scheduled-apn-sender", ScheduleContinuous},
		{NewCertificateRotationWorker(svc, nil), "generate-certificate", ScheduleOnDemand},
		{NewZKParamsWorker(svc, nil), "generate-zk-params", ScheduleOnDemand},
		{NewCheckDynamicConfigurationWorker(svc, nil), "check-dynamic-config", ScheduleOnDemand},
	}
	for _, c := range cases {
		if c.worker.Name() != c.name {
			t.Errorf("Name: got %q want %q", c.worker.Name(), c.name)
		}
		if c.worker.Schedule() != c.schedule {
			t.Errorf("%s Schedule: got %q want %q", c.name, c.worker.Schedule(), c.schedule)
		}
		if err := c.worker.Run(context.Background()); err != nil {
			t.Errorf("%s Run returned error: %v", c.name, err)
		}
	}
}

func TestNewRemoveExpiredAccountsWorker_DefaultThreshold(t *testing.T) {
	t.Parallel()
	w := NewRemoveExpiredAccountsWorker(newTestService(), 0)
	if w.ExpiryThreshold != 120*24*time.Hour {
		t.Fatalf("expected 120-day default threshold, got %v", w.ExpiryThreshold)
	}
}

func TestNewRemoveExpiredAccountsWorker_ExplicitThreshold(t *testing.T) {
	t.Parallel()
	w := NewRemoveExpiredAccountsWorker(newTestService(), 30*24*time.Hour)
	if w.ExpiryThreshold != 30*24*time.Hour {
		t.Fatalf("expected explicit threshold to be honored, got %v", w.ExpiryThreshold)
	}
}

func TestNewRemoveExpiredLinkedDevicesWorker_DefaultThreshold(t *testing.T) {
	t.Parallel()
	w := NewRemoveExpiredLinkedDevicesWorker(newTestService(), 0)
	if w.LinkExpiryThreshold != 45*24*time.Hour {
		t.Fatalf("expected 45-day default, got %v", w.LinkExpiryThreshold)
	}
}

func TestNewNotifyIdleDevicesWorker_DefaultInterval(t *testing.T) {
	t.Parallel()
	w := NewNotifyIdleDevicesWorker(newTestService(), nil, 0)
	if w.NotifyInterval != 24*time.Hour {
		t.Fatalf("expected 24h default interval, got %v", w.NotifyInterval)
	}
}

func TestRegisterDefaults_RegistersEveryWorker(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	if err := RegisterDefaults(s, newTestService(), nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	names := s.List()
	if len(names) != 13 {
		t.Fatalf("expected 13 default workers registered, got %d: %v", len(names), names)
	}
	// Spot-check a few known names are present.
	want := map[string]bool{
		"remove-expired-accounts": false,
		"remove-expired-messages": false,
		"message-persister":       false,
		"generate-certificate":    false,
	}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("default registration missing %q", n)
		}
	}
}

func TestRegisterDefaults_FailsOnDuplicateRegistration(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	if err := RegisterDefaults(s, newTestService(), nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	// A second call tries to register the same workers again.
	if err := RegisterDefaults(s, newTestService(), nil, nil, nil, nil, nil); err == nil {
		t.Fatal("expected duplicate registration on second RegisterDefaults")
	}
}

func TestRegisterDefaults_WithBackups_RegistersBackupWorkers(t *testing.T) {
	// newWorkerFixture (defined in backups_test.go) wires svc.Backups.
	f := newWorkerFixture(t)
	s := NewScheduler(quietConfig())
	if err := RegisterDefaults(s, f.svc, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("RegisterDefaults: %v", err)
	}
	names := s.List()
	// 13 base workers + 2 backup workers = 15.
	if len(names) != 15 {
		t.Fatalf("expected 15 workers with backups wired, got %d: %v", len(names), names)
	}
}

// noopJobStore is a minimal jobs.Store that accepts all calls without
// doing anything. Used to give ScheduledJobsWorker and APNPushSenderWorker
// a non-nil Manager so the Run bodies execute.
type noopJobStore struct{}

func (s *noopJobStore) Enqueue(_ context.Context, _ *jobs.Job) error { return nil }
func (s *noopJobStore) ClaimDue(_ context.Context, _ time.Time, _ int, _ ...string) ([]*jobs.Job, error) {
	return nil, nil
}
func (s *noopJobStore) MarkDone(_ context.Context, _ string) error { return nil }
func (s *noopJobStore) MarkFailed(_ context.Context, _ string, _ time.Time, _ time.Duration, _ int) error {
	return nil
}
func (s *noopJobStore) ResetToPending(_ context.Context, _ string, _ time.Time) error { return nil }
func (s *noopJobStore) RecoverStale(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}
func (s *noopJobStore) Get(_ context.Context, _ string) (*jobs.Job, error) {
	return nil, jobs.ErrJobNotFound
}

func TestScheduledJobsWorker_NonNilMgr_DelegatesRunOnce(t *testing.T) {
	mgr := jobs.NewManager(&noopJobStore{}, nil)
	w := NewScheduledJobsWorker(newTestService(), mgr)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run with non-nil mgr: %v", err)
	}
}

func TestAPNPushSenderWorker_NonNilMgr_DelegatesRunOnce(t *testing.T) {
	mgr := jobs.NewManager(&noopJobStore{}, nil)
	w := NewAPNPushSenderWorker(newTestService(), mgr)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run with non-nil mgr: %v", err)
	}
}

func TestCheckDynamicConfigurationWorker_NonNilMgr_DelegatesRefresh(t *testing.T) {
	ctx := context.Background()
	mgr, err := remoteconfig.NewManager(ctx, remoteconfig.ManagerConfig{
		Store: remoteconfig.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Stop()
	w := NewCheckDynamicConfigurationWorker(newTestService(), mgr)
	if err := w.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
}
