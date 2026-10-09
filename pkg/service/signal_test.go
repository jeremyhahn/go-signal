package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// buildTestServiceConfig constructs a ServiceConfig backed entirely by
// in-memory stores. All managers are fully initialised.
func buildTestServiceConfig() ServiceConfig {
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)

	msgStore := newMockMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)

	keyStore := newMockPreKeyStore()
	keysMgr := keys.NewKeysManager(keyStore)

	profStore := newMockProfileStore()
	profMgr := profiles.NewProfilesManager(profStore)

	signingKey := secrets.MustNewSecureString(context.Background(), "signal-test-key-32bytes-padding!!")
	certMgr := certificates.NewCertificatesManager(signingKey, slog.Default())

	provStore := newMockProvisioningStore()
	devMgr := devices.NewDevicesManager(provStore, acctMgr, keysMgr, slog.Default())

	unameStore := newMockUsernameStore()
	unameMgr := usernames.NewUsernamesManager(unameStore, slog.Default())

	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider:    &noOpTurnProvider{},
		SurveyPublisher: &noOpSurveyPublisher{},
		Logger:          slog.Default(),
	})
	wsSessions := signalws.NewSessionManager(slog.Default())

	return ServiceConfig{
		Accounts:     acctMgr,
		Messages:     msgMgr,
		Keys:         keysMgr,
		Profiles:     profMgr,
		Certificates: certMgr,
		Devices:      devMgr,
		Usernames:    unameMgr,
		Calling:      callingMgr,
		WSSessions:   wsSessions,
		Logger:       slog.Default(),
	}
}

// TestNewSignalService_AllFieldsPopulated verifies that NewSignalService wires
// every service field correctly.
func TestNewSignalService_AllFieldsPopulated(t *testing.T) {
	cfg := buildTestServiceConfig()
	svc := NewSignalService(cfg)

	if svc == nil {
		t.Fatal("NewSignalService: returned nil")
		return
	}
	if svc.Accounts == nil {
		t.Error("NewSignalService: Accounts is nil")
	}
	if svc.Messages == nil {
		t.Error("NewSignalService: Messages is nil")
	}
	if svc.Keys == nil {
		t.Error("NewSignalService: Keys is nil")
	}
	if svc.Profiles == nil {
		t.Error("NewSignalService: Profiles is nil")
	}
	if svc.Certificates == nil {
		t.Error("NewSignalService: Certificates is nil")
	}
	if svc.Devices == nil {
		t.Error("NewSignalService: Devices is nil")
	}
	if svc.Usernames == nil {
		t.Error("NewSignalService: Usernames is nil")
	}
	if svc.CallSignaling == nil {
		t.Error("NewSignalService: CallSignaling is nil")
	}
}

// TestNewSignalService_ServiceTypesCorrect verifies that each field in the
// returned SignalService is of the expected concrete implementation type.
func TestNewSignalService_ServiceTypesCorrect(t *testing.T) {
	cfg := buildTestServiceConfig()
	svc := NewSignalService(cfg)

	if _, ok := svc.Accounts.(*accountService); !ok {
		t.Error("NewSignalService: Accounts is not *accountService")
	}
	if _, ok := svc.Messages.(*messageService); !ok {
		t.Error("NewSignalService: Messages is not *messageService")
	}
	if _, ok := svc.Keys.(*keyService); !ok {
		t.Error("NewSignalService: Keys is not *keyService")
	}
	if _, ok := svc.Profiles.(*profileService); !ok {
		t.Error("NewSignalService: Profiles is not *profileService")
	}
	if _, ok := svc.Certificates.(*certificateService); !ok {
		t.Error("NewSignalService: Certificates is not *certificateService")
	}
	if _, ok := svc.Devices.(*deviceService); !ok {
		t.Error("NewSignalService: Devices is not *deviceService")
	}
	if _, ok := svc.Usernames.(*usernameService); !ok {
		t.Error("NewSignalService: Usernames is not *usernameService")
	}
}

// TestNewSignalService_IndependentInstances verifies that two calls to
// NewSignalService produce independent service instances that share no state.
func TestNewSignalService_IndependentInstances(t *testing.T) {
	svc1 := NewSignalService(buildTestServiceConfig())
	svc2 := NewSignalService(buildTestServiceConfig())

	if svc1 == svc2 {
		t.Error("NewSignalService: expected distinct instances")
	}
	if svc1.Accounts == svc2.Accounts {
		t.Error("NewSignalService: Accounts services share the same instance unexpectedly")
	}
}

// TestSignalService_AccountsFieldIsFunctional performs a quick smoke test
// on the wired AccountService to confirm it is usable end-to-end.
func TestSignalService_AccountsFieldIsFunctional(t *testing.T) {
	svc := NewSignalService(buildTestServiceConfig())
	ctx := testCtx()

	a := newTestAccount("smoke-uuid", "+14155550099")
	if err := svc.Accounts.Create(ctx, a); err != nil {
		t.Fatalf("Accounts.Create: %v", err)
	}

	got, err := svc.Accounts.Get(ctx, "smoke-uuid")
	if err != nil {
		t.Fatalf("Accounts.Get: %v", err)
	}
	if got.UUID != "smoke-uuid" {
		t.Errorf("Accounts.Get: expected smoke-uuid, got %q", got.UUID)
	}
}

// TestSignalService_MessagesFieldIsFunctional performs a quick smoke test on
// the wired MessageService.
func TestSignalService_MessagesFieldIsFunctional(t *testing.T) {
	svc := NewSignalService(buildTestServiceConfig())
	ctx := testCtx()

	env := newTestEnvelope()
	if err := svc.Messages.Insert(ctx, "uuid-msg-smoke", 1, env); err != nil {
		t.Fatalf("Messages.Insert: %v", err)
	}

	pending, err := svc.Messages.GetMessagesForDevice(ctx, "uuid-msg-smoke", 1)
	if err != nil {
		t.Fatalf("Messages.GetMessagesForDevice: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("Messages.GetMessagesForDevice: expected 1, got %d", len(pending))
	}
}

// TestNewSignalService_NilWSSessions verifies that CallSignaling is nil when
// WSSessions is not provided, exercising the false branch of the
// WSSessions != nil && Calling != nil guard in NewSignalService.
func TestNewSignalService_NilWSSessions(t *testing.T) {
	cfg := buildTestServiceConfig()
	cfg.WSSessions = nil

	svc := NewSignalService(cfg)
	if svc == nil {
		t.Fatal("NewSignalService returned nil")
		return
	}
	if svc.CallSignaling != nil {
		t.Error("NewSignalService: CallSignaling should be nil when WSSessions is nil")
	}
}

// TestNewSignalService_NilCalling verifies that CallSignaling is nil when
// Calling is not provided.
func TestNewSignalService_NilCalling(t *testing.T) {
	cfg := buildTestServiceConfig()
	cfg.Calling = nil

	svc := NewSignalService(cfg)
	if svc == nil {
		t.Fatal("NewSignalService returned nil")
		return
	}
	if svc.CallSignaling != nil {
		t.Error("NewSignalService: CallSignaling should be nil when Calling is nil")
	}
}

// TestNewSignalService_NilLogger verifies that NewSignalService falls back to
// slog.Default() when Logger is nil, exercising the logger nil-check branch.
func TestNewSignalService_NilLogger(t *testing.T) {
	cfg := buildTestServiceConfig()
	cfg.Logger = nil

	svc := NewSignalService(cfg)
	if svc == nil {
		t.Fatal("NewSignalService returned nil")
		return
	}
	// CallSignaling must still be wired because WSSessions and Calling are non-nil.
	if svc.CallSignaling == nil {
		t.Error("NewSignalService: CallSignaling should be set even when Logger is nil")
	}
}

// TestSignalService_KeysFieldIsFunctional performs a quick smoke test on the
// wired KeyService.
func TestSignalService_KeysFieldIsFunctional(t *testing.T) {
	svc := NewSignalService(buildTestServiceConfig())
	ctx := testCtx()

	req := &keys.SetKeysRequest{
		PreKeys: []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk")}},
	}
	if err := svc.Keys.StoreKeys(ctx, "uuid-key-smoke", 1, req); err != nil {
		t.Fatalf("Keys.StoreKeys: %v", err)
	}

	state, err := svc.Keys.GetPreKeyCount(ctx, "uuid-key-smoke", 1)
	if err != nil {
		t.Fatalf("Keys.GetPreKeyCount: %v", err)
	}
	if state.ECCount != 1 {
		t.Errorf("Keys.GetPreKeyCount: expected ECCount=1, got %d", state.ECCount)
	}
}
