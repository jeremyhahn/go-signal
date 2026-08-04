package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	accountpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/account"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
	"github.com/jeremyhahn/go-signal/pkg/service"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

func TestConfig_EnabledReportsListenConfigured(t *testing.T) {
	t.Parallel()
	if (Config{}).Enabled() {
		t.Fatal("empty Listen should report disabled")
	}
	if !(Config{Listen: "127.0.0.1:0"}).Enabled() {
		t.Fatal("configured Listen should report enabled")
	}
}

func TestNew_RegistersAllServices(t *testing.T) {
	t.Parallel()
	s := buildTestServer(t, ":0")
	if s == nil || s.s == nil {
		t.Fatal("expected non-nil server and embedded grpc.Server")
	}
	info := s.s.GetServiceInfo()

	// Spot-check the 16 services we register.
	expected := []string{
		"org.signal.chat.account.Accounts",
		"org.signal.chat.account.AccountsAnonymous",
		"org.signal.chat.messages.Messages",
		"org.signal.chat.messages.MessagesAnonymous",
		"org.signal.chat.keys.Keys",
		"org.signal.chat.keys.KeysAnonymous",
		"org.signal.chat.profile.Profile",
		"org.signal.chat.profile.ProfileAnonymous",
		"org.signal.chat.device.Devices",
		"org.signal.chat.backup.Backups",
		"org.signal.chat.backup.BackupsAnonymous",
		"org.signal.chat.calling.Calling",
		"org.signal.chat.calling.quality.CallQuality",
		"org.signal.chat.credentials.ExternalServiceCredentials",
		"org.signal.chat.credentials.ExternalServiceCredentialsAnonymous",
		"org.signal.chat.payments.Payments",
		// RegistrationService moved to cmd/registration-service in Phase 4.1.
		"kt_query.KeyTransparencyQueryService",
	}
	for _, name := range expected {
		if _, ok := info[name]; !ok {
			t.Errorf("service %q not registered", name)
		}
	}
}

// TestServer_RoundTrip spins up the server on an ephemeral port, dials
// it, invokes GetAccountIdentity on the authenticated Accounts service,
// and verifies an Unauthenticated response (because no Basic header is
// sent). This confirms the listener, routing interceptor, and service
// registration are all wired together.
func TestServer_RoundTrip_UnauthenticatedCall(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()

	s := buildTestServer(t, addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve(ctx) }()
	// Allow the listener to bind before we dial.
	time.Sleep(50 * time.Millisecond)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := accountpb.NewAccountsClient(conn)
	_, err = client.GetAccountIdentity(context.Background(), &accountpb.GetAccountIdentityRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without credentials, got %v", err)
	}

	s.Stop()
	if err := <-errCh; err != nil && !isClosedListener(err) {
		t.Fatalf("Serve returned unexpected error: %v", err)
	}
}

func TestServer_Nil_IsSafe(t *testing.T) {
	t.Parallel()
	var s *Server
	s.Stop()
	if err := s.Serve(context.Background()); err != nil {
		t.Fatalf("nil Server Serve should no-op: %v", err)
	}
}

func TestServer_Serve_BadAddress_ReturnsError(t *testing.T) {
	t.Parallel()
	s := buildTestServer(t, "")
	// Override the listen address to something invalid after construction.
	s.cfg.Listen = "not-a-valid-address:99999"
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("expected error when Serve cannot bind")
	}
}

func TestNew_WithDirectorySource_RegistersDirectoryService(t *testing.T) {
	t.Parallel()
	store := memory.NewMemoryAccountStore()
	am := accounts.NewAccountsManager(store, 6)
	svc := service.NewSignalService(service.ServiceConfig{Accounts: am})

	// dirsvc.MemorySource satisfies dirsvc.AccountSource.
	dirSrc := dirsvc.NewMemorySource(nil)
	s := New(Config{Listen: ":0"}, am, svc, dirSrc)
	info := s.s.GetServiceInfo()
	if _, ok := info["org.signal.directory.DirectoryService"]; !ok {
		t.Error("DirectoryService not registered when source is non-nil")
	}
}

func TestRoutingInterceptor_AnonymousPrefix_CallsAnonInterceptor(t *testing.T) {
	t.Parallel()
	var anonCalled, authCalled bool
	anon := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		anonCalled = true
		return handler(ctx, req)
	}
	auth := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		authCalled = true
		return handler(ctx, req)
	}
	ri := routingInterceptor(auth, anon)
	info := &grpc.UnaryServerInfo{FullMethod: "/org.signal.chat.account.AccountsAnonymous/GetGroupSendToken"}
	_, _ = ri(context.Background(), nil, info, func(ctx context.Context, req interface{}) (interface{}, error) { return nil, nil })
	if !anonCalled {
		t.Error("expected anonymous interceptor to be called for anonymous service prefix")
	}
	if authCalled {
		t.Error("auth interceptor must not be called for anonymous prefix")
	}
}

func TestRoutingInterceptor_ExternalInfraPrefix_PassesThroughToHandler(t *testing.T) {
	t.Parallel()
	var authCalled, anonCalled, handlerCalled bool
	auth := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		authCalled = true
		return handler(ctx, req)
	}
	anon := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		anonCalled = true
		return handler(ctx, req)
	}
	ri := routingInterceptor(auth, anon)
	info := &grpc.UnaryServerInfo{FullMethod: "/org.signal.registration.rpc.RegistrationService/CreateSession"}
	_, _ = ri(context.Background(), nil, info, func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return nil, nil
	})
	if authCalled || anonCalled {
		t.Error("neither auth nor anon interceptor should be called for external infra prefix")
	}
	if !handlerCalled {
		t.Error("handler must be called directly for external infra prefix")
	}
}

// --- helpers ----------------------------------------------------------

func buildTestServer(t *testing.T, listen string) *Server {
	t.Helper()
	store := memory.NewMemoryAccountStore()
	am := accounts.NewAccountsManager(store, 6)
	// SignalService takes a ServiceConfig with manager pointers. We can
	// pass a minimal config — Phase 1 services never call through.
	svc := service.NewSignalService(service.ServiceConfig{
		Accounts: am,
	})
	return New(Config{Listen: listen}, am, svc, nil)
}

// isClosedListener reports whether err is the expected "listener closed"
// error that GracefulStop produces; we tolerate it in round-trip tests.
func isClosedListener(err error) bool {
	return err != nil && (containsString(err.Error(), "use of closed network connection") ||
		containsString(err.Error(), "closed"))
}

func containsString(s, substr string) bool {
	return len(substr) <= len(s) && findString(s, substr) >= 0
}

func findString(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
