package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc"

	accountpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/account"
	backupspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/backups"
	callqualitypb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/call_quality"
	callingpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/calling"
	credentialspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/credentials"
	devicepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/device"
	keyspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keys"
	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
	messagespb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/messages"
	paymentspb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/payments"
	profilepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/profile"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/api/grpc/interceptors"
	"github.com/jeremyhahn/go-signal/pkg/api/grpc/services"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

// Config holds the gRPC server configuration.
type Config struct {
	// Listen is the "host:port" address the gRPC server binds to. If empty
	// the server is disabled and New returns a nil *Server — callers check
	// with s.Enabled() before using it.
	Listen string
}

// Enabled reports whether the gRPC listener should be started.
func (c Config) Enabled() bool { return c.Listen != "" }

// Server is the gRPC server: one *grpc.Server with authenticated and anonymous interceptors and every service registered.
type Server struct {
	cfg Config
	s   *grpc.Server
}

// New constructs a Server; accounts resolves Basic credentials and directoryOpts go to dirsvc.NewServer (WithEventSource enables live Subscribe).
func New(cfg Config, am *accounts.AccountsManager, svc *service.SignalService, directorySource dirsvc.AccountSource, directoryOpts ...dirsvc.ServerOption) *Server {
	authInterceptor := interceptors.AuthenticatedUnary(am)
	anonInterceptor := interceptors.AnonymousUnary()

	// One server-wide interceptor dispatches by service name, since grpc-go has no per-service interceptors.
	s := grpc.NewServer(
		grpc.UnaryInterceptor(routingInterceptor(authInterceptor, anonInterceptor)),
	)

	// Register authenticated services.
	accountpb.RegisterAccountsServer(s, services.NewAccountService(svc))
	messagespb.RegisterMessagesServer(s, services.NewMessagesService(svc))
	keyspb.RegisterKeysServer(s, services.NewKeysService(svc))
	profilepb.RegisterProfileServer(s, services.NewProfileService(svc))
	devicepb.RegisterDevicesServer(s, services.NewDevicesService(svc))
	backupspb.RegisterBackupsServer(s, services.NewBackupsService(svc))
	callingpb.RegisterCallingServer(s, services.NewCallingService(svc))
	callqualitypb.RegisterCallQualityServer(s, services.NewCallQualityService(svc))
	credentialspb.RegisterExternalServiceCredentialsServer(s, services.NewExternalServiceCredentialsService(svc))
	paymentspb.RegisterPaymentsServer(s, services.NewPaymentsService())

	// Register anonymous services.
	accountpb.RegisterAccountsAnonymousServer(s, services.NewAccountsAnonymousService(svc))
	messagespb.RegisterMessagesAnonymousServer(s, services.NewMessagesAnonymousService(svc))
	keyspb.RegisterKeysAnonymousServer(s, services.NewKeysAnonymousService(svc))
	profilepb.RegisterProfileAnonymousServer(s, services.NewProfileAnonymousService(svc))
	backupspb.RegisterBackupsAnonymousServer(s, services.NewBackupsAnonymousService(svc))
	credentialspb.RegisterExternalServiceCredentialsAnonymousServer(s, services.NewExternalServiceCredentialsAnonymousService(svc))

	// External-infrastructure services; DirectoryService is the read surface cmd/cdsi consumes.
	ktpb.RegisterKeyTransparencyQueryServiceServer(s, services.NewKeyTransparencyService(svc))
	if directorySource != nil {
		dirpb.RegisterDirectoryServiceServer(s, dirsvc.NewServer(directorySource, directoryOpts...))
	}

	return &Server{cfg: cfg, s: s}
}

// Serve starts the gRPC server and blocks until it is stopped. Calling
// Serve on a nil-config Server is a no-op.
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return nil
	}
	lis, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "grpc: listen", err)
	}
	go func() {
		<-ctx.Done()
		s.s.GracefulStop()
	}()
	if err := s.s.Serve(lis); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "grpc: serve", err)
	}
	return nil
}

// Stop gracefully shuts down the gRPC server.
func (s *Server) Stop() {
	if s == nil {
		return
	}
	s.s.GracefulStop()
}

// anonymousServicePrefixes lists the AUTH_ONLY_ANONYMOUS services; keep in sync with the .proto annotations.
var anonymousServicePrefixes = []string{
	"/org.signal.chat.account.AccountsAnonymous/",
	"/org.signal.chat.messages.MessagesAnonymous/",
	"/org.signal.chat.keys.KeysAnonymous/",
	"/org.signal.chat.profile.ProfileAnonymous/",
	"/org.signal.chat.backup.BackupsAnonymous/",
	"/org.signal.chat.credentials.ExternalServiceCredentialsAnonymous/",
}

// externalInfraPrefixes lists services that are neither authenticated nor
// anonymous in the AUTH_ONLY sense. They carry their own auth model
// (mTLS + HMAC-signed credentials) implemented separately.
var externalInfraPrefixes = []string{
	"/org.signal.registration.rpc.RegistrationService/",
	"/kt_query.KeyTransparencyQueryService/",
	"/org.signal.directory.DirectoryService/",
}

// routingInterceptor dispatches to the authenticated interceptor, the
// anonymous interceptor, or passes through for externally-authenticated
// services, based on the FullMethod name.
func routingInterceptor(auth, anon grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		method := info.FullMethod
		for _, p := range anonymousServicePrefixes {
			if hasPrefix(method, p) {
				return anon(ctx, req, info, handler)
			}
		}
		for _, p := range externalInfraPrefixes {
			if hasPrefix(method, p) {
				return handler(ctx, req)
			}
		}
		return auth(ctx, req, info, handler)
	}
}

// hasPrefix is strings.HasPrefix localised to avoid an import cycle with
// other helpers; keeps this file self-contained.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
