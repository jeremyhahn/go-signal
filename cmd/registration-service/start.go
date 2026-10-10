package main

import (
	"context"
	"log/slog"
	"net"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	regpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/registrationservice"
	regsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/registration"
	"github.com/jeremyhahn/go-signal/pkg/config"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/health"
	"github.com/jeremyhahn/go-signal/pkg/metrics"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	pgstorage "github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	"github.com/jeremyhahn/go-signal/pkg/verification/factory"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the registration-service gRPC server",
	Long: "Start the registration-service gRPC server. Hosts the " +
		"RegistrationService.proto contract backed by an in-memory " +
		"session store and the verification transport configured via " +
		"the YAML config (twilio, stub).",
	RunE: runStart,
}

func init() { rootCmd.AddCommand(startCmd) }

func runStart(cmd *cobra.Command, _ []string) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	transport, err := buildTransport(cfg.Verification, logger)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "transport", err)
	}
	store, err := buildSessionStore(ctx, cfg.Storage, logger)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "session store", err)
	}
	coreSvc := core.NewService(store, transport, core.Config{
		CodeLength:  cfg.Verification.CodeLength,
		CodeTTL:     time.Duration(cfg.Verification.CodeTTLSeconds) * time.Second,
		MaxAttempts: cfg.Verification.MaxAttempts,
		FixedCode:   cfg.Verification.FixedCode,
	})
	defer coreSvc.Shutdown()

	addr := cfg.Verification.GRPCListen
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrUnavailable, "listen "+addr, err)
	}
	gs := grpc.NewServer()
	regpb.RegisterRegistrationServiceServer(gs, regsvc.NewServer(coreSvc))

	probes := health.New()
	metricsReg := metrics.NewRegistry("registration-service")
	go func() {
		if err := health.RunSidecar(ctx, probes, metricsReg, cfg.Health.Listen); err != nil {
			logger.Error("health sidecar", slog.Any("error", err))
		}
	}()

	logger.InfoContext(ctx, "registration-service ready",
		slog.String("listen", addr),
		slog.String("transport", transport.Name()))

	errs := make(chan error, 1)
	go func() {
		if serveErr := gs.Serve(lis); serveErr != nil {
			errs <- signalerrors.Wrap(signalerrors.ErrInternal, "grpc serve", serveErr)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("registration-service shutting down")
		probes.SetUnhealthy()
		gs.GracefulStop()
		return nil
	case err := <-errs:
		gs.Stop()
		return err
	}
}

// buildSessionStore selects the verification.VerificationSessionStore
// implementation based on cfg.Backend. "qrdb" wires a qrdb-backed store
// behind an in-process FakeKVStore (same pattern used by signald for
// the qrdb backend before a live qrdb transport is provisioned).
// "postgres" opens a Postgres pool and runs migrations. Any other value
// defaults to MemoryVerificationSessionStore.
func buildSessionStore(ctx context.Context, cfg config.StorageConfig, logger *slog.Logger) (verification.VerificationSessionStore, error) {
	switch cfg.Backend {
	case "qrdb":
		logger.Info("registration-service: using qrdb storage backend (in-process fake transport)")
		kv := qrdbstorage.NewFakeKVStore()
		return qrdbstorage.NewVerificationSessionStore(kv), nil
	case "postgres":
		logger.Info("registration-service: using postgres storage backend")
		pgClient, err := pgstorage.New(ctx, pgstorage.Config{
			DSN:             cfg.Postgres.DSN(),
			MaxConns:        int32(cfg.Postgres.MaxConns),
			MinConns:        int32(cfg.Postgres.MinConns),
			MaxConnLifetime: cfg.Postgres.MaxConnLifetime,
			MaxConnIdleTime: cfg.Postgres.MaxConnIdleTime,
			ConnectTimeout:  cfg.Postgres.ConnectTimeout,
			Logger:          logger,
		})
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres connect", err)
		}
		if err := pgClient.Migrate(ctx); err != nil {
			pgClient.Close()
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres migrate", err)
		}
		return pgstorage.NewVerificationSessionStore(pgClient.Pool()), nil
	default:
		logger.Info("registration-service: using memory storage backend")
		return verification.NewMemoryVerificationSessionStore(), nil
	}
}

// buildTransport constructs the verification transport per the YAML config
// via the shared factory (stub for development, twilio for production).
func buildTransport(vc config.VerificationConfig, logger *slog.Logger) (verification.VerificationTransport, error) {
	return factory.Build(vc, logger)
}
