package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/health"
	ktserver "github.com/jeremyhahn/go-signal/pkg/keytransparency/server"
	"github.com/jeremyhahn/go-signal/pkg/metrics"
)

const defaultGRPCListen = "0.0.0.0:8098"

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the key-transparency gRPC service",
	RunE:  runStart,
}

func init() { rootCmd.AddCommand(startCmd) }

func runStart(cmd *cobra.Command, _ []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	listen := cfg.KeyTransparency.GRPCListen
	if listen == "" {
		listen = defaultGRPCListen
	}

	// Generate a fresh ed25519 signing key at startup. Production
	// deployments will load a persistent key from KMS (planned for
	// the proof-generation follow-up that wires real Merkle roots).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "ed25519 keygen", err)
	}
	logger.Info("kt signing key generated",
		slog.String("pub", hex.EncodeToString(pub)))

	log := ktserver.NewMemoryLog()
	srv := ktserver.NewGRPCServer(log, priv)

	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrUnavailable, "listen "+listen, err)
	}
	gs := grpc.NewServer()
	ktpb.RegisterKeyTransparencyQueryServiceServer(gs, srv)

	probes := health.New()
	metricsReg := metrics.NewRegistry("key-transparency")
	go func() {
		if err := health.RunSidecar(ctx, probes, metricsReg, ""); err != nil {
			logger.Error("health sidecar", slog.Any("error", err))
		}
	}()

	logger.InfoContext(ctx, "key-transparency ready", slog.String("listen", listen))

	errs := make(chan error, 1)
	go func() {
		if serveErr := gs.Serve(lis); serveErr != nil {
			errs <- signalerrors.Wrap(signalerrors.ErrInternal, "grpc serve", serveErr)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("key-transparency shutting down")
		probes.SetUnhealthy()
		shutdownDone := make(chan struct{})
		go func() { gs.GracefulStop(); close(shutdownDone) }()
		select {
		case <-shutdownDone:
		case <-time.After(5 * time.Second):
			gs.Stop()
		}
		return nil
	case err := <-errs:
		gs.Stop()
		return err
	}
}

// Keep errors imported for future error-decoration callers.
var _ = errors.New
