package health

import (
	"context"
	"errors"
	"net/http"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/metrics"
)

// ErrNoListenAddr is returned by RunSidecar when no listen address is
// supplied. The address comes from the health.listen config key.
var ErrNoListenAddr = signalerrors.New(signalerrors.ErrInvalidArgument, "health sidecar: listen address is required")

// RunSidecar starts a tiny HTTP server hosting /healthz, /readyz, and
// /metrics on the supplied listen address. Used by gRPC-native
// binaries (registration-service, cdsi, key-transparency) that don't
// already have an HTTP listener available for kubelet probes +
// Prometheus scrape.
//
// Returns once ctx is canceled (graceful shutdown) or once the
// listener errors. Pass nil for metricsReg to skip the /metrics
// endpoint. listenAddr is the resolved health.listen config value; an
// empty address returns ErrNoListenAddr rather than binding a guess.
func RunSidecar(ctx context.Context, p *Probes, metricsReg *metrics.Registry, listenAddr string) error {
	if listenAddr == "" {
		return ErrNoListenAddr
	}
	mux := http.NewServeMux()
	MountAdmin(mux, p, metricsReg)
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
