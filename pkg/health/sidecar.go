package health

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/metrics"
)

// RunSidecar starts a tiny HTTP server hosting /healthz, /readyz, and
// /metrics on the supplied listen address. Used by gRPC-native
// binaries (registration-service, cdsi, key-transparency) that don't
// already have an HTTP listener available for kubelet probes +
// Prometheus scrape.
//
// Returns once ctx is canceled (graceful shutdown) or once the
// listener errors. Pass nil for metricsReg to skip the /metrics
// endpoint. listenAddr defaults to "0.0.0.0:8099" when empty.
func RunSidecar(ctx context.Context, p *Probes, metricsReg *metrics.Registry, listenAddr string) error {
	if listenAddr == "" {
		listenAddr = "0.0.0.0:8099"
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
