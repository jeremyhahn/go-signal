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

// RunSidecar serves /healthz, /readyz and /metrics (nil metricsReg skips it) on listenAddr until ctx ends or the listener fails; empty listenAddr is ErrNoListenAddr.
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
