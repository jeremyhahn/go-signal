package health

import (
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/metrics"
)

// MountAdmin attaches the standard operator endpoints to mux:
//
//	/healthz  — liveness (probes)
//	/readyz   — readiness (probes)
//	/metrics  — Prometheus scrape target (metricsReg.Handler)
//
// Both pieces share the same admin mux/port so kubectl probes and
// Prometheus scrape the same listener. Pass nil for metricsReg to
// expose only the health probes.
func MountAdmin(mux *http.ServeMux, p *Probes, metricsReg *metrics.Registry) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	p.Mount(mux)
	if metricsReg != nil {
		mux.Handle("/metrics", metricsReg.Handler())
	}
}
