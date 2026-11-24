package health

import (
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/metrics"
)

// MountAdmin adds /healthz, /readyz and, when metricsReg is non-nil, /metrics to mux.
func MountAdmin(mux *http.ServeMux, p *Probes, metricsReg *metrics.Registry) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	p.Mount(mux)
	if metricsReg != nil {
		mux.Handle("/metrics", metricsReg.Handler())
	}
}
