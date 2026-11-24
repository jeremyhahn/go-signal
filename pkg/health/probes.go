// Package health implements the /healthz + /readyz probe endpoints
// every Phase 4 binary exposes. Kubernetes liveness/readiness probes
// hit these paths; the binary that mounts them returns 200 when the
// process is healthy, 503 with a JSON diagnostic when a registered
// checker fails.
//
// The model:
//
//   - LIVENESS: a single boolean "the process is alive". A failed
//     liveness probe restarts the pod. Default-true once Mount is
//     called; binaries that need a stricter check can call
//     SetUnhealthy.
//
//   - READINESS: a set of named Checks, each "ready or not, plus a
//     diagnostic". The probe iterates them; any check returning a
//     non-nil error flips the probe to 503. Use this for backend
//     dependencies (database, redis, downstream gRPC).
//
// The endpoint mounts onto an existing *http.ServeMux so binaries can
// share their probe listener with the main service port or run it on
// a dedicated metrics/admin port.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Check is one named readiness probe. Returning a non-nil error
// flips /readyz to 503 with the error message in the JSON body.
type Check func(ctx context.Context) error

// Probes holds the liveness + readiness state for one binary.
type Probes struct {
	mu        sync.RWMutex
	alive     bool
	checks    map[string]Check
	timeout   time.Duration
	startedAt time.Time
}

// New constructs Probes. The process starts alive=true with no
// readiness checks; binaries register checks via Add().
func New() *Probes {
	return &Probes{
		alive:     true,
		checks:    make(map[string]Check),
		timeout:   2 * time.Second,
		startedAt: time.Now().UTC(),
	}
}

// SetUnhealthy flips liveness to false. /healthz starts returning 503.
// Use during graceful shutdown so kubelet stops sending traffic before
// the listener tears down.
func (p *Probes) SetUnhealthy() {
	p.mu.Lock()
	p.alive = false
	p.mu.Unlock()
}

// SetCheckTimeout overrides the per-check deadline. Zero leaves the
// default 2s in place.
func (p *Probes) SetCheckTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	p.mu.Lock()
	p.timeout = d
	p.mu.Unlock()
}

// Add registers a readiness check. name is the JSON key the probe
// surfaces; duplicate names overwrite. Call before Mount.
func (p *Probes) Add(name string, c Check) {
	if name == "" || c == nil {
		return
	}
	p.mu.Lock()
	p.checks[name] = c
	p.mu.Unlock()
}

// Mount registers /healthz + /readyz on mux. Pass nil to use
// http.DefaultServeMux.
func (p *Probes) Mount(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.HandleFunc("/healthz", p.healthz)
	mux.HandleFunc("/readyz", p.readyz)
}

// healthz responds 200 when alive, 503 otherwise. Body is a small
// JSON envelope with the uptime so operators can spot a recent
// restart from kubectl logs.
func (p *Probes) healthz(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	alive := p.alive
	uptime := time.Since(p.startedAt)
	p.mu.RUnlock()
	status := http.StatusOK
	if !alive {
		status = http.StatusServiceUnavailable
	}
	writeProbeJSON(w, status, map[string]any{
		"alive":         alive,
		"uptimeSeconds": int64(uptime.Seconds()),
	})
}

// readyz runs every registered check and reports the aggregate.
func (p *Probes) readyz(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	checks := make(map[string]Check, len(p.checks))
	for k, v := range p.checks {
		checks[k] = v
	}
	timeout := p.timeout
	p.mu.RUnlock()

	results := make(map[string]string, len(checks))
	ready := true
	for name, c := range checks {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		err := c(ctx)
		cancel()
		if err != nil {
			ready = false
			results[name] = err.Error()
		} else {
			results[name] = "ok"
		}
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeProbeJSON(w, status, map[string]any{
		"ready":  ready,
		"checks": results,
	})
}

func writeProbeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
