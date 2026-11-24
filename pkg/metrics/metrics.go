// Package metrics holds the Prometheus instrumentation every Phase 4
// binary exposes on its /metrics endpoint. Metric names follow the
// Java Signal-Server Micrometer naming where applicable so operator
// dashboards (Grafana boards, runbook queries) stay portable.
//
// One Registry per binary is constructed at start-up; the binaries
// register the per-subsystem metrics they actually use. The
// HTTPMiddleware wrapper instruments any net/http.Handler chain so
// per-route latency + status-code distribution land in
// http_server_request_duration_seconds + http_server_requests_total
// out of the box.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry bundles a Prometheus registry plus the standard
// instrumentation every Signal-server binary needs.
//
// The exported metrics:
//
//   - HTTPRequestsTotal: counter over (method, route, status_code).
//   - HTTPRequestDuration: histogram (seconds) over (method, route).
//   - GRPCRequestsTotal: counter over (service, method, code).
//   - GRPCRequestDuration: histogram (seconds) over (service, method).
//   - InflightRequests: gauge over the request lifecycle.
//
// All histograms use the Prometheus default RPC-oriented buckets
// (5ms → 10s) matching Java Micrometer's default ServerWebSocket
// timer config.
type Registry struct {
	Reg                 *prometheus.Registry
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	GRPCRequestsTotal   *prometheus.CounterVec
	GRPCRequestDuration *prometheus.HistogramVec
	InflightRequests    prometheus.Gauge
}

// NewRegistry constructs a Registry with the standard instrumentation
// pre-registered. binary is the service name (e.g. "signald",
// "svr2") which becomes a static label on every metric.
func NewRegistry(binary string) *Registry {
	reg := prometheus.NewRegistry()
	constLabels := prometheus.Labels{"service": binary}

	r := &Registry{
		Reg: reg,
		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "http_server_requests_total",
				Help:        "Total HTTP requests processed by the server, partitioned by method, route, and status.",
				ConstLabels: constLabels,
			},
			[]string{"method", "route", "status"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:        "http_server_request_duration_seconds",
				Help:        "HTTP request latency in seconds, partitioned by method and route.",
				ConstLabels: constLabels,
				Buckets:     prometheus.DefBuckets,
			},
			[]string{"method", "route"},
		),
		GRPCRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name:        "grpc_server_requests_total",
				Help:        "Total gRPC requests processed, partitioned by service, method, and code.",
				ConstLabels: constLabels,
			},
			[]string{"grpc_service", "grpc_method", "grpc_code"},
		),
		GRPCRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:        "grpc_server_request_duration_seconds",
				Help:        "gRPC request latency in seconds.",
				ConstLabels: constLabels,
				Buckets:     prometheus.DefBuckets,
			},
			[]string{"grpc_service", "grpc_method"},
		),
		InflightRequests: prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        "http_server_inflight_requests",
			Help:        "Number of HTTP requests currently in flight.",
			ConstLabels: constLabels,
		}),
	}

	reg.MustRegister(
		r.HTTPRequestsTotal,
		r.HTTPRequestDuration,
		r.GRPCRequestsTotal,
		r.GRPCRequestDuration,
		r.InflightRequests,
		// Process collectors — Java's Micrometer publishes the same
		// JVM-equivalents; this gets us per-process CPU, RSS, FD count.
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)
	return r
}

// Handler returns the /metrics handler bound to this Registry. Bind
// onto a dedicated admin/probe mux — never expose on a port that
// faces untrusted clients.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.Reg, promhttp.HandlerOpts{
		Registry: r.Reg,
	})
}

// HTTPMiddleware wraps next with request-counter + histogram
// instrumentation. route is the static route label (Java's
// "uri" tag) — pass the registered pattern, NOT the request path,
// to keep cardinality bounded.
func (r *Registry) HTTPMiddleware(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.InflightRequests.Inc()
		defer r.InflightRequests.Dec()
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, req)
		dur := time.Since(start).Seconds()
		r.HTTPRequestsTotal.WithLabelValues(req.Method, route, strconv.Itoa(rec.code)).Inc()
		r.HTTPRequestDuration.WithLabelValues(req.Method, route).Observe(dur)
	})
}

// ObserveGRPC records one gRPC call against the request counter +
// latency histogram. Call from a unary interceptor with the proto
// FullMethod ("/org.signal.x.Service/Method") and the result code.
func (r *Registry) ObserveGRPC(service, method, code string, dur time.Duration) {
	r.GRPCRequestsTotal.WithLabelValues(service, method, code).Inc()
	r.GRPCRequestDuration.WithLabelValues(service, method).Observe(dur.Seconds())
}

// statusRecorder captures the response status code so the middleware
// can attach it to the per-request counter.
type statusRecorder struct {
	http.ResponseWriter
	code        int
	wroteHeader bool
}

// WriteHeader records the supplied status code and forwards to the
// underlying writer.
func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.code = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Write proxies Write so handlers that call Write directly without
// an explicit WriteHeader still record a 200 default.
func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.code = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
