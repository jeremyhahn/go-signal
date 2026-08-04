package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/metrics"
)

func TestMountAdmin_MountsHealthzAndReadyz(t *testing.T) {
	mux := http.NewServeMux()
	p := New()
	MountAdmin(mux, p, nil)

	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("MountAdmin: %s returned %d, want 200", path, rec.Code)
		}
	}
}

func TestMountAdmin_NilMetricsReg_SkipsMetricsEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	p := New()
	MountAdmin(mux, p, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// The mux returns 404 when /metrics is not registered.
	if rec.Code == http.StatusOK {
		t.Error("MountAdmin: /metrics should not be registered when metricsReg is nil")
	}
}

func TestMountAdmin_WithMetricsReg_MountsMetrics(t *testing.T) {
	mux := http.NewServeMux()
	p := New()
	reg := metrics.NewRegistry("test")
	MountAdmin(mux, p, reg)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("MountAdmin: /metrics returned %d, want 200", rec.Code)
	}
}

func TestMountAdmin_NilMux_UsesDefaultServeMux(t *testing.T) {
	// Swap out the global DefaultServeMux for the duration of this test
	// to avoid polluting state across other tests.
	orig := http.DefaultServeMux
	http.DefaultServeMux = http.NewServeMux()
	t.Cleanup(func() { http.DefaultServeMux = orig })

	p := New()
	MountAdmin(nil, p, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("MountAdmin(nil mux): /healthz returned %d, want 200", rec.Code)
	}
}
