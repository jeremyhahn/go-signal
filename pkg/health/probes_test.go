package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func roundTrip(t *testing.T, p *Probes, path string) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	p.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return resp.StatusCode, body
}

func TestProbes_HealthzAliveByDefault(t *testing.T) {
	status, body := roundTrip(t, New(), "/healthz")
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !body["alive"].(bool) {
		t.Error("alive should be true by default")
	}
}

func TestProbes_HealthzAfterSetUnhealthy(t *testing.T) {
	p := New()
	p.SetUnhealthy()
	status, body := roundTrip(t, p, "/healthz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", status)
	}
	if body["alive"].(bool) {
		t.Error("alive should be false after SetUnhealthy")
	}
}

func TestProbes_ReadyzEmptyChecksIsReady(t *testing.T) {
	status, body := roundTrip(t, New(), "/readyz")
	if status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if !body["ready"].(bool) {
		t.Error("empty checks should be ready")
	}
}

func TestProbes_ReadyzAllPass(t *testing.T) {
	p := New()
	p.Add("db", func(_ context.Context) error { return nil })
	p.Add("cache", func(_ context.Context) error { return nil })
	status, body := roundTrip(t, p, "/readyz")
	if status != http.StatusOK {
		t.Errorf("status = %d", status)
	}
	checks := body["checks"].(map[string]any)
	if checks["db"] != "ok" || checks["cache"] != "ok" {
		t.Errorf("checks = %v", checks)
	}
}

func TestProbes_ReadyzOneFailingFlipsAggregate(t *testing.T) {
	p := New()
	p.Add("db", func(_ context.Context) error { return nil })
	p.Add("downstream", func(_ context.Context) error { return errors.New("upstream 503") })
	status, body := roundTrip(t, p, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", status)
	}
	if body["ready"].(bool) {
		t.Error("ready should be false")
	}
	checks := body["checks"].(map[string]any)
	if checks["downstream"] != "upstream 503" {
		t.Errorf("downstream check msg = %v", checks["downstream"])
	}
}

func TestProbes_AddRejectsEmptyAndNil(t *testing.T) {
	p := New()
	p.Add("", func(_ context.Context) error { return nil })
	p.Add("named", nil)
	if len(p.checks) != 0 {
		t.Errorf("expected 0 registered checks; got %d", len(p.checks))
	}
}

func TestProbes_CheckTimeoutAppliesToSlowCheck(t *testing.T) {
	p := New()
	p.SetCheckTimeout(20 * time.Millisecond)
	p.Add("slow", func(ctx context.Context) error {
		select {
		case <-time.After(200 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	status, body := roundTrip(t, p, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Errorf("slow check should fail readiness; status = %d", status)
	}
	if body["checks"].(map[string]any)["slow"] == "ok" {
		t.Error("slow check should not be ok")
	}
}

func TestProbes_MountNilMuxUsesDefault(t *testing.T) {
	// Use a fresh DefaultServeMux for the test so we don't pollute
	// global state across runs.
	orig := http.DefaultServeMux
	http.DefaultServeMux = http.NewServeMux()
	t.Cleanup(func() { http.DefaultServeMux = orig })
	New().Mount(nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("default mux /healthz = %d", rec.Code)
	}
}

func TestProbes_SetCheckTimeoutZeroIsNoop(t *testing.T) {
	p := New()
	original := p.timeout
	p.SetCheckTimeout(0)
	if p.timeout != original {
		t.Errorf("zero timeout should be ignored; got %v", p.timeout)
	}
}
