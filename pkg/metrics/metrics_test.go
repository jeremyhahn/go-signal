package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistry_HandlerExposesMetrics(t *testing.T) {
	r := NewRegistry("test-binary")
	r.HTTPRequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	buf := make([]byte, 64*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, `http_server_requests_total{`) {
		t.Errorf("expected counter in body; got %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, `service="test-binary"`) {
		t.Errorf("expected service label; got %q", body[:min(200, len(body))])
	}
}

func TestRegistry_HTTPMiddleware_RecordsStatusAndDuration(t *testing.T) {
	r := NewRegistry("test")
	handler := r.HTTPMiddleware("/v1/echo", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hi"))
	}))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	resp, _ := http.Get(srv.URL)
	_ = resp.Body.Close()

	got := readMetricsBody(t, r)
	wants := []string{
		`http_server_requests_total{method="GET",route="/v1/echo",service="test",status="418"}`,
		`http_server_request_duration_seconds_count{method="GET",route="/v1/echo",service="test"}`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("expected %q in /metrics; not found", w)
		}
	}
}

func TestRegistry_HTTPMiddleware_DefaultsTo200WhenHandlerWritesBodyOnly(t *testing.T) {
	r := NewRegistry("test")
	handler := r.HTTPMiddleware("/v1/quiet", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	resp, _ := http.Get(srv.URL)
	_ = resp.Body.Close()
	got := readMetricsBody(t, r)
	want := `status="200"`
	if !strings.Contains(got, want) {
		t.Errorf("expected default-200 label; got %q", excerpt(got, want))
	}
}

func TestRegistry_HTTPMiddleware_InflightGaugeRespectsLifecycle(t *testing.T) {
	r := NewRegistry("test")
	gate := make(chan struct{})
	handler := r.HTTPMiddleware("/v1/slow", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-gate
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	done := make(chan struct{})
	go func() {
		resp, _ := http.Get(srv.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
		close(done)
	}()
	// Give the goroutine a chance to hit the middleware.
	time.Sleep(20 * time.Millisecond)
	if !strings.Contains(readMetricsBody(t, r), `http_server_inflight_requests{service="test"} 1`) {
		t.Errorf("expected inflight=1 during handler")
	}
	close(gate)
	<-done
	if !strings.Contains(readMetricsBody(t, r), `http_server_inflight_requests{service="test"} 0`) {
		t.Errorf("expected inflight=0 after handler returned")
	}
}

func TestRegistry_ObserveGRPC(t *testing.T) {
	r := NewRegistry("test")
	r.ObserveGRPC("org.signal.X", "Method", "OK", 25*time.Millisecond)
	got := readMetricsBody(t, r)
	if !strings.Contains(got, `grpc_server_requests_total{grpc_code="OK",grpc_method="Method",grpc_service="org.signal.X",service="test"} 1`) {
		t.Errorf("missing grpc counter; %q", excerpt(got, "grpc_server_requests_total"))
	}
}

func readMetricsBody(t *testing.T, r *Registry) string {
	t.Helper()
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 128*1024)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func excerpt(s, needle string) string {
	i := strings.Index(s, needle)
	if i < 0 {
		return "(needle not present)"
	}
	end := i + len(needle) + 80
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
