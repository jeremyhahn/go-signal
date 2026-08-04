package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParse_ValidHeaderRoundTrips(t *testing.T) {
	const hdr = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	tc, err := Parse(hdr)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !tc.Sampled {
		t.Error("Sampled bit should be set")
	}
	if got := tc.Header(); got != hdr {
		t.Errorf("Header() round-trip = %q", got)
	}
}

func TestParse_RejectsBadInputs(t *testing.T) {
	cases := []string{
		"",
		"00-zzz-bbb-cc",
		"01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", // wrong version
		"00-shortTraceID-b7ad6b7169203331-01",
		"00-0af7651916cd43dd8448eb211c80319c-shortspn-01",
		"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-zz", // bad flags
		"00-00000000000000000000000000000000-b7ad6b7169203331-01", // zero trace id
		"00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01", // zero span id
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := Parse(c); err == nil {
				t.Errorf("expected error for %q", c)
			}
		})
	}
}

func TestNew_GeneratesNonZeroIDs(t *testing.T) {
	tc, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if isZero(tc.TraceID[:]) {
		t.Error("TraceID is zero")
	}
	if isZero(tc.SpanID[:]) {
		t.Error("SpanID is zero")
	}
	if !tc.Sampled {
		t.Error("freshly minted contexts should sample by default")
	}
}

func TestNewChildSpan_PreservesTraceIDChangesSpan(t *testing.T) {
	parent, _ := New()
	child, err := parent.NewChildSpan()
	if err != nil {
		t.Fatalf("NewChildSpan: %v", err)
	}
	if child.TraceID != parent.TraceID {
		t.Error("TraceID should be inherited")
	}
	if child.SpanID == parent.SpanID {
		t.Error("SpanID should be re-minted")
	}
}

func TestContext_RoundTrip(t *testing.T) {
	src, _ := New()
	ctx := WithContext(context.Background(), src)
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext returned !ok")
	}
	if got.Header() != src.Header() {
		t.Errorf("context-stored header = %q", got.Header())
	}
}

func TestFromContext_MissingReturnsFalse(t *testing.T) {
	_, ok := FromContext(context.Background())
	if ok {
		t.Error("expected ok=false on empty context")
	}
}

func TestHTTPMiddleware_PreservesInboundTrace(t *testing.T) {
	const hdr = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	mux := http.NewServeMux()
	var seen TraceContext
	mux.Handle("/x", HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, ok := FromContext(r.Context())
		if !ok {
			t.Error("middleware did not attach trace context")
			return
		}
		seen = tc
		w.WriteHeader(http.StatusOK)
	})))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	req.Header.Set(HeaderName, hdr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if seen.Header() != hdr {
		t.Errorf("inbound header lost: got %q", seen.Header())
	}
	if got := resp.Header.Get(HeaderName); got != hdr {
		t.Errorf("response traceparent = %q", got)
	}
}

func TestHTTPMiddleware_MintsWhenMissing(t *testing.T) {
	mux := http.NewServeMux()
	var seen TraceContext
	mux.Handle("/x", HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, _ := FromContext(r.Context())
		seen = tc
		w.WriteHeader(http.StatusOK)
	})))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, _ := http.Get(srv.URL + "/x")
	_ = resp.Body.Close()
	if isZero(seen.TraceID[:]) {
		t.Error("expected fresh trace id when inbound header is missing")
	}
	if !strings.HasPrefix(resp.Header.Get(HeaderName), "00-") {
		t.Errorf("response traceparent = %q", resp.Header.Get(HeaderName))
	}
}
