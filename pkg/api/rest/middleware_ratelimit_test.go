package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/limits"
)

// errRateLimiter is a test double that returns a configurable error from Allow.
type errRateLimiter struct {
	err error
}

func (e *errRateLimiter) Allow(_ context.Context, _ string) error         { return e.err }
func (e *errRateLimiter) AllowN(_ context.Context, _ string, _ int) error { return e.err }

// --------------------------------------------------------------------------
// rateLimitMiddleware
// --------------------------------------------------------------------------

func TestRateLimitMiddleware_AllowsRequestUnderLimit(t *testing.T) {
	cfg := limits.BucketConfig{
		BucketSize:      5,
		RefillRate:      1.0,
		CleanupInterval: 0,
		StaleAfter:      0,
	}
	rl := limits.NewTokenBucketLimiter(cfg)
	defer rl.Stop()

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := rateLimitMiddleware(rl, ipKey, inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !called {
		t.Error("expected inner handler to be called")
	}
}

func TestRateLimitMiddleware_Returns429WhenLimitExceeded(t *testing.T) {
	cfg := limits.BucketConfig{
		BucketSize:      2,
		RefillRate:      0.001, // very slow refill
		CleanupInterval: 0,
		StaleAfter:      0,
	}
	rl := limits.NewTokenBucketLimiter(cfg)
	defer rl.Stop()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rateLimitMiddleware(rl, ipKey, inner)

	// Exhaust the bucket.
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:1"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}

	// This request should be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rr.Code)
	}
}

func TestRateLimitMiddleware_SetsRetryAfterHeader(t *testing.T) {
	cfg := limits.BucketConfig{
		BucketSize:      1,
		RefillRate:      1.0,
		CleanupInterval: 0,
		StaleAfter:      0,
	}
	rl := limits.NewTokenBucketLimiter(cfg)
	defer rl.Stop()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rateLimitMiddleware(rl, ipKey, inner)

	// Exhaust.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:5000"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// Expect 429 with Retry-After header.
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "192.168.1.1:5000"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req2)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	retryAfter := rr.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("expected Retry-After header to be set")
	}
	val, err := strconv.ParseInt(retryAfter, 10, 64)
	if err != nil {
		t.Fatalf("Retry-After is not a valid integer: %q", retryAfter)
	}
	if val < 1 {
		t.Errorf("expected Retry-After >= 1, got %d", val)
	}
}

func TestRateLimitMiddleware_DifferentIPsAreIndependent(t *testing.T) {
	cfg := limits.BucketConfig{
		BucketSize:      2,
		RefillRate:      0.001,
		CleanupInterval: 0,
		StaleAfter:      0,
	}
	rl := limits.NewTokenBucketLimiter(cfg)
	defer rl.Stop()

	calls := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	handler := rateLimitMiddleware(rl, ipKey, inner)

	// Exhaust IP "1.1.1.1".
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "1.1.1.1:100"
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	// "2.2.2.2" should still get through.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "2.2.2.2:100"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("different IP should not be rate-limited, got %d", rr.Code)
	}
}

func TestRateLimitMiddleware_UUIDKeyUsesAccountUUID(t *testing.T) {
	cfg := limits.BucketConfig{
		BucketSize:      1,
		RefillRate:      0.001,
		CleanupInterval: 0,
		StaleAfter:      0,
	}
	rl := limits.NewTokenBucketLimiter(cfg)
	defer rl.Stop()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := rateLimitMiddleware(rl, uuidKey, inner)

	acct := &accounts.Account{UUID: "uuid-abc-123"}
	ctx := contextWithAccount(context.Background(), acct)

	// First request should pass.
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1 = req1.WithContext(ctx)
	req1.RemoteAddr = "10.0.0.1:1"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr1.Code)
	}

	// Second request with same UUID should be limited.
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2 = req2.WithContext(ctx)
	req2.RemoteAddr = "10.0.0.1:1"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for exhausted UUID bucket, got %d", rr2.Code)
	}
}

// --------------------------------------------------------------------------
// ipKey
// --------------------------------------------------------------------------

func TestIPKey_ExtractsRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.5:8080"
	got := ipKey(req, nil)
	if got != "192.0.2.5" {
		t.Errorf("expected 192.0.2.5, got %q", got)
	}
}

func TestIPKey_PreservesIPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:9090"
	got := ipKey(req, nil)
	if got != "::1" {
		t.Errorf("expected ::1, got %q", got)
	}
}

func TestIPKey_IgnoresXForwardedForWithoutTrustedProxies(t *testing.T) {
	// When no trusted proxies are configured, XFF is ignored entirely to
	// prevent header spoofing. RemoteAddr is used as the authoritative source.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.1")
	got := ipKey(req, nil)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr 10.0.0.1 (XFF ignored without trusted proxies), got %q", got)
	}
}

func TestIPKey_IgnoresXForwardedForSingleWithoutTrustedProxies(t *testing.T) {
	// A single XFF entry is also ignored when no trusted proxies are configured.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.20")
	got := ipKey(req, nil)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr 10.0.0.1 (XFF ignored without trusted proxies), got %q", got)
	}
}

func TestIPKey_RemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3"
	got := ipKey(req, nil)
	// When RemoteAddr has no port, it is returned as-is.
	if got != "10.1.2.3" {
		t.Errorf("expected 10.1.2.3, got %q", got)
	}
}

// --------------------------------------------------------------------------
// uuidKey
// --------------------------------------------------------------------------

func TestUUIDKey_ReturnsAccountUUID(t *testing.T) {
	acct := &accounts.Account{UUID: "test-uuid-1234"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1"
	got := uuidKey(req, acct)
	if got != "test-uuid-1234" {
		t.Errorf("expected test-uuid-1234, got %q", got)
	}
}

func TestUUIDKey_FallsBackToIPWhenNoAccount(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:9999"
	got := uuidKey(req, nil)
	if got != "172.16.0.1" {
		t.Errorf("expected 172.16.0.1, got %q", got)
	}
}

func TestUUIDKey_FallsBackToRemoteAddrNotXForwardedFor(t *testing.T) {
	// Without trusted proxies configured, uuidKey falls back to the RemoteAddr
	// IP (not XFF) to prevent header spoofing when no account is present.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	got := uuidKey(req, nil)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr 10.0.0.1 (XFF ignored without trusted proxies), got %q", got)
	}
}

// --------------------------------------------------------------------------
// rateLimitMiddleware – non-RateLimitedError path (500)
// --------------------------------------------------------------------------

// TestRateLimitMiddleware_InternalErrorReturns500 verifies that when the
// RateLimiter returns an unexpected error (not *signalerrors.RateLimitedError),
// the middleware responds with 500 Internal Server Error rather than forwarding
// to the inner handler.
func TestRateLimitMiddleware_InternalErrorReturns500(t *testing.T) {
	rl := &errRateLimiter{err: errors.New("unexpected limiter failure")}

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := rateLimitMiddleware(rl, ipKey, inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unexpected limiter error, got %d", rr.Code)
	}
	if called {
		t.Error("inner handler must not be called on limiter error")
	}
}

// --------------------------------------------------------------------------
// rateLimit helper
// --------------------------------------------------------------------------

// TestRateLimit_NilLimiterPassesThrough verifies that rateLimit returns the
// original handler unchanged when the limiter is nil (rate limiting disabled).
func TestRateLimit_NilLimiterPassesThrough(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := rateLimit(nil, ipKey, inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected inner handler to be called when limiter is nil")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestRateLimit_NonNilLimiterEnforcesLimit verifies that rateLimit wraps the
// handler with rateLimitMiddleware when a non-nil limiter is provided.
func TestRateLimit_NonNilLimiterEnforcesLimit(t *testing.T) {
	// A limiter that always rejects.
	rl := &errRateLimiter{err: errors.New("always fail")}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := rateLimit(rl, ipKey, inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The limiter error is not a RateLimitedError, so we get 500.
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 from wrapped limiter, got %d", rr.Code)
	}
}
