package secrets

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stubResolver counts Resolve calls so tests can verify caching
// behaviour, and lets the test inject errors.
type stubResolver struct {
	scheme string
	value  string
	calls  int
	err    error
}

func (s *stubResolver) Scheme() string { return s.scheme }
func (s *stubResolver) Resolve(_ context.Context, _ string) (*SecureString, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return NewSecureString(s.value), nil
}

func TestNewCachingResolver_RejectsBadInputs(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on zero ttl")
		}
	}()
	NewCachingResolver(&stubResolver{scheme: "kms"}, 0)
}

func TestNewCachingResolver_RejectsNilUnderlying(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil underlying")
		}
	}()
	NewCachingResolver(nil, time.Minute)
}

func TestCachingResolver_FirstResolveFetchesUnderlying(t *testing.T) {
	stub := &stubResolver{scheme: "kms", value: "v1"}
	c := NewCachingResolver(stub, time.Minute)
	s, err := c.Resolve(context.Background(), "kms://a")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if s.Plaintext() != "v1" {
		t.Errorf("plaintext = %q", s.Plaintext())
	}
	if stub.calls != 1 {
		t.Errorf("expected 1 underlying call; got %d", stub.calls)
	}
}

func TestCachingResolver_SubsequentResolvesCacheHit(t *testing.T) {
	stub := &stubResolver{scheme: "kms", value: "v1"}
	c := NewCachingResolver(stub, time.Minute)
	_, _ = c.Resolve(context.Background(), "kms://a")
	_, _ = c.Resolve(context.Background(), "kms://a")
	_, _ = c.Resolve(context.Background(), "kms://a")
	if stub.calls != 1 {
		t.Errorf("cached resolver should hit underlying once; got %d", stub.calls)
	}
}

func TestCachingResolver_TTLExpiryRefetches(t *testing.T) {
	stub := &stubResolver{scheme: "kms", value: "v1"}
	c := NewCachingResolver(stub, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	c.clock = func() time.Time { return now }
	_, _ = c.Resolve(context.Background(), "kms://a")
	// Same instant — cache hit.
	_, _ = c.Resolve(context.Background(), "kms://a")
	if stub.calls != 1 {
		t.Errorf("calls before expiry = %d", stub.calls)
	}
	// Jump past TTL.
	now = now.Add(2 * time.Minute)
	stub.value = "v2"
	got, _ := c.Resolve(context.Background(), "kms://a")
	if stub.calls != 2 {
		t.Errorf("expected re-fetch after TTL; calls=%d", stub.calls)
	}
	if got.Plaintext() != "v2" {
		t.Errorf("post-rotation plaintext = %q", got.Plaintext())
	}
}

func TestCachingResolver_InvalidateForcesRefetch(t *testing.T) {
	stub := &stubResolver{scheme: "kms", value: "v1"}
	c := NewCachingResolver(stub, time.Hour)
	_, _ = c.Resolve(context.Background(), "kms://a")
	stub.value = "v2"
	c.Invalidate("kms://a")
	got, _ := c.Resolve(context.Background(), "kms://a")
	if stub.calls != 2 {
		t.Errorf("Invalidate should force re-fetch; calls=%d", stub.calls)
	}
	if got.Plaintext() != "v2" {
		t.Errorf("post-invalidate plaintext = %q", got.Plaintext())
	}
}

func TestCachingResolver_UnderlyingErrorNotCached(t *testing.T) {
	stub := &stubResolver{scheme: "kms", err: errors.New("kms down")}
	c := NewCachingResolver(stub, time.Hour)
	if _, err := c.Resolve(context.Background(), "kms://a"); err == nil {
		t.Error("expected error")
	}
	stub.err = nil
	stub.value = "v1"
	got, err := c.Resolve(context.Background(), "kms://a")
	if err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if got.Plaintext() != "v1" {
		t.Errorf("recovered plaintext = %q", got.Plaintext())
	}
}

func TestCachingResolver_Scheme(t *testing.T) {
	c := NewCachingResolver(&stubResolver{scheme: "kms"}, time.Minute)
	if c.Scheme() != "kms" {
		t.Errorf("Scheme proxy mismatch: %q", c.Scheme())
	}
}
