package rest

import (
	"testing"
)

// wsAcceptOptions sanity checks. The SVR2 WebSocket endpoint itself
// moved to cmd/svr2 in Phase 4.2; the option helper is retained here
// for other WebSocket handlers that need the same origin policy.

func TestWSAcceptOptions_NoAllowedOrigins_NoInsecureSkip(t *testing.T) {
	s := newTestServer(t)
	opts := s.wsAcceptOptions()
	if opts.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false with no allowed origins")
	}
	if len(opts.OriginPatterns) != 0 {
		t.Errorf("expected empty OriginPatterns, got %v", opts.OriginPatterns)
	}
}

func TestWSAcceptOptions_WithAllowedOrigins_SetsPatterns(t *testing.T) {
	logger := testLogger()
	s := NewServer(ServerConfig{
		Host:           "127.0.0.1",
		Port:           0,
		Logger:         logger,
		AllowedOrigins: []string{"https://signal.example.com"},
	})
	opts := s.wsAcceptOptions()
	if opts.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false even with allowed origins")
	}
	if len(opts.OriginPatterns) != 1 {
		t.Fatalf("expected 1 OriginPattern, got %d", len(opts.OriginPatterns))
	}
	if opts.OriginPatterns[0] != "https://signal.example.com" {
		t.Errorf("expected origin pattern %q, got %q",
			"https://signal.example.com", opts.OriginPatterns[0])
	}
}
