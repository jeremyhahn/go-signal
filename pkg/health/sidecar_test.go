package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestRunSidecar_CancelContext verifies that RunSidecar returns nil when the
// context is cancelled (the normal graceful-shutdown path).
func TestRunSidecar_CancelContext(t *testing.T) {
	p := New()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately after a brief delay so the server has time to start.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	// Pick a free port so we don't collide with other tests.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find free port: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()

	err = RunSidecar(ctx, p, nil, addr)
	if err != nil {
		t.Errorf("RunSidecar: expected nil on context cancel, got %v", err)
	}
}

// TestRunSidecar_InvalidAddr verifies that RunSidecar propagates a listen
// error when the address is unusable (the ListenAndServe-error path).
func TestRunSidecar_InvalidAddr(t *testing.T) {
	p := New()
	ctx := context.Background()

	// Port 0 on a bare IP forces the OS to pick a port, but a completely
	// malformed address will cause ListenAndServe to fail immediately.
	err := RunSidecar(ctx, p, nil, "invalid-address-%%%")
	if err == nil {
		t.Error("RunSidecar: expected error for invalid listen address")
	}
}

// TestRunSidecar_EmptyAddr verifies that RunSidecar refuses an empty
// address instead of binding a hardcoded fallback: the address must come
// from the health.listen config key.
func TestRunSidecar_EmptyAddr(t *testing.T) {
	err := RunSidecar(context.Background(), New(), nil, "")
	if !errors.Is(err, ErrNoListenAddr) {
		t.Fatalf("RunSidecar(\"\"): got %v, want ErrNoListenAddr", err)
	}
}

// TestRunSidecar_BindsConfiguredAddr verifies the sidecar serves on the
// exact address it is given.
func TestRunSidecar_BindsConfiguredAddr(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find free port: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunSidecar(ctx, New(), nil, addr) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, getErr := http.Get("http://" + addr + "/healthz")
		if getErr == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sidecar never served on %s: %v", addr, getErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunSidecar: %v", err)
	}
}
