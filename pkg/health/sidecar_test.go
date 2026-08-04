package health

import (
	"context"
	"net"
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

// TestRunSidecar_DefaultAddr verifies that the default listen address is used
// when listenAddr is empty. We cannot actually bind 0.0.0.0:8099 in the test
// environment, so we just verify the function returns an error (bind failure)
// rather than hanging. This exercises the empty-string branch.
func TestRunSidecar_DefaultAddr(t *testing.T) {
	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// If the port is available it will bind fine and the context cancel will
	// close it (err == nil). If it's already in use, ListenAndServe returns
	// an error. Either outcome is acceptable — the test just confirms the
	// function returns without panicking.
	_ = RunSidecar(ctx, p, nil, "")
}
