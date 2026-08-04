package checks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestHTTPGet_200IsReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	if err := HTTPGet(srv.URL, nil)(context.Background()); err != nil {
		t.Errorf("expected ready; got %v", err)
	}
}

func TestHTTPGet_5xxFlipsToError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	if err := HTTPGet(srv.URL, nil)(context.Background()); err == nil {
		t.Error("expected error on 5xx")
	}
}

func TestHTTPGet_4xxStillReady(t *testing.T) {
	// 4xx is the server saying "I heard you and refused" — the server
	// itself is reachable. Probes flip to 503 only on 5xx / network
	// failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	if err := HTTPGet(srv.URL, nil)(context.Background()); err != nil {
		t.Errorf("4xx should be ready; got %v", err)
	}
}

func TestHTTPGet_NetworkErrorFlipsToError(t *testing.T) {
	if err := HTTPGet("http://127.0.0.1:1", nil)(context.Background()); err == nil {
		t.Error("expected error on unreachable host")
	}
}

func TestGRPCConn_NilConnFails(t *testing.T) {
	if err := GRPCConn(nil)(context.Background()); err == nil {
		t.Error("nil conn should fail")
	}
}

func TestGRPCConn_LiveBufconnIsReady(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := GRPCConn(conn)(ctx); err != nil {
		t.Errorf("freshly-opened bufconn should be Idle/Ready; got %v", err)
	}
}

type stubPinger struct {
	err error
}

func (s stubPinger) Ping(_ context.Context) error { return s.err }

func TestPing_Success(t *testing.T) {
	if err := Ping("db", stubPinger{})(context.Background()); err != nil {
		t.Errorf("expected nil; got %v", err)
	}
}

func TestPing_Error(t *testing.T) {
	want := errors.New("backend down")
	err := Ping("db", stubPinger{err: want})(context.Background())
	if !errors.Is(err, want) {
		t.Errorf("expected wrap of want; got %v", err)
	}
}

func TestPing_NilPingerFails(t *testing.T) {
	if err := Ping("db", nil)(context.Background()); err == nil {
		t.Error("nil pinger should fail")
	}
}

func TestAggregate_StopsAtFirstFailure(t *testing.T) {
	calls := 0
	bump := func(_ context.Context) error {
		calls++
		return nil
	}
	bad := func(_ context.Context) error { return errors.New("boom") }
	agg := Aggregate(bump, bad, bump)
	if err := agg(context.Background()); err == nil {
		t.Error("expected error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (aggregate should short-circuit)", calls)
	}
}

func TestAggregate_AllReady(t *testing.T) {
	agg := Aggregate(
		func(_ context.Context) error { return nil },
		func(_ context.Context) error { return nil },
	)
	if err := agg(context.Background()); err != nil {
		t.Errorf("expected nil; got %v", err)
	}
}

func TestAggregate_EmptyChecks(t *testing.T) {
	agg := Aggregate()
	if err := agg(context.Background()); err != nil {
		t.Errorf("empty aggregate should be ready; got %v", err)
	}
}

// TestGRPCConn_ShutdownConn verifies the default branch in GRPCConn
// (TransientFailure / Shutdown states). After conn.Close() the state
// transitions to Shutdown.
func TestGRPCConn_ShutdownConn(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Close the connection — this drives the state into Shutdown.
	_ = conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = GRPCConn(conn)(ctx)
	if err == nil {
		t.Error("expected error for Shutdown connection")
	}
}

// TestGRPCConn_ConnectingState verifies the Connecting branch: a conn pointed
// at an unreachable address will move to Connecting once we force a ping RPC,
// and the check should time out (or report the context error).
func TestGRPCConn_ConnectingState(t *testing.T) {
	// Point at a port that refuses connections so the conn goes to
	// TransientFailure / Connecting once activity is triggered.
	conn, err := grpc.NewClient("127.0.0.1:1",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Force the connection to start dialing.
	conn.Connect()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// The check may return a context error (timeout) or a gRPC state error —
	// either way it must not return nil.
	err = GRPCConn(conn)(ctx)
	if err == nil {
		t.Error("expected non-nil error for connecting/failed connection")
	}
}
