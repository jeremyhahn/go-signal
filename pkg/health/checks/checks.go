// Package checks holds the standard readiness-check builders the
// Phase 4 binaries plug into health.Probes.Add.
//
// Every check follows the same contract: a single context-bounded
// function returning nil when the backend is reachable and a typed
// error otherwise. Probes.timeout caps how long a check may take, so
// checks here MUST honour ctx.Done() — never block past it.
package checks

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-signal/pkg/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// HTTPGet returns a Check that does a HEAD/GET against url and reports
// success when the response status is < 500. Use this for downstream
// HTTP services whose health is signalled by HTTP-level reachability.
// Java's FaultTolerantHttpClient uses the same liveness signal.
func HTTPGet(url string, client *http.Client) health.Check {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode >= 500 {
			return signalerrors.New(signalerrors.ErrUnavailable, "checks: "+url+" returned "+strconv.Itoa(resp.StatusCode))
		}
		return nil
	}
}

// GRPCConn returns a Check that asks a gRPC connection for its
// connectivity state and reports ready when the state is Ready or
// Idle. gRPC's lazy connection model means freshly opened channels
// sit in Idle until the first RPC; that's still considered healthy
// from a readiness perspective. Connecting / TransientFailure /
// Shutdown all flip the probe to 503.
//
// Pass the conn signald uses to call cdsi (or vice versa) so kubelet
// can see when the downstream is unreachable.
func GRPCConn(conn *grpc.ClientConn) health.Check {
	return func(ctx context.Context) error {
		if conn == nil {
			return errors.New("checks: nil gRPC connection")
		}
		state := conn.GetState()
		switch state {
		case connectivity.Ready, connectivity.Idle:
			return nil
		case connectivity.Connecting:
			// Wait up to ctx for the state to settle.
			if !conn.WaitForStateChange(ctx, state) {
				return ctx.Err()
			}
			next := conn.GetState()
			if next == connectivity.Ready || next == connectivity.Idle {
				return nil
			}
			return signalerrors.New(signalerrors.ErrUnavailable, "checks: grpc state = "+next.String())
		default:
			return signalerrors.New(signalerrors.ErrUnavailable, "checks: grpc state = "+state.String())
		}
	}
}

// Pinger is the smallest surface a backend store needs to expose to
// participate in readiness checks. Both *cache.Client and the qrdb/
// postgres stores can implement this with a few-line `Ping(ctx)`
// shim.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Ping returns a Check that calls Ping on the supplied backend. nil
// Pingers are treated as a permanent failure so misconfigured wires
// show up loudly rather than silently passing.
func Ping(name string, p Pinger) health.Check {
	return func(ctx context.Context) error {
		if p == nil {
			return signalerrors.New(signalerrors.ErrInvalidArgument, "checks: "+name+" pinger is nil")
		}
		return p.Ping(ctx)
	}
}

// Aggregate returns a Check that runs the supplied checks in order
// and reports the first failing one. Useful for binaries with
// several dependencies that should all be ready before the binary
// itself is — keeps the /readyz JSON keys tidy by collapsing them
// into a single aggregate.
func Aggregate(checks ...health.Check) health.Check {
	return func(ctx context.Context) error {
		for i, c := range checks {
			if err := c(ctx); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "aggregate["+strconv.Itoa(i)+"]", err)
			}
		}
		return nil
	}
}
