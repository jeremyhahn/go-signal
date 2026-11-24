// Package checks builds readiness checks for health.Probes.Add; each must honour ctx.Done().
package checks

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/jeremyhahn/go-signal/pkg/health"
)

// HTTPGet returns a Check that succeeds when url answers with a status below 500.
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

// GRPCConn returns a Check that is ready while conn is Ready or Idle.
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

// Pinger is what a backend store implements to take part in readiness checks.
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

// Aggregate returns a Check that runs checks in order and reports the first failure.
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
