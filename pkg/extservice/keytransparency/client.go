// Package keytransparency is the chat-server-side gRPC client for
// cmd/key-transparency. signald's KT REST handlers translate inbound
// JSON requests into proto calls through this Client.
//
// The Client wraps the generated KeyTransparencyQueryServiceClient
// and exposes a typed surface so signald handlers don't import the
// proto types directly.
package keytransparency

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"google.golang.org/grpc"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
)

// Client is the chat-server -> key-transparency surface.
type Client interface {
	Search(ctx context.Context, req *ktpb.SearchRequest) (*ktpb.SearchResponse, error)
	Monitor(ctx context.Context, req *ktpb.MonitorRequest) (*ktpb.MonitorResponse, error)
	Distinguished(ctx context.Context, req *ktpb.DistinguishedRequest) (*ktpb.DistinguishedResponse, error)
	Close() error
}

// Config configures the gRPC client.
type Config struct {
	// Conn, when non-nil, is used directly (caller owns it and Close
	// is a no-op).
	Conn *grpc.ClientConn
	// Endpoint is the host:port to dial when Conn is nil.
	Endpoint string
	// DialOptions are forwarded to grpc.NewClient when Endpoint is used.
	DialOptions []grpc.DialOption
	// Timeout caps each RPC. Zero means no timeout (caller's ctx governs).
	Timeout time.Duration
	// TLSConfig overrides the default TLS dial options when Endpoint
	// is used and DialOptions is empty. nil + Endpoint set + no
	// DialOptions uses TLS 1.2 minimum against the system roots.
	TLSConfig *tls.Config
}

// GRPCClient implements Client via gRPC.
type GRPCClient struct {
	cc      *grpc.ClientConn
	owned   bool
	stub    ktpb.KeyTransparencyQueryServiceClient
	timeout time.Duration
}

// New constructs a GRPCClient.
func New(cfg Config) (*GRPCClient, error) {
	if (cfg.Conn != nil) == (cfg.Endpoint != "") {
		return nil, errors.New("keytransparency: exactly one of Conn or Endpoint is required")
	}
	var (
		cc    *grpc.ClientConn
		owned bool
		err   error
	)
	if cfg.Conn != nil {
		cc = cfg.Conn
	} else {
		cc, err = grpc.NewClient(cfg.Endpoint, cfg.DialOptions...)
		if err != nil {
			return nil, err
		}
		owned = true
	}
	return &GRPCClient{
		cc:      cc,
		owned:   owned,
		stub:    ktpb.NewKeyTransparencyQueryServiceClient(cc),
		timeout: cfg.Timeout,
	}, nil
}

// Search forwards to the gRPC stub.
func (c *GRPCClient) Search(ctx context.Context, req *ktpb.SearchRequest) (*ktpb.SearchResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.stub.Search(ctx, req)
}

// Monitor forwards to the gRPC stub.
func (c *GRPCClient) Monitor(ctx context.Context, req *ktpb.MonitorRequest) (*ktpb.MonitorResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.stub.Monitor(ctx, req)
}

// Distinguished forwards to the gRPC stub.
func (c *GRPCClient) Distinguished(ctx context.Context, req *ktpb.DistinguishedRequest) (*ktpb.DistinguishedResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.stub.Distinguished(ctx, req)
}

// Close shuts down the underlying channel iff this Client owns it.
func (c *GRPCClient) Close() error {
	if c.owned && c.cc != nil {
		return c.cc.Close()
	}
	return nil
}

func (c *GRPCClient) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}
