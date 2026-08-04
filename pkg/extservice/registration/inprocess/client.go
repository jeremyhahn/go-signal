// Package inprocess implements registration.Client by calling a local
// *core.Service directly. Use it from unit tests and from the
// monolithic deployment topology where signald embeds the verification
// stack rather than talking to a remote registration-service binary.
package inprocess

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/extservice/registration"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// Client is a pass-through wrapper around *core.Service.
type Client struct {
	svc *core.Service
}

// New returns an in-process Client. Ownership of the Service stays
// with the caller — Client.Close intentionally does not shut it down
// because other components in the same process may still need it.
func New(svc *core.Service) *Client {
	return &Client{svc: svc}
}

// Compile-time interface conformance.
var _ registration.Client = (*Client)(nil)

func (c *Client) CreateSession(ctx context.Context, number string) (*verification.VerificationSession, error) {
	return c.svc.CreateSession(ctx, number)
}

func (c *Client) GetSession(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	return c.svc.GetSession(ctx, sessionID)
}

func (c *Client) SendCode(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	return c.svc.SendCode(ctx, sessionID)
}

func (c *Client) SubmitCode(ctx context.Context, sessionID, code string) (*verification.VerificationSession, error) {
	return c.svc.SubmitCode(ctx, sessionID, code)
}

// Close is a no-op because the Service is owned by the caller.
func (c *Client) Close() error { return nil }
