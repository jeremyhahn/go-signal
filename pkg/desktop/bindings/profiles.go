//go:build desktop

package bindings

import (
	"context"
	"time"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// ProfileBindings provides profile operations to the frontend.
type ProfileBindings struct {
	client *signal.Client
}

// NewProfileBindings creates profile bindings.
func NewProfileBindings(client *signal.Client) *ProfileBindings {
	return &ProfileBindings{client: client}
}

// GetProfile fetches a user's profile from the server.
func (b *ProfileBindings) GetProfile(uuid string) (*signal.Profile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.GetProfile(ctx, uuid)
}

// UpdateProfile updates the local user's profile on the server.
func (b *ProfileBindings) UpdateProfile(profile signal.Profile) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.UpdateProfile(ctx, profile)
}
