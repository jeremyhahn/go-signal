package signal

import (
	"context"
	"fmt"
)

// UpdateProfile updates the authenticated user's profile.
func (c *Client) UpdateProfile(ctx context.Context, profile Profile) error {
	body := map[string]any{}
	if profile.GivenName != "" {
		body["name"] = profile.GivenName
		if profile.FamilyName != "" {
			body["name"] = profile.GivenName + "\x00" + profile.FamilyName
		}
	}
	if profile.About != "" {
		body["about"] = profile.About
	}
	if profile.AboutEmoji != "" {
		body["aboutEmoji"] = profile.AboutEmoji
	}

	return c.doRequest(ctx, "PUT", "/v1/profile", body, nil)
}

// GetProfile retrieves a user's profile by UUID.
func (c *Client) GetProfile(ctx context.Context, uuid string) (*Profile, error) {
	var result Profile
	if err := c.doRequest(ctx, "GET", "/v1/profile/"+uuid, nil, &result); err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}
	return &result, nil
}
