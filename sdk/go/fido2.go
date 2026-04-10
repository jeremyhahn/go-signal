package signal

import (
	"context"
	"fmt"
)

// FIDO2Capabilities returns the server's FIDO2/WebAuthn configuration.
func (c *Client) FIDO2Capabilities(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	if err := c.doRequest(ctx, "GET", "/v1/fido2/capabilities", nil, &result); err != nil {
		return nil, fmt.Errorf("fido2 capabilities: %w", err)
	}
	return result, nil
}

// FIDO2ListCredentials returns all registered security keys.
func (c *Client) FIDO2ListCredentials(ctx context.Context) ([]FIDO2Credential, error) {
	var result struct {
		Credentials []FIDO2Credential `json:"credentials"`
	}
	if err := c.doRequest(ctx, "GET", "/v1/fido2/credentials", nil, &result); err != nil {
		return nil, fmt.Errorf("list fido2 credentials: %w", err)
	}
	return result.Credentials, nil
}

// FIDO2DeleteCredential removes a security key.
func (c *Client) FIDO2DeleteCredential(ctx context.Context, credentialID string) error {
	return c.doRequest(ctx, "DELETE", "/v1/fido2/credentials/"+credentialID, nil, nil)
}

// FIDO2RenameCredential updates a security key's name.
func (c *Client) FIDO2RenameCredential(ctx context.Context, credentialID, name string) error {
	return c.doRequest(ctx, "PUT", "/v1/fido2/credentials/"+credentialID+"/name",
		map[string]string{"name": name}, nil)
}

// FIDO2RegisterKey starts a FIDO2 registration ceremony.
// Note: WebAuthn ceremonies require a browser/GUI context. This method
// handles the server-side flow; the actual key interaction needs a
// WebAuthn client (available in the Wails GUI).
func (c *Client) FIDO2RegisterKey(ctx context.Context, username string) (map[string]any, error) {
	var result map[string]any
	err := c.doRequest(ctx, "POST", "/v1/fido2/session",
		map[string]string{"username": username}, &result)
	if err != nil {
		return nil, fmt.Errorf("fido2 register: %w", err)
	}
	return result, nil
}

// FIDO2FinishRegistration completes a FIDO2 registration ceremony by
// submitting the attestation response from the browser's
// navigator.credentials.create() call.
func (c *Client) FIDO2FinishRegistration(ctx context.Context, sessionID string, attestation map[string]any) error {
	return c.doRequest(ctx, "POST", "/v1/fido2/register/complete",
		map[string]any{"sessionId": sessionID, "attestation": attestation}, nil)
}

// FIDO2BeginLogin starts a FIDO2 authentication ceremony.
// Returns CredentialRequestOptions for the browser's navigator.credentials.get().
func (c *Client) FIDO2BeginLogin(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := c.doRequest(ctx, "POST", "/v1/fido2/login/begin", nil, &result)
	if err != nil {
		return nil, fmt.Errorf("fido2 begin login: %w", err)
	}
	return result, nil
}

// FIDO2FinishLogin completes a FIDO2 authentication ceremony by submitting
// the assertion response from the browser's navigator.credentials.get() call.
func (c *Client) FIDO2FinishLogin(ctx context.Context, assertion map[string]any) error {
	return c.doRequest(ctx, "POST", "/v1/fido2/login/complete",
		map[string]any{"assertion": assertion}, nil)
}
