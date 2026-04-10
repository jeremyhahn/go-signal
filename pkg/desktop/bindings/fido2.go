//go:build desktop && fido2

package bindings

import (
	"context"
	"encoding/json"
	"time"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// FIDO2Bindings provides WebAuthn security key operations to the frontend.
// The WebAuthn ceremony is split between Go (server communication) and
// TypeScript (browser navigator.credentials API in the Wails webview).
type FIDO2Bindings struct {
	client *signal.Client
}

// NewFIDO2Bindings creates FIDO2 bindings.
func NewFIDO2Bindings(client *signal.Client) *FIDO2Bindings {
	return &FIDO2Bindings{client: client}
}

// FIDO2Capabilities returns the server's WebAuthn configuration.
func (b *FIDO2Bindings) FIDO2Capabilities() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.FIDO2Capabilities(ctx)
}

// FIDO2ListCredentials returns all registered security keys.
func (b *FIDO2Bindings) FIDO2ListCredentials() ([]signal.FIDO2Credential, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.FIDO2ListCredentials(ctx)
}

// FIDO2BeginRegistration starts a WebAuthn registration ceremony.
// Returns the CredentialCreationOptions that the frontend passes to
// navigator.credentials.create().
func (b *FIDO2Bindings) FIDO2BeginRegistration(username string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return b.client.FIDO2RegisterKey(ctx, username)
}

// FIDO2FinishRegistration completes a WebAuthn registration ceremony.
// The attestation parameter is the JSON-serialized PublicKeyCredential
// from the browser's navigator.credentials.create() response.
func (b *FIDO2Bindings) FIDO2FinishRegistration(sessionID, attestationJSON string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var attestation map[string]any
	if err := json.Unmarshal([]byte(attestationJSON), &attestation); err != nil {
		return err
	}
	return b.client.FIDO2FinishRegistration(ctx, sessionID, attestation)
}

// FIDO2BeginLogin starts a WebAuthn authentication ceremony.
// Returns the CredentialRequestOptions that the frontend passes to
// navigator.credentials.get().
func (b *FIDO2Bindings) FIDO2BeginLogin() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return b.client.FIDO2BeginLogin(ctx)
}

// FIDO2FinishLogin completes a WebAuthn authentication ceremony.
// The assertion parameter is the JSON-serialized PublicKeyCredential
// from the browser's navigator.credentials.get() response.
func (b *FIDO2Bindings) FIDO2FinishLogin(assertionJSON string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var assertion map[string]any
	if err := json.Unmarshal([]byte(assertionJSON), &assertion); err != nil {
		return err
	}
	return b.client.FIDO2FinishLogin(ctx, assertion)
}

// FIDO2DeleteCredential removes a registered security key.
func (b *FIDO2Bindings) FIDO2DeleteCredential(credentialID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.FIDO2DeleteCredential(ctx, credentialID)
}

// FIDO2RenameCredential renames a security key.
func (b *FIDO2Bindings) FIDO2RenameCredential(credentialID, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.FIDO2RenameCredential(ctx, credentialID, name)
}
