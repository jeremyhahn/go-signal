package securestorage

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestStorageCredentials_DestroyIsNilSafeAndIdempotent covers the guards that
// let callers write `defer creds.Destroy()` before they know whether issuance
// succeeded, and let a shutdown path wipe something an error path already did.
func TestStorageCredentials_DestroyIsNilSafeAndIdempotent(t *testing.T) {
	var nilCreds *StorageCredentials
	nilCreds.Destroy() // must not panic

	creds := &StorageCredentials{
		Username: "u",
		Password: secrets.MustNewSecureString(t.Context(), "p"),
	}
	creds.Destroy()
	creds.Destroy() // second call must be a no-op, not a panic

	if !creds.Password.IsDestroyed(t.Context()) {
		t.Error("password survived Destroy")
	}
}

// TestStorageCredentials_UnmarshalRejectsMalformedJSON covers the decode-error
// branch: a malformed body must fail before anything is sealed, leaving the
// receiver untouched.
func TestStorageCredentials_UnmarshalRejectsMalformedJSON(t *testing.T) {
	creds := StorageCredentials{
		Username: "original",
		Password: secrets.MustNewSecureString(t.Context(), "original-password"),
	}
	defer creds.Destroy()

	if err := json.Unmarshal([]byte(`{"username":`), &creds); err == nil {
		t.Fatal("Unmarshal accepted malformed JSON")
	}
	// The receiver keeps what it had: a failed decode must not wipe a live
	// credential on its way out.
	if got := creds.Password.Plaintext(t.Context()); got != "original-password" {
		t.Errorf("a failed decode disturbed the receiver: password = %q", got)
	}
	if creds.Username != "original" {
		t.Errorf("a failed decode disturbed the receiver: username = %q", creds.Username)
	}
}

// TestGetAuth_HMACPathSealFailureFailsClosed covers the same failure on the
// HMAC branch: the digest was computed but could not be placed in protected
// memory, so issuance reports it rather than returning a passwordless
// credential.
func TestGetAuth_HMACPathSealFailureFailsClosed(t *testing.T) {
	m := NewSecureStorageManager(slog.Default())
	defer m.Destroy()
	if err := m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "shared-secret")); err != nil {
		t.Fatalf("SetSharedSecret: %v", err)
	}

	injected := errors.New("no protected memory available")
	original := newSecureStringBytes
	newSecureStringBytes = func(context.Context, []byte) (*secrets.SecureString, error) { return nil, injected }
	t.Cleanup(func() { newSecureStringBytes = original })

	creds, err := m.GetAuth(context.Background(), "acct")
	if err == nil {
		t.Fatal("GetAuth returned a credential it could not protect")
	}
	if creds != nil {
		t.Error("GetAuth returned credentials alongside the error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("the injected cause was lost: %v", err)
	}
}

// TestGetAuth_StubPathSealFailureFailsClosed covers the branch where the stub
// credential itself cannot be placed in protected memory. Issuance must report
// the failure rather than return a credential with no password — the caller
// would serialise it and the client would present it.
func TestGetAuth_StubPathSealFailureFailsClosed(t *testing.T) {
	m := NewSecureStorageManager(slog.Default())
	defer m.Destroy()
	// No shared secret configured, so GetAuth takes the stub branch.

	injected := errors.New("no protected memory available")
	// The stub path seals from bytes now (uuid.New().MarshalText), so this is
	// the seam it actually goes through.
	original := newSecureStringBytes
	newSecureStringBytes = func(context.Context, []byte) (*secrets.SecureString, error) { return nil, injected }
	t.Cleanup(func() { newSecureStringBytes = original })

	creds, err := m.GetAuth(context.Background(), "acct")
	if err == nil {
		t.Fatal("GetAuth returned a credential it could not protect")
	}
	if creds != nil {
		t.Error("GetAuth returned credentials alongside the error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("the injected cause was lost: %v", err)
	}
}
