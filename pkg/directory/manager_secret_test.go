package directory

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestGetAuthToken_WireFormUnchangedByProtectedSecret pins the CDS credential
// bytes to the plain-[]byte HMAC this manager produced before the secret moved
// into protected memory. cmd/cdsi re-derives the same digest to authenticate.
func TestGetAuthToken_WireFormUnchangedByProtectedSecret(t *testing.T) {
	const secret, acct = "cdsi-shared-secret", "b9d0d4e2-0000-4000-8000-000000000001"

	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString(secret))
	defer m.Destroy()

	creds, err := m.GetAuthToken(context.Background(), acct)
	if err != nil {
		t.Fatalf("GetAuthToken: %v", err)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(acct))
	want := hex.EncodeToString(mac.Sum(nil))

	if creds.Username != acct {
		t.Errorf("username = %q, want %q", creds.Username, acct)
	}
	if creds.Password.Plaintext() != want {
		t.Errorf("password = %q, want %q", creds.Password.Plaintext(), want)
	}
}

// TestSetSharedSecret_WipesTheSecretItReplaces is the defect this change
// closes: a rotation used to leave the superseded key resident.
func TestSetSharedSecret_WipesTheSecretItReplaces(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString("first"))
	superseded := m.state.Load().secret

	_ = m.SetSharedSecret(secrets.MustNewSecureString("second"))
	defer m.Destroy()

	if !superseded.IsDestroyed() {
		t.Error("the superseded secret is still resident in protected memory")
	}
	if got := m.state.Load().secret.Plaintext(); got != "second" {
		t.Errorf("sharedSecret = %q, want %q", got, "second")
	}
}

func TestSetSharedSecret_UnsetSecretWipesTheSecretItReplaces(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString("first"))
	superseded := m.state.Load().secret

	_ = m.SetSharedSecret(secrets.MustNewSecureString(""))

	if !superseded.IsDestroyed() {
		t.Error("the superseded secret is still resident in protected memory")
	}
	if m.state.Load().secret != nil {
		t.Error("expected a nil sharedSecret after clearing")
	}
}

// TestSetSharedSecret_ClonesTheCallersSecret covers the ownership contract:
// signald passes cfg.CDSI.SharedSecret, which cfg.Destroy wipes separately.
func TestSetSharedSecret_ClonesTheCallersSecret(t *testing.T) {
	src := secrets.MustNewSecureString("cdsi-shared-secret")
	defer src.Destroy()

	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(src)
	m.Destroy()

	if src.IsDestroyed() {
		t.Error("Destroy wiped the caller's secret")
	}
	if got := src.Plaintext(); got != "cdsi-shared-secret" {
		t.Errorf("caller's secret = %q, want %q", got, "cdsi-shared-secret")
	}
}

// TestDestroy_MakesCredentialIssuanceFailClosed is the reason the manager
// tracks HMAC mode separately from the secret pointer. A wiped key must
// surface as an error; falling back to the random-UUID stub would hand the
// caller a plausible password that cdsi rejects, disguising the loss of the
// key as a successful credential grant.
func TestDestroy_MakesCredentialIssuanceFailClosed(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString("cdsi-shared-secret"))
	m.Destroy()

	creds, err := m.GetAuthToken(context.Background(), "acct")
	if err == nil {
		t.Fatalf("expected an error once the secret is wiped, got credentials %+v", creds)
	}
	if creds != nil {
		t.Errorf("expected nil credentials alongside the error, got %+v", creds)
	}
	var unavailable *SharedSecretUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %T (%v), want *SharedSecretUnavailableError", err, err)
	}
	if unavailable.AccountUUID != "acct" {
		t.Errorf("AccountUUID = %q, want %q", unavailable.AccountUUID, "acct")
	}
}

// TestGetAuthToken_StubModeSurvivesDestroy is the other half: a deployment
// that never configured HMAC mode is not in a failure state, so it keeps
// serving the legacy stub.
func TestGetAuthToken_StubModeSurvivesDestroy(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	m.Destroy()

	creds, err := m.GetAuthToken(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAuthToken: %v", err)
	}
	// 36 == random UUID; 64 == HMAC-SHA256 hex.
	if len(creds.Password.Plaintext()) != 36 {
		t.Errorf("password len = %d, want 36 (random UUID stub): %q", len(creds.Password.Plaintext()), creds.Password)
	}
}

// TestSetSharedSecret_UnsetSecretReturnsToStubMode covers the explicit
// disable path, which must NOT fail closed — it is a configuration choice,
// not the loss of a key.
func TestSetSharedSecret_UnsetSecretReturnsToStubMode(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString("cdsi-shared-secret"))
	_ = m.SetSharedSecret(secrets.MustNewSecureString(""))

	creds, err := m.GetAuthToken(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAuthToken: %v", err)
	}
	if len(creds.Password.Plaintext()) != 36 {
		t.Errorf("password len = %d, want 36 (random UUID stub): %q", len(creds.Password.Plaintext()), creds.Password)
	}
}

func TestDestroy_IsIdempotentAndNilSafe(t *testing.T) {
	var nilMgr *DirectoryManager
	nilMgr.Destroy() // must not panic

	m := NewDirectoryManager(testLogger())
	m.Destroy() // no secret was ever set
	_ = m.SetSharedSecret(secrets.MustNewSecureString("s"))
	m.Destroy()
	m.Destroy()
}
