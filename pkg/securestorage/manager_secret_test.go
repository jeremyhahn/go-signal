package securestorage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestGetAuth_WireFormUnchangedByProtectedSecret pins the storage-service
// credential bytes to the plain-[]byte HMAC this manager produced before the
// secret moved into protected memory. cmd/storage-service re-derives the same
// digest to authenticate.
func TestGetAuth_WireFormUnchangedByProtectedSecret(t *testing.T) {
	const secret, acct = "storage-shared-secret", "b9d0d4e2-0000-4000-8000-000000000001"

	m := NewSecureStorageManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString(secret))
	defer m.Destroy()

	creds, err := m.GetAuth(context.Background(), acct)
	if err != nil {
		t.Fatalf("GetAuth: %v", err)
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
	m := NewSecureStorageManager(testLogger())
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
	m := NewSecureStorageManager(testLogger())
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
// signald passes cfg.StorageService.SharedSecret, wiped separately by
// cfg.Destroy.
func TestSetSharedSecret_ClonesTheCallersSecret(t *testing.T) {
	src := secrets.MustNewSecureString("storage-shared-secret")
	defer src.Destroy()

	m := NewSecureStorageManager(testLogger())
	_ = m.SetSharedSecret(src)
	m.Destroy()

	if src.IsDestroyed() {
		t.Error("Destroy wiped the caller's secret")
	}
	if got := src.Plaintext(); got != "storage-shared-secret" {
		t.Errorf("caller's secret = %q, want %q", got, "storage-shared-secret")
	}
}

// TestDestroy_MakesCredentialIssuanceFailClosed is the reason the manager
// tracks HMAC mode separately from the secret pointer. A wiped key must
// surface as an error; falling back to the random-UUID stub would hand the
// caller a plausible password that storage-service rejects, disguising the
// loss of the key as a successful credential grant.
func TestDestroy_MakesCredentialIssuanceFailClosed(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString("storage-shared-secret"))
	m.Destroy()

	creds, err := m.GetAuth(context.Background(), "acct")
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

// TestGetAuth_StubModeSurvivesDestroy is the other half: a deployment that
// never configured HMAC mode is not in a failure state, so it keeps serving
// the legacy stub.
func TestGetAuth_StubModeSurvivesDestroy(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.Destroy()

	creds, err := m.GetAuth(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAuth: %v", err)
	}
	// 36 == random UUID; 64 == HMAC-SHA256 hex.
	if len(creds.Password.Plaintext()) != 36 {
		t.Errorf("password len = %d, want 36 (random UUID stub): %q", len(creds.Password.Plaintext()), creds.Password.Plaintext())
	}
}

// TestSetSharedSecret_UnsetSecretReturnsToStubMode covers the explicit
// disable path, which must NOT fail closed — it is a configuration choice,
// not the loss of a key.
func TestSetSharedSecret_UnsetSecretReturnsToStubMode(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString("storage-shared-secret"))
	_ = m.SetSharedSecret(secrets.MustNewSecureString(""))

	creds, err := m.GetAuth(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAuth: %v", err)
	}
	if len(creds.Password.Plaintext()) != 36 {
		t.Errorf("password len = %d, want 36 (random UUID stub): %q", len(creds.Password.Plaintext()), creds.Password.Plaintext())
	}
}

func TestDestroy_IsIdempotentAndNilSafe(t *testing.T) {
	var nilMgr *SecureStorageManager
	nilMgr.Destroy() // must not panic

	m := NewSecureStorageManager(testLogger())
	m.Destroy() // no secret was ever set
	_ = m.SetSharedSecret(secrets.MustNewSecureString("s"))
	m.Destroy()
	m.Destroy()
}
