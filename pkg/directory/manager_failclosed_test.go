package directory

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// failClone makes the manager's protected-memory clone fail for the duration
// of a test. Allocation failure cannot be provoked from outside the process,
// which is why the seam exists.
func failClone(t *testing.T, injected error) {
	t.Helper()
	original := cloneSecret
	cloneSecret = func(*secrets.SecureString) (*secrets.SecureString, error) { return nil, injected }
	t.Cleanup(func() { cloneSecret = original })
}

// TestSetSharedSecret_CloneFailureDoesNotDowngradeToStub is the regression
// test for the fail-open Codex found.
//
// SetSharedSecret branched on "is the clone empty?" to choose legacy stub
// mode. Clone returned an empty value both when there was no secret to copy
// AND when the copy could not be allocated, so a protected-memory failure was
// indistinguishable from an unconfigured deployment. The consequence was not a
// crash but something quieter and worse: a CDSI-configured server would come
// up in stub mode and hand clients random UUIDs with a nil error — credentials
// cdsi rejects — under nothing more exotic than memory pressure.
//
// The manager now propagates the failure and changes nothing.
//
// Reverting SetSharedSecret to treat a failed clone as an absent secret makes
// this fail.
func TestSetSharedSecret_CloneFailureDoesNotDowngradeToStub(t *testing.T) {
	m := NewDirectoryManager(slog.Default())
	defer m.Destroy()

	secret := secrets.MustNewSecureString("shared-secret")
	defer secret.Destroy()

	injected := errors.New("no protected memory available")
	failClone(t, injected)

	if err := m.SetSharedSecret(secret); err == nil {
		t.Fatal("SetSharedSecret accepted a secret it could not protect")
	}

	// The manager must not have silently entered stub mode. Issuance either
	// fails closed or is simply unconfigured — what it must never do is return
	// a plausible credential as a success for a deployment that DID configure
	// a shared secret.
	st := m.state.Load()
	if st != nil && st.hmac && st.secret == nil {
		t.Fatal("a failed clone published HMAC mode with no key")
	}
	if st != nil && !st.hmac && st.secret != nil {
		t.Fatal("a failed clone published stub mode over a live key")
	}

	// And the caller's own secret is untouched, so a retry is possible.
	if secret.IsDestroyed() {
		t.Error("a failed SetSharedSecret destroyed the caller's secret")
	}
}

// TestSetSharedSecret_CloneFailurePreservesTheInstalledKey covers the rotation
// case the review named: a manager already minting must not lose its working
// key because a replacement could not be allocated.
//
// Reverting SetSharedSecret to swap before it knows the clone succeeded makes
// this fail.
func TestSetSharedSecret_CloneFailurePreservesTheInstalledKey(t *testing.T) {
	ctx := context.Background()
	m := NewDirectoryManager(slog.Default())
	defer m.Destroy()

	installed := secrets.MustNewSecureString("first-secret")
	defer installed.Destroy()
	if err := m.SetSharedSecret(installed); err != nil {
		t.Fatalf("SetSharedSecret: %v", err)
	}

	before, err := m.GetAuthToken(ctx, "acct")
	if err != nil {
		t.Fatalf("GetAuthToken: %v", err)
	}
	want := before.Password.Plaintext()
	before.Password.Destroy()

	rotating := secrets.MustNewSecureString("second-secret")
	defer rotating.Destroy()

	failClone(t, errors.New("no protected memory available"))
	if err := m.SetSharedSecret(rotating); err == nil {
		t.Fatal("a rotation that could not be allocated reported success")
	}

	// Still minting, and with the SAME key as before the failed rotation.
	after, err := m.GetAuthToken(ctx, "acct")
	if err != nil {
		t.Fatalf("the manager stopped minting after a failed rotation: %v", err)
	}
	got := after.Password.Plaintext()
	after.Password.Destroy()

	if got != want {
		t.Error("a failed rotation replaced or destroyed the installed key")
	}
	if len(got) != 64 {
		t.Errorf("password is %d chars, want the 64-char HMAC digest — the manager fell back to the stub", len(got))
	}
}
