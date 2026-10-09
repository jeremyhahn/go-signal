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
	cloneSecret = func(*secrets.SecureString, context.Context) (*secrets.SecureString, bool, error) {
		return nil, false, injected
	}
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

	secret := secrets.MustNewSecureString(t.Context(), "shared-secret")
	defer secret.Destroy()

	injected := errors.New("no protected memory available")
	failClone(t, injected)

	if err := m.SetSharedSecret(t.Context(), secret); err == nil {
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
	if secret.IsDestroyed(t.Context()) {
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

	installed := secrets.MustNewSecureString(t.Context(), "first-secret")
	defer installed.Destroy()
	if err := m.SetSharedSecret(t.Context(), installed); err != nil {
		t.Fatalf("SetSharedSecret: %v", err)
	}

	before, err := m.GetAuthToken(ctx, "acct")
	if err != nil {
		t.Fatalf("GetAuthToken: %v", err)
	}
	want := before.Password.Plaintext(t.Context())
	before.Password.Destroy()

	rotating := secrets.MustNewSecureString(t.Context(), "second-secret")
	defer rotating.Destroy()

	failClone(t, errors.New("no protected memory available"))
	if err := m.SetSharedSecret(t.Context(), rotating); err == nil {
		t.Fatal("a rotation that could not be allocated reported success")
	}

	// Still minting, and with the SAME key as before the failed rotation.
	after, err := m.GetAuthToken(ctx, "acct")
	if err != nil {
		t.Fatalf("the manager stopped minting after a failed rotation: %v", err)
	}
	got := after.Password.Plaintext(t.Context())
	after.Password.Destroy()

	if got != want {
		t.Error("a failed rotation replaced or destroyed the installed key")
	}
	if len(got) != 64 {
		t.Errorf("password is %d chars, want the 64-char HMAC digest — the manager fell back to the stub", len(got))
	}
}

// TestSetSharedSecret_UnopenableSecretDoesNotDowngradeToStub is the
// regression test for the second half of the same fail-open (#15 §1).
//
// The clone-failure path above was fixed, but the branch that CHOSE stub mode
// still asked IsDestroyed, which reports true for three different states:
// never configured, destroyed, and configured-but-unopenable. Only the first
// means "this deployment did not ask for CDSI". The other two mean a key is
// installed and cannot be read, and answering those with the legacy stub
// hands out random UUIDs cdsi rejects — the same invisible downgrade, reached
// by a different route.
//
// A configured secret that has been destroyed is exactly that state: it is
// not absent, and it cannot be revealed.
//
// Reverting the branch to IsDestroyed makes this fail: the manager returns
// nil and quietly installs stub mode.
func TestSetSharedSecret_UnopenableSecretDoesNotDowngradeToStub(t *testing.T) {
	m := NewDirectoryManager(slog.Default())
	defer m.Destroy()

	// Configured, then wiped: IsAbsent() is false, every reveal fails.
	secret := secrets.MustNewSecureString(t.Context(), "shared-secret")
	secret.Destroy()

	if err := m.SetSharedSecret(t.Context(), secret); err == nil {
		t.Fatal("SetSharedSecret accepted a configured secret it could not open")
	}

	// Nothing may have been published. With the branch reverted to
	// IsDestroyed this call returns nil and installs a stub state here,
	// which is the downgrade being guarded against; the error return is what
	// makes cmd/signald abort startup instead of serving random UUIDs.
	if st := m.state.Load(); st != nil {
		t.Fatalf("an unopenable configured secret published state: hmac=%v key=%v",
			st.hmac, st.secret != nil)
	}
}

// The absent case must keep working: an unset secret is a deployment choice,
// not a failure, and still selects the stub.
func TestSetSharedSecret_AbsentSecretStillSelectsTheStub(t *testing.T) {
	m := NewDirectoryManager(slog.Default())
	defer m.Destroy()

	if err := m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "")); err != nil {
		t.Fatalf("an absent secret is not a failure, got: %v", err)
	}

	st := m.state.Load()
	if st == nil {
		t.Fatal("no state published")
	}
	if st.hmac {
		t.Error("an absent secret must select stub mode, not HMAC mode")
	}
	if st.secret != nil {
		t.Error("stub mode must hold no key")
	}

	// And issuance still works, returning the legacy random credential.
	if _, err := m.GetAuthToken(context.Background(), "user-1"); err != nil {
		t.Errorf("stub mode should still issue credentials, got: %v", err)
	}
}
