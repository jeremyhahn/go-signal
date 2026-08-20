package storage

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// failClone makes the protected-memory clone fail for the duration of a test.
// Allocation failure cannot be provoked from outside the process, which is why
// the seam exists.
func failClone(t *testing.T, injected error) {
	t.Helper()
	original := cloneSecret
	cloneSecret = func(*secrets.SecureString) (*secrets.SecureString, error) { return nil, injected }
	t.Cleanup(func() { cloneSecret = original })
}

// TestNewHTTP_CloneFailureIsReportedNotMistakenForAMissingSecret pins the
// fail-closed half of the constructor.
//
// Clone used to answer "no secret to copy" and "the copy could not be
// allocated" with the same empty value, so a protected-memory failure would
// have surfaced as "SharedSecret is required" — a configuration error for what
// is actually a runtime resource failure. Worse, a caller retrying on
// configuration errors would never recover. The two are now distinct: the
// allocation failure is an internal error carrying its cause.
func TestNewHTTP_CloneFailureIsReportedNotMistakenForAMissingSecret(t *testing.T) {
	secret := secrets.MustNewSecureString("shared-secret")
	defer secret.Destroy()

	injected := errors.New("no protected memory available")
	failClone(t, injected)

	c, err := NewHTTP(HTTPConfig{BaseURL: "https://storage.example", SharedSecret: secret})
	if err == nil {
		t.Fatal("NewHTTP returned a client it could not protect a secret for")
	}
	if c != nil {
		t.Error("NewHTTP returned a client alongside the error")
	}
	if !errors.Is(err, injected) {
		t.Errorf("the injected cause was lost: %v", err)
	}

	// The caller's secret is untouched, so a retry is possible.
	if secret.IsDestroyed() {
		t.Error("a failed NewHTTP destroyed the caller's secret")
	}
}
