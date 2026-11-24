package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// failProtectedSeal makes sealing the opened buffer fail for the duration of a
// test, so the fail-closed path can be exercised. A sealing failure cannot be
// provoked from outside, which is why the seam exists. Like the real
// NewSecretFromBuffer, the double consumes the buffer it is handed.
func failProtectedSeal(t *testing.T, injected error) {
	t.Helper()
	original := sealProtectedBuffer
	sealProtectedBuffer = func(_ context.Context, buf *secure.Buffer) (*secure.Secret, error) {
		buf.Destroy()
		return nil, injected
	}
	t.Cleanup(func() { sealProtectedBuffer = original })
}

// TestClone_AllocationFailureIsAnErrorNotAnEmptyValue: Clone must report an allocation failure as an error, distinct from no secret.
func TestClone_AllocationFailureIsAnErrorNotAnEmptyValue(t *testing.T) {
	injected := errors.New("no protected memory available")

	for name, inject := range map[string]func(*testing.T, error){
		"buffer sealing": failProtectedSeal,
	} {
		t.Run(name, func(t *testing.T) {
			src := MustNewSecureString("shared-secret")
			defer src.Destroy()

			inject(t, injected)

			clone, err := src.Clone()
			if err == nil {
				t.Fatal("Clone reported success despite an allocation failure")
			}
			var sealErr *SealError
			if !errors.As(err, &sealErr) {
				t.Errorf("err = %T (%v), want *SealError", err, err)
			}
			if !errors.Is(err, injected) && !errors.Is(sealErr.Cause, injected) {
				t.Errorf("the injected cause was lost: %v", err)
			}
			if clone != nil {
				t.Error("Clone returned a SecureString alongside the error — a caller checking only emptiness would treat it as 'no secret configured'")
			}

			// The source must be untouched: a failed copy is not a reason to
			// lose the original.
			if src.IsDestroyed() {
				t.Error("a failed Clone destroyed its source")
			}
			if got := src.Plaintext(); got != "shared-secret" {
				t.Errorf("source = %q after a failed Clone, want %q", got, "shared-secret")
			}
		})
	}
}

// TestClone_AbsentSecretIsNotAnError pins the other half of the distinction:
// a receiver with nothing to copy is a legitimate configuration, not a
// failure, and must stay cheap to express.
func TestClone_AbsentSecretIsNotAnError(t *testing.T) {
	destroyed := MustNewSecureString("x")
	destroyed.Destroy()

	for name, src := range map[string]*SecureString{
		"nil":       nil,
		"unset":     MustNewSecureString(""),
		"destroyed": destroyed,
	} {
		t.Run(name, func(t *testing.T) {
			clone, err := src.Clone()
			if err != nil {
				t.Fatalf("an absent secret is not a failure, got: %v", err)
			}
			if clone == nil {
				t.Fatal("Clone returned nil without an error")
			}
			if !clone.IsDestroyed() {
				t.Error("expected an unset clone")
			}
		})
	}
}
