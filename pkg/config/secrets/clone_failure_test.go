package secrets

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// failProtectedBuffer makes the protected allocator fail for the duration of a
// test, so the fail-closed path can be exercised. Allocation failure cannot be
// provoked from outside, which is why the seam exists.
func failProtectedBuffer(t *testing.T, injected error) {
	t.Helper()
	original := newProtectedBuffer
	newProtectedBuffer = func(int) (*secure.Buffer, error) { return nil, injected }
	t.Cleanup(func() { newProtectedBuffer = original })
}

// failProtectedSeal makes sealing the copied buffer fail, covering the second
// allocation step independently of the first.
func failProtectedSeal(t *testing.T, injected error) {
	t.Helper()
	original := sealProtectedBuffer
	sealProtectedBuffer = func(*secure.Buffer) (*secure.Secret, error) { return nil, injected }
	t.Cleanup(func() { sealProtectedBuffer = original })
}

// TestClone_AllocationFailureIsAnErrorNotAnEmptyValue is the regression test
// for the fail-open this change closes.
//
// Clone used to return an unset SecureString for BOTH "there is no secret to
// copy" and "the copy could not be allocated". Callers branch on emptiness to
// choose legacy stub behaviour, so the second case silently became the first:
// under memory pressure a configured deployment would downgrade to random
// credentials its peer rejects, with no error anywhere. The two outcomes are
// now distinguishable, which is the whole point.
//
// Reverting Clone to a single return value makes this fail to compile, which is
// the strongest form of the guard.
func TestClone_AllocationFailureIsAnErrorNotAnEmptyValue(t *testing.T) {
	injected := errors.New("no protected memory available")

	for name, inject := range map[string]func(*testing.T, error){
		"buffer allocation": failProtectedBuffer,
		"buffer sealing":    failProtectedSeal,
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
