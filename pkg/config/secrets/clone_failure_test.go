package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
	"gopkg.in/yaml.v3"
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
	sealProtectedBuffer = func(context.Context, *secure.Buffer) (*secure.Secret, error) { return nil, injected }
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

	// A sealed source opens into a fresh buffer and seals that in place, so
	// only the sealing step can fail. A staged source (decoded from YAML, not
	// yet sealed) is copied into a new buffer first, so both steps can.
	for name, tc := range map[string]struct {
		source func(*testing.T) *SecureString
		inject func(*testing.T, error)
	}{
		"sealed source, buffer sealing":    {sealedSource, failProtectedSeal},
		"staged source, buffer allocation": {stagedSource, failProtectedBuffer},
		"staged source, buffer sealing":    {stagedSource, failProtectedSeal},
	} {
		t.Run(name, func(t *testing.T) {
			src := tc.source(t)
			defer src.Destroy()

			tc.inject(t, injected)

			clone, err := src.Clone(t.Context())
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
			if src.IsDestroyed(t.Context()) {
				t.Error("a failed Clone destroyed its source")
			}
			if got := src.Plaintext(t.Context()); got != "shared-secret" {
				t.Errorf("source = %q after a failed Clone, want %q", got, "shared-secret")
			}
		})
	}
}

// sealedSource returns a SecureString whose value is already sealed.
func sealedSource(t *testing.T) *SecureString {
	t.Helper()
	return MustNewSecureString(t.Context(), "shared-secret")
}

// stagedSource returns a SecureString decoded from YAML and not yet sealed,
// the state config.Load leaves a secret in until it seals the config.
func stagedSource(t *testing.T) *SecureString {
	t.Helper()
	var c struct {
		Secret SecureString `yaml:"secret"`
	}
	if err := yaml.Unmarshal([]byte(`secret: "shared-secret"`), &c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return &c.Secret
}

// TestClone_AbsentSecretIsNotAnError pins the other half of the distinction:
// a receiver with nothing to copy is a legitimate configuration, not a
// failure, and must stay cheap to express.
func TestClone_AbsentSecretIsNotAnError(t *testing.T) {
	destroyed := MustNewSecureString(t.Context(), "x")
	destroyed.Destroy()

	for name, src := range map[string]*SecureString{
		"nil":       nil,
		"unset":     MustNewSecureString(t.Context(), ""),
		"destroyed": destroyed,
	} {
		t.Run(name, func(t *testing.T) {
			clone, err := src.Clone(t.Context())
			if err != nil {
				t.Fatalf("an absent secret is not a failure, got: %v", err)
			}
			if clone == nil {
				t.Fatal("Clone returned nil without an error")
			}
			if !clone.IsDestroyed(t.Context()) {
				t.Error("expected an unset clone")
			}
		})
	}
}
