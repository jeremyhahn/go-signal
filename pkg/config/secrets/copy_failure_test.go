package secrets

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ctxIgnoringResolver seals under context.Background so the secret it returns
// is valid however the caller's context is later canceled.
type ctxIgnoringResolver struct{ value string }

func (ctxIgnoringResolver) Scheme() string { return "kms" }
func (r ctxIgnoringResolver) Resolve(context.Context, string) (*SecureString, error) {
	return NewSecureString(context.Background(), r.value)
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestCachingResolver_CopyFailureIsAnError: when the copy handed to the caller
// cannot be made because the cached secret will not open, Resolve must fail.
// It used to read the secret as "", turn that into an unset SecureString and
// report success, losing a configured secret with no error.
func TestCachingResolver_CopyFailureIsAnError(t *testing.T) {
	for name, warm := range map[string]bool{
		"cache hit":        true,
		"fresh from fetch": false,
	} {
		t.Run(name, func(t *testing.T) {
			c := NewCachingResolver(ctxIgnoringResolver{value: "v1"}, time.Minute)
			if warm {
				first, err := c.Resolve(t.Context(), "kms://a")
				if err != nil {
					t.Fatalf("warm Resolve: %v", err)
				}
				defer first.Destroy()
			}

			got, err := c.Resolve(canceledContext(), "kms://a")
			var unavailable *UnavailableSecretError
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %T (%v), want *UnavailableSecretError", err, err)
			}
			if got != nil {
				t.Error("Resolve returned a SecureString alongside the error")
			}
		})
	}
}

// TestAutoGenResolver_CachedCopyFailureNamesTheOpenFailure: the cached
// generated secret failing to open is reported as such, not as an empty
// secret.
func TestAutoGenResolver_CachedCopyFailureNamesTheOpenFailure(t *testing.T) {
	r := NewAutoGenResolver(16)
	first, err := r.Resolve(t.Context(), "auto")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	defer first.Destroy()

	got, err := r.Resolve(canceledContext(), "auto")
	var unavailable *UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %T (%v), want *UnavailableSecretError", err, err)
	}
	if got != nil {
		t.Error("Resolve returned a SecureString alongside the error")
	}
}
