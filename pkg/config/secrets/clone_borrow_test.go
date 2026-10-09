package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// TestClone_StagedSourceHoldsOneBorrowAtATime arms go-qrdb's nested-borrow
// guard around the page-to-page copy of a staged source. v0.46 forbids any
// secure-package call inside a WithBytes callback, whichever object it targets,
// so a copy that borrows the destination from inside the source's borrow is a
// violation even though the two buffers have independent locks.
func TestClone_StagedSourceHoldsOneBorrowAtATime(t *testing.T) {
	defer secure.GuardBorrows(t.Fatalf)()

	src := stagedSource(t)
	defer src.Destroy()

	clone, err := src.Clone(t.Context())
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer clone.Destroy()

	got, err := clone.Reveal(t.Context())
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if got != "shared-secret" {
		t.Errorf("clone = %q, want %q", got, "shared-secret")
	}
}

// TestClone_UnopenableSourceIsAnError pins that a configured secret which
// cannot be opened — here a canceled context refuses the open — is reported,
// not returned as an unset clone. An unset clone reads as "no secret
// configured" to every caller that branches on emptiness.
func TestClone_UnopenableSourceIsAnError(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	for name, source := range map[string]func(*testing.T) *SecureString{
		"sealed": sealedSource,
		"staged": stagedSource,
	} {
		t.Run(name, func(t *testing.T) {
			src := source(t)
			defer src.Destroy()
			if name == "staged" {
				// A staged value is borrowed in place and ignores ctx; seal it
				// so the canceled context reaches the open.
				if err := src.Seal(t.Context()); err != nil {
					t.Fatalf("Seal: %v", err)
				}
			}

			clone, err := src.Clone(canceled)
			var unavailable *UnavailableSecretError
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %T (%v), want *UnavailableSecretError", err, err)
			}
			if clone != nil {
				t.Error("Clone returned a SecureString alongside the error")
			}
		})
	}
}
