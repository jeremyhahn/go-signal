package storage

import (
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
)

// ownershipRaceRounds is sized so NewHTTP and the caller's Destroy interleave
// many times on a multi-core runner. The window under test is a few
// instructions wide, so the round count is what gives the test its power.
const ownershipRaceRounds = 4000

// TestNewHTTP_DestroyDuringOwnershipTransfer overlaps NewHTTP with the caller
// destroying the shared secret it passed in.
//
// The contract under test is the constructor's verdict: a client returned
// without an error must be able to derive credentials. Validating
// cfg.SharedSecret and cloning it afterwards cannot honour that — the two
// steps are separate reveals of a secret the caller still owns, so a Destroy
// landing between them leaves NewHTTP reporting success over an unset clone
// and every later request failing closed. Cloning first and validating the
// clone closes the window, because the value checked is the value kept.
//
// Reverting NewHTTP to check-then-clone makes this fail.
func TestNewHTTP_DestroyDuringOwnershipTransfer(t *testing.T) {
	for round := range ownershipRaceRounds {
		secret := secrets.MustNewSecureString(t.Context(), "shared-secret")

		var wg sync.WaitGroup
		wg.Add(1)
		release := make(chan struct{})
		go func() {
			defer wg.Done()
			<-release
			secret.Destroy()
		}()

		close(release)
		c, err := NewHTTP(t.Context(), HTTPConfig{BaseURL: "https://storage.example", SharedSecret: secret})
		if err == nil {
			if common.BasicAuthHeaderSecret(t.Context(), "acct", c.secret) == "" {
				t.Fatalf("round %d: NewHTTP reported success but the client cannot derive credentials", round)
			}
			_ = c.Close()
		}

		wg.Wait()
		secret.Destroy()
	}
}

// TestNewHTTP_ClonesRatherThanValidatesCallerSecret pins the ownership
// contract the race above depends on: the client holds its own enclave, so the
// caller destroying its copy afterwards leaves the client signing.
func TestNewHTTP_ClonesRatherThanValidatesCallerSecret(t *testing.T) {
	secret := secrets.MustNewSecureString(t.Context(), "shared-secret")
	c, err := NewHTTP(t.Context(), HTTPConfig{BaseURL: "https://storage.example", SharedSecret: secret})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	defer func() { _ = c.Close() }()

	secret.Destroy()

	if common.BasicAuthHeaderSecret(t.Context(), "acct", c.secret) == "" {
		t.Fatal("client lost its credentials when the caller destroyed its own secret")
	}
}
