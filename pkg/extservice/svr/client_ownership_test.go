package svr

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

// TestNewHTTP_DestroyDuringOwnershipTransfer checks a client NewHTTP returns can derive credentials even if the caller destroys the secret concurrently.
func TestNewHTTP_DestroyDuringOwnershipTransfer(t *testing.T) {
	for round := range ownershipRaceRounds {
		secret := secrets.MustNewSecureString("shared-secret")

		var wg sync.WaitGroup
		wg.Add(1)
		release := make(chan struct{})
		go func() {
			defer wg.Done()
			<-release
			secret.Destroy()
		}()

		close(release)
		c, err := NewHTTP(HTTPConfig{BaseURL: "https://svr2.example", SharedSecret: secret})
		if err == nil {
			if common.BasicAuthHeaderSecret("acct", c.secret) == "" {
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
	secret := secrets.MustNewSecureString("shared-secret")
	c, err := NewHTTP(HTTPConfig{BaseURL: "https://svr2.example", SharedSecret: secret})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	defer func() { _ = c.Close() }()

	secret.Destroy()

	if common.BasicAuthHeaderSecret("acct", c.secret) == "" {
		t.Fatal("client lost its credentials when the caller destroyed its own secret")
	}
}
