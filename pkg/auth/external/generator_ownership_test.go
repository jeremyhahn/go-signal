package external

import (
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// ownershipRaceRounds is sized so the constructor and the caller's Destroy
// interleave many times on a multi-core runner. The window under test is a
// few instructions wide, so one round proves nothing and the count is what
// gives the test its power.
const ownershipRaceRounds = 4000

// TestNewGenerator_DestroyDuringOwnershipTransfer overlaps NewGenerator with
// the caller destroying the key it passed in.
//
// The contract under test is the constructor's verdict: if NewGenerator
// returns no error, the Generator it returned must be able to sign. Validating
// cfg.Key and cloning it afterwards cannot honour that — the two steps are
// separate reveals of a secret the caller still owns, so a Destroy landing
// between them leaves the constructor reporting success over an unset clone.
// Cloning first and validating the clone closes the window, because the value
// checked is the value kept.
//
// Reverting NewGenerator to check-then-clone makes this fail.
func TestNewGenerator_DestroyDuringOwnershipTransfer(t *testing.T) {
	for round := range ownershipRaceRounds {
		key := secrets.MustNewSecureString("shared-secret")

		var wg sync.WaitGroup
		wg.Add(1)
		release := make(chan struct{})
		go func() {
			defer wg.Done()
			<-release
			key.Destroy()
		}()

		close(release)
		g, err := NewGenerator(GeneratorConfig{Key: key})
		if err == nil {
			issued, genErr := g.Generate("acct")
			if genErr != nil {
				t.Fatalf("round %d: NewGenerator reported success but Generate failed: %v", round, genErr)
			}
			issued.Destroy()
			g.Destroy()
		}

		wg.Wait()
		key.Destroy()
	}
}

// TestNewGenerator_ClonesRatherThanValidatesCallerKey pins the ownership
// contract the race above depends on: the Generator holds its own enclave, so
// the caller destroying its copy afterwards leaves the Generator signing.
func TestNewGenerator_ClonesRatherThanValidatesCallerKey(t *testing.T) {
	key := secrets.MustNewSecureString("shared-secret")
	g, err := NewGenerator(GeneratorConfig{Key: key})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	defer g.Destroy()

	key.Destroy()

	creds, err := g.Generate("acct")
	if err != nil {
		t.Fatalf("Generate after the caller destroyed its own key: %v", err)
	}
	defer creds.Destroy()
	if creds.Password.IsDestroyed() {
		t.Fatal("Generate returned an unset password")
	}
}

// TestNewGenerator_DestroyedKeyIsRejected covers the deterministic half: a key
// already gone when the constructor is called yields an error and no
// Generator, rather than one that fails at first use.
func TestNewGenerator_DestroyedKeyIsRejected(t *testing.T) {
	key := secrets.MustNewSecureString("shared-secret")
	key.Destroy()

	g, err := NewGenerator(GeneratorConfig{Key: key})
	if err == nil {
		t.Fatal("NewGenerator accepted a destroyed key")
	}
	if g != nil {
		t.Fatal("NewGenerator returned a Generator alongside an error")
	}
}
