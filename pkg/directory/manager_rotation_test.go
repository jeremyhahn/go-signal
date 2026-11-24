package directory

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// rotationRaceRounds is sized so the two setters interleave many times on a
// multi-core runner. Publishing mode and key as two independent atomics leaves
// a window a few instructions wide, so the round count is what gives the test
// its power.
const rotationRaceRounds = 3000

// TestSetSharedSecret_ConcurrentRotationsNeverStrandHMACModeWithoutAKey checks a completed rotation leaves the manager able to issue.
func TestSetSharedSecret_ConcurrentRotationsNeverStrandHMACModeWithoutAKey(t *testing.T) {
	ctx := context.Background()

	for round := range rotationRaceRounds {
		m := NewDirectoryManager(slog.Default())

		configured := secrets.MustNewSecureString("shared-secret")
		stub := secrets.MustNewSecureString("")

		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, s := range []*secrets.SecureString{configured, stub} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_ = m.SetSharedSecret(s)
			}()
		}
		close(start)
		wg.Wait()

		// Both setters have returned. Whichever finished last, the manager is
		// now in a settled configuration and must be able to issue under it.
		creds, err := m.GetAuthToken(ctx, "acct")
		var unavailable *SharedSecretUnavailableError
		if errors.As(err, &unavailable) {
			t.Fatalf("round %d: rotation stranded HMAC mode with no revealable key; "+
				"issuance now fails closed permanently: %v", round, err)
		}
		if err != nil {
			t.Fatalf("round %d: GetAuthToken: %v", round, err)
		}
		creds.Password.Destroy()

		configured.Destroy()
		stub.Destroy()
		m.Destroy()
	}
}

// TestSetSharedSecret_ConcurrentRotationsNeverSplitModeFromKey checks mode and key always agree.
func TestSetSharedSecret_ConcurrentRotationsNeverSplitModeFromKey(t *testing.T) {
	for round := range rotationRaceRounds {
		m := NewDirectoryManager(slog.Default())

		configured := secrets.MustNewSecureString("shared-secret")
		stub := secrets.MustNewSecureString("")

		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, s := range []*secrets.SecureString{configured, stub} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_ = m.SetSharedSecret(s)
			}()
		}
		close(start)
		wg.Wait()

		st := m.state.Load()
		if st.hmac != (st.secret != nil) {
			t.Fatalf("round %d: mode and key disagree — hmac=%v, key installed=%v",
				round, st.hmac, st.secret != nil)
		}

		configured.Destroy()
		stub.Destroy()
		m.Destroy()
	}
}

// TestDestroy_ConcurrentWithRotationConsistentState checks mode and key agree whichever of Destroy and a setter wins.
func TestDestroy_ConcurrentWithRotationConsistentState(t *testing.T) {
	for round := range rotationRaceRounds {
		m := NewDirectoryManager(slog.Default())
		first := secrets.MustNewSecureString("first")
		_ = m.SetSharedSecret(first)

		rotating := secrets.MustNewSecureString("second")

		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; m.SetSharedSecret(rotating) }()
		go func() { defer wg.Done(); <-start; m.Destroy() }()
		close(start)
		wg.Wait()

		// Destroy is the last word only if it ran last; a setter that landed
		// after it legitimately leaves a key installed. What must never happen
		// is a state whose mode disagrees with whether a key is there.
		if st := m.state.Load(); !st.hmac && st.secret != nil {
			t.Fatalf("round %d: a key is installed while stub mode is advertised", round)
		}

		// A rotation that won the race left a manager-owned clone live;
		// wipe it before the next round rather than accumulating one
		// protected allocation per iteration.
		m.Destroy()
		first.Destroy()
		rotating.Destroy()
	}
}
