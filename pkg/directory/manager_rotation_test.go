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

// TestSetSharedSecret_ConcurrentRotationsNeverStrandHMACModeWithoutAKey races
// an HMAC-configuring setter against a stub-configuring one.
//
// The manager has exactly two legitimate resting states: HMAC mode over a key
// it can reveal, or the legacy stub. Publishing the mode flag and the secret
// through two independent atomics admits a third, because the stores can
// interleave: the stub setter's swap lands between the HMAC setter's install
// and its mode store, so the key just installed is wiped and HMAC mode is then
// announced over nothing. Issuance fails closed from that point on and never
// recovers, because the mode deliberately does not revert — a deployment whose
// last completed configuration was a real shared secret can no longer mint
// anything at all.
//
// The assertion is deliberately behavioural, not a peek at the manager's
// fields: it is the contract "a completed rotation leaves the manager able to
// issue", which holds however the state happens to be represented. That is
// what lets it be checked against the two-atomic implementation it replaced.
//
// Reverting SetSharedSecret to two independent atomic stores makes this fail.
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

// TestSetSharedSecret_ConcurrentRotationsNeverSplitModeFromKey pins the same
// property from the other side, where behaviour alone cannot see it: a key
// installed while stub mode is advertised issues a random UUID that looks like
// a valid credential and that cdsi rejects, which is indistinguishable from a
// legitimate stub result. Only the state itself distinguishes them.
//
// Publishing both fields as one immutable value makes the mixture
// unrepresentable, which is what this asserts.
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

// TestDestroy_ConcurrentWithRotationConsistentState races Destroy against a
// setter and asserts the ONE property this design guarantees: whatever state
// wins, mode and key agree. Destroy carries the current mode flag forward with
// a compare-and-swap, so a rotation landing in between is simply the newer
// configuration.
//
// What this test does NOT establish, stated plainly because an earlier version
// implied otherwise: it does not prove Destroy is terminal. A setter that
// completes after Destroy returns legitimately leaves a key installed under
// the current design — there is no tombstone state for setters to CAS
// against. An earlier version ended with a second Destroy and asserted nothing
// survived, which is true of any uncontended Destroy and therefore masked
// exactly that gap rather than testing it. The gap is real and tracked
// separately; making Destroy terminal changes SetSharedSecret's contract and
// belongs in its own change.
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
