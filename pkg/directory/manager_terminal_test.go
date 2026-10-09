package directory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// recordClones wraps the cloneSecret seam so a test can see every copy the
// manager took ownership of. The clones are the whole point of these tests:
// the defect was a setter publishing one after shutdown, and the only way to
// prove none survived is to hold the manager's own copies and ask.
func recordClones(t *testing.T) func() []*secrets.SecureString {
	t.Helper()

	original := cloneSecret
	var (
		mu     sync.Mutex
		clones []*secrets.SecureString
	)
	cloneSecret = func(s *secrets.SecureString, ctx context.Context) (*secrets.SecureString, bool, error) {
		clone, configured, err := original(s, ctx)
		if clone != nil {
			mu.Lock()
			clones = append(clones, clone)
			mu.Unlock()
		}
		return clone, configured, err
	}
	t.Cleanup(func() { cloneSecret = original })

	return func() []*secrets.SecureString {
		mu.Lock()
		defer mu.Unlock()
		return append([]*secrets.SecureString(nil), clones...)
	}
}

// TestSetSharedSecret_AfterDestroyIsRefused pins the terminal contract in its
// simplest form: once shutdown has run, nothing installs another key.
func TestSetSharedSecret_AfterDestroyIsRefused(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	if err := m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "cdsi-shared-secret")); err != nil {
		t.Fatalf("SetSharedSecret: %v", err)
	}
	m.Destroy()

	clones := recordClones(t)
	err := m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "a-second-secret"))

	var destroyed *ManagerDestroyedError
	if !errors.As(err, &destroyed) {
		t.Fatalf("SetSharedSecret after Destroy = %v, want ManagerDestroyedError", err)
	}
	// The refused call owned the clone it made; refusing to publish does not
	// excuse it from wiping one.
	for i, clone := range clones() {
		if !clone.IsDestroyed(t.Context()) {
			t.Errorf("clone %d survived a refused SetSharedSecret", i)
		}
	}
	if st := m.state.Load(); st == nil || !st.destroyed || st.secret != nil {
		t.Errorf("state after a refused set = %+v, want terminal with no secret", st)
	}
	// And the manager still fails closed rather than minting with the key it
	// refused, or reverting to the stub.
	var unavailable *SharedSecretUnavailableError
	if _, err := m.GetAuthToken(context.Background(), "acct"); !errors.As(err, &unavailable) {
		t.Errorf("GetAuthToken after a refused set = %v, want SharedSecretUnavailableError", err)
	}
}

// A never-configured manager has nothing to wipe, which is exactly why the
// hole was there: Destroy returned early and left no marker, so a setter
// arriving afterwards installed a live secret into a manager that had already
// shut down — no race required.
func TestDestroy_OnNeverConfiguredManagerIsTerminal(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	m.Destroy()

	clones := recordClones(t)
	err := m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "cdsi-shared-secret"))

	var destroyed *ManagerDestroyedError
	if !errors.As(err, &destroyed) {
		t.Fatalf("SetSharedSecret on a destroyed unconfigured manager = %v, want ManagerDestroyedError", err)
	}
	for i, clone := range clones() {
		if !clone.IsDestroyed(t.Context()) {
			t.Errorf("clone %d survived a refused SetSharedSecret", i)
		}
	}
	if st := m.state.Load(); st == nil || !st.destroyed || st.secret != nil {
		t.Errorf("state = %+v, want terminal with no secret", st)
	}
	// The documented judgement, pinned so it stays a decision: a manager that
	// never held a key keeps serving the legacy stub after Destroy. There is
	// nothing to protect, and failing closed here would turn shutdown into an
	// outage for non-CDSI deployments in exchange for nothing.
	creds, err := m.GetAuthToken(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAuthToken on a destroyed unconfigured manager = %v, want stub credentials", err)
	}
	creds.Destroy()
}

// TestSetSharedSecret_RacingDestroyNeverLeavesALiveSecret is the regression
// test for the interleaving itself.
//
// SetSharedSecret clones before it publishes. A Destroy that ran in that gap
// used to wipe what was installed, return, and let the setter publish its
// clone afterwards — a live protected allocation, installed after shutdown
// completed, that nothing would ever wipe. The assertion is on the clones the
// manager owned, not on timing: whichever way each round is scheduled, no copy
// may be alive at the end.
func TestSetSharedSecret_RacingDestroyNeverLeavesALiveSecret(t *testing.T) {
	clones := recordClones(t)

	const rounds = 200
	for round := range rounds {
		m := NewDirectoryManager(testLogger())

		var (
			wg     sync.WaitGroup
			setErr error
		)
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			setErr = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "cdsi-shared-secret"))
		}()
		go func() {
			defer wg.Done()
			<-start
			m.Destroy()
		}()
		close(start)
		wg.Wait()

		// Only two outcomes are legal: the setter won and its key was then
		// wiped by Destroy, or it lost and was refused. Anything else means a
		// third path exists that neither side accounted for.
		var destroyed *ManagerDestroyedError
		if setErr != nil && !errors.As(setErr, &destroyed) {
			t.Fatalf("round %d: SetSharedSecret = %v, want nil or ManagerDestroyedError", round, setErr)
		}
		st := m.state.Load()
		if st == nil || !st.destroyed {
			t.Fatalf("round %d: state = %+v, want terminal", round, st)
		}
		if st.secret != nil {
			t.Fatalf("round %d: a live secret is installed after Destroy returned", round)
		}
	}

	for i, clone := range clones() {
		if !clone.IsDestroyed(t.Context()) {
			t.Errorf("clone %d is still live after its manager was destroyed", i)
		}
	}
}
