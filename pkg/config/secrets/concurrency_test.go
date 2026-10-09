package secrets

import (
	"sync"
	"testing"
)

// TestWithBytes_ConcurrentRevealsAndDestroy is the race regression test for
// the accessor's use from live request paths. A long-lived secret is revealed
// on many goroutines while another wipes it; under -race any unsynchronised
// access to the enclave pointer fails the test.
//
// The contract being pinned is that every reveal either completes on the real
// key or fails closed — there is no third outcome where it reads through a
// pointer that destruction is in the middle of clearing.
func TestWithBytes_ConcurrentRevealsAndDestroy(t *testing.T) {
	const (
		readers   = 24
		perReader = 40
	)
	s := MustNewSecureString(t.Context(), "shared-secret")

	var (
		wg               sync.WaitGroup
		mu               sync.Mutex
		mixed            bool
		revealed, failed int
	)
	start := make(chan struct{})

	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range perReader {
				var got string
				ok := s.WithBytes(t.Context(), func(b []byte) { got = string(b) })
				mu.Lock()
				switch {
				case ok && got == "shared-secret":
					revealed++
				case !ok && got == "":
					failed++
				default:
					// A partial reveal would land here: reported success with
					// the wrong bytes, or failure after fn had already run.
					mixed = true
				}
				mu.Unlock()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		s.Destroy()
	}()

	close(start)
	wg.Wait()

	if mixed {
		t.Error("a reveal observed neither the whole secret nor a clean failure")
	}
	if revealed+failed != readers*perReader {
		t.Errorf("accounted for %d of %d reveals", revealed+failed, readers*perReader)
	}
	// Destroy landing at any point is fine, but every reveal after it must
	// fail closed — so the secret must be gone by the end.
	if !s.IsDestroyed(t.Context()) {
		t.Error("secret is still readable after Destroy")
	}
}

// TestDestroy_ConcurrentDestroysWipeExactlyOnce covers the other overlap the
// lifecycle creates: a shutdown path and a component's own Close both calling
// Destroy at once.
func TestDestroy_ConcurrentDestroysWipeExactlyOnce(t *testing.T) {
	s := MustNewSecureString(t.Context(), "shared-secret")

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.Destroy()
		}()
	}
	close(start)
	wg.Wait()

	if !s.IsDestroyed(t.Context()) {
		t.Error("secret survived concurrent Destroy calls")
	}
	if got := s.Plaintext(t.Context()); got != "" {
		t.Errorf("Plaintext() = %q after Destroy, want empty", got)
	}
}

// TestClone_ConcurrentWithDestroy pins the same guarantee for Clone, which
// reveals through WithBytes and is called on component-construction paths that
// can overlap a shutdown.
func TestClone_ConcurrentWithDestroy(t *testing.T) {
	s := MustNewSecureString(t.Context(), "shared-secret")

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		clones []*SecureString
	)
	t.Cleanup(func() {
		for _, c := range clones {
			c.Destroy()
		}
	})

	start := make(chan struct{})
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, err := s.Clone(t.Context())
			if err != nil {
				t.Errorf("Clone: %v", err)
				return
			}
			mu.Lock()
			clones = append(clones, c)
			mu.Unlock()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		s.Destroy()
	}()
	close(start)
	wg.Wait()

	// Each clone is either a faithful copy or unset — never partial.
	for i, c := range clones {
		if c.IsDestroyed(t.Context()) {
			continue
		}
		if got := c.Plaintext(t.Context()); got != "shared-secret" {
			t.Errorf("clone %d = %q, want %q or unset", i, got, "shared-secret")
		}
	}
}
