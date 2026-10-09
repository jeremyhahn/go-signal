package directory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestGetAuthToken_ConcurrentWithDestroy overlaps live credential issuance
// with the shutdown-path wipe, which is exactly how the manager is used: the
// REST handler mints on request goroutines while runStart destroys on the way
// out. Under -race this fails if the secret is touched unsynchronised.
//
// Every issuance must land on one of two outcomes — a real HMAC password, or
// a SharedSecretUnavailableError. A random-UUID stub password would mean the
// wipe had been mistaken for "HMAC was never configured".
func TestGetAuthToken_ConcurrentWithDestroy(t *testing.T) {
	const (
		callers   = 16
		perCaller = 25
	)
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "cdsi-shared-secret"))

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		bad []string
	)
	start := make(chan struct{})

	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range perCaller {
				creds, err := m.GetAuthToken(context.Background(), "acct")
				// Every issued credential is a protected allocation; a stress
				// loop that abandons them exhausts mlock long before it proves
				// anything.
				if creds != nil {
					defer creds.Password.Destroy()
				}
				var unavailable *SharedSecretUnavailableError
				switch {
				case err == nil && len(creds.Password.Plaintext(t.Context())) == 64: // HMAC-SHA256 hex
				case errors.As(err, &unavailable) && creds == nil:
				default:
					mu.Lock()
					bad = append(bad, describe(creds, err))
					mu.Unlock()
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		m.Destroy()
	}()

	close(start)
	wg.Wait()

	if len(bad) > 0 {
		t.Errorf("%d issuances were neither a real credential nor a clean failure, e.g. %s", len(bad), bad[0])
	}
}

func describe(creds *DirectoryCredentials, err error) string {
	if err != nil {
		return "err=" + err.Error()
	}
	if creds == nil {
		return "nil credentials and nil error"
	}
	// Report the shape, never the credential: this string reaches a CI log
	// on failure, and a bearer password there outlives every wipe.
	return fmt.Sprintf("password of %d chars", len(creds.Password.Plaintext(context.Background())))
}
