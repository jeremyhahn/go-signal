package directory

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestGetAuthToken_ConcurrentWithDestroy checks issuance racing Destroy yields an HMAC password or SharedSecretUnavailableError, never a stub.
func TestGetAuthToken_ConcurrentWithDestroy(t *testing.T) {
	const (
		callers   = 16
		perCaller = 25
	)
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(secrets.MustNewSecureString("cdsi-shared-secret"))

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
				case err == nil && len(creds.Password.Plaintext()) == 64: // HMAC-SHA256 hex
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
	return fmt.Sprintf("password of %d chars", len(creds.Password.Plaintext()))
}
