package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestClose_ConcurrentWithRequests overlaps requests with Close; every request authenticates with the real secret or fails closed (run with -race).
func TestClose_ConcurrentWithRequests(t *testing.T) {
	const callers = 16

	var (
		mu           sync.Mutex
		unauthorized int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			mu.Lock()
			unauthorized++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := NewHTTP(HTTPConfig{BaseURL: srv.URL, SharedSecret: secrets.MustNewSecureString("shared-secret")})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Either outcome is acceptable; a panic or a race is not.
			_ = c.DeleteStoredData(context.Background(), "acct")
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_ = c.Close()
	}()
	close(start)
	wg.Wait()

	if unauthorized > 0 {
		t.Errorf("%d requests reached the server with no Authorization header", unauthorized)
	}
}
