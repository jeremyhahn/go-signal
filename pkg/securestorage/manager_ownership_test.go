package securestorage

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// ownershipRaceRounds is sized so SetSharedSecret and the caller's Destroy
// interleave many times on a multi-core runner. The window under test is a few
// instructions wide, so the round count is what gives the test its power.
const ownershipRaceRounds = 4000

// TestSetSharedSecret_DestroyDuringOwnershipTransfer: SetSharedSecret ends in HMAC mode over a readable key or the stub, never HMAC over an unset clone.
func TestSetSharedSecret_DestroyDuringOwnershipTransfer(t *testing.T) {
	ctx := context.Background()

	for round := range ownershipRaceRounds {
		m := NewSecureStorageManager(slog.Default())
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
		_ = m.SetSharedSecret(secret)

		creds, err := m.GetAuth(ctx, "acct")
		var unavailable *SharedSecretUnavailableError
		if errors.As(err, &unavailable) {
			t.Fatalf("round %d: manager settled in HMAC mode with no revealable key: %v", round, err)
		}
		if err != nil {
			t.Fatalf("round %d: GetAuth: %v", round, err)
		}
		if creds.Password.Plaintext() == "" {
			t.Fatalf("round %d: GetAuth returned an empty password", round)
		}

		wg.Wait()
		secret.Destroy()
		m.Destroy()
	}
}

// TestSetSharedSecret_ClonesRatherThanValidatesCallerSecret pins the ownership
// contract the race above depends on: the manager holds its own enclave, so
// the caller destroying its copy afterwards leaves the manager minting.
func TestSetSharedSecret_ClonesRatherThanValidatesCallerSecret(t *testing.T) {
	m := NewSecureStorageManager(slog.Default())
	defer m.Destroy()

	secret := secrets.MustNewSecureString("shared-secret")
	_ = m.SetSharedSecret(secret)
	secret.Destroy()

	creds, err := m.GetAuth(context.Background(), "acct")
	if err != nil {
		t.Fatalf("GetAuth after the caller destroyed its own secret: %v", err)
	}
	if creds.Password.Plaintext() == "" {
		t.Fatal("GetAuth returned an empty password")
	}
}
