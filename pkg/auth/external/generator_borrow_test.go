package external

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestValidate_HoldsOneBorrowAtATime arms go-qrdb's nested-borrow guard around
// Validate. v0.46 rejects any secure-package call from inside a WithBytes
// callback, and opening the generator key to recompute the HMAC from inside the
// credential's own borrow is exactly that.
func TestValidate_HoldsOneBorrowAtATime(t *testing.T) {
	defer secure.GuardBorrows(t.Fatalf)()

	now := time.Unix(1_700_000_000, 0)
	for name, prepend := range map[string]bool{"timestamp only": false, "prepended username": true} {
		t.Run(name, func(t *testing.T) {
			g, err := NewGenerator(t.Context(), GeneratorConfig{
				Key:             secrets.MustNewSecureString(t.Context(), "secret"),
				Clock:           fixedClock(now),
				PrependUsername: prepend,
			})
			if err != nil {
				t.Fatalf("NewGenerator: %v", err)
			}
			creds, err := g.Generate(t.Context(), "attachments/abc")
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			defer creds.Destroy()

			issued, err := g.Validate(t.Context(), creds, 5*time.Minute)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !issued.Equal(now) {
				t.Errorf("issued = %v, want %v", issued, now)
			}
		})
	}
}
