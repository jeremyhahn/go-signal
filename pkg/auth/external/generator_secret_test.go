package external

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestGenerate_WireFormUnchangedByProtectedKey pins the credential bytes to
// the plain-[]byte HMAC this generator produced before the key moved into
// protected memory. Any divergence breaks every external service that
// re-derives the signature.
func TestGenerate_WireFormUnchangedByProtectedKey(t *testing.T) {
	const key, identity = "shared-secret", "+15550100"
	now := time.Unix(1700000000, 0)

	g, err := NewGenerator(GeneratorConfig{
		Key:   secrets.MustNewSecureString(key),
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	creds, err := g.Generate(identity)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ts := "1700000000"
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(identity + ":" + ts))
	want := ts + ":" + hex.EncodeToString(mac.Sum(nil))

	if creds.Username != identity {
		t.Errorf("username = %q, want %q", creds.Username, identity)
	}
	if got := creds.Password.Plaintext(); got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
}

func TestGenerate_WireFormUnchangedWithPrependUsername(t *testing.T) {
	const key, identity = "shared-secret", "+15550100"
	now := time.Unix(1700000000, 0)

	g, err := NewGenerator(GeneratorConfig{
		Key:             secrets.MustNewSecureString(key),
		PrependUsername: true,
		Clock:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	creds, err := g.Generate(identity)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	ts := "1700000000"
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(identity + ":" + ts))
	want := identity + ":" + ts + ":" + hex.EncodeToString(mac.Sum(nil))

	if got := creds.Password.Plaintext(); got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
}

func TestNewGenerator_RejectsUnsetAndDestroyedKeys(t *testing.T) {
	destroyed := secrets.MustNewSecureString("k")
	destroyed.Destroy()

	cases := map[string]*secrets.SecureString{
		"nil":       nil,
		"unset":     secrets.MustNewSecureString(""),
		"destroyed": destroyed,
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewGenerator(GeneratorConfig{Key: key}); err == nil {
				t.Error("expected NewGenerator to reject the key")
			}
		})
	}
}

// TestNewGenerator_ClonesTheKey covers the ownership contract: destroying the
// generator must not reach back into the caller's secret, which in signald is
// the process config wiped separately by cfg.Destroy.
func TestNewGenerator_ClonesTheKey(t *testing.T) {
	key := secrets.MustNewSecureString("shared-secret")
	defer key.Destroy()

	g, err := NewGenerator(GeneratorConfig{Key: key})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	g.Destroy()

	if key.IsDestroyed() {
		t.Error("Generator.Destroy wiped the caller's key")
	}
	if got := key.Plaintext(); got != "shared-secret" {
		t.Errorf("caller's key = %q, want %q", got, "shared-secret")
	}
}

// TestGenerator_DestroyingTheCallersKeyLeavesTheGeneratorWorking is the other
// half of the ownership contract — signald calls cfg.Destroy() at shutdown.
func TestGenerator_DestroyingTheCallersKeyLeavesTheGeneratorWorking(t *testing.T) {
	key := secrets.MustNewSecureString("shared-secret")
	g, err := NewGenerator(GeneratorConfig{Key: key, Clock: func() time.Time { return time.Unix(1, 0) }})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	defer g.Destroy()

	key.Destroy()

	creds, err := g.Generate("alice")
	if err != nil {
		t.Fatalf("Generate after the caller destroyed its key: %v", err)
	}
	if _, err := g.Validate(creds, 0); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestGenerator_GenerateFailsClosedAfterDestroy(t *testing.T) {
	g, err := NewGenerator(GeneratorConfig{Key: secrets.MustNewSecureString("k")})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	g.Destroy()

	creds, err := g.Generate("alice")
	if err == nil {
		t.Fatalf("expected an error after Destroy, got credentials %+v", creds)
	}
	if !strings.Contains(err.Error(), "destroyed") {
		t.Errorf("error = %q, want it to name the destroyed generator", err)
	}
}

func TestGenerator_ValidateFailsClosedAfterDestroy(t *testing.T) {
	g, err := NewGenerator(GeneratorConfig{Key: secrets.MustNewSecureString("k")})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	creds, err := g.Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	g.Destroy()

	if _, err := g.Validate(creds, 0); err == nil {
		t.Error("expected Validate to reject a credential once the key is wiped")
	}
}

func TestGenerator_DestroyIsIdempotentAndNilSafe(t *testing.T) {
	var nilGen *Generator
	nilGen.Destroy() // must not panic

	g, err := NewGenerator(GeneratorConfig{Key: secrets.MustNewSecureString("k")})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	g.Destroy()
	g.Destroy()
}

// TestNewGenerator_ConfiguredButUnreadableKeyIsUnusableNotMissing pins the
// distinction the typed errors exist to make.
//
// Clone erases the configured flag: a clone of a configured-but-unreadable
// key is empty and reports IsAbsent() == true, exactly like a clone of an
// unset one. Asking the CLONE therefore answers "no key configured" for a key
// that is installed and merely unreadable — and a caller allowed to fall back
// to an unauthenticated mode on MissingKeyError would downgrade a deployment
// that does have a key.
//
// Reverting the check to ask the clone makes this fail with MissingKeyError.
func TestNewGenerator_ConfiguredButUnreadableKeyIsUnusableNotMissing(t *testing.T) {
	key := secrets.MustNewSecureString("shared-secret")
	key.Destroy() // configured, then unreadable

	_, err := NewGenerator(GeneratorConfig{Key: key})

	var unusable *UnusableKeyError
	if !errors.As(err, &unusable) {
		t.Fatalf("expected *UnusableKeyError, got %#v", err)
	}
	var missing *MissingKeyError
	if errors.As(err, &missing) {
		t.Error("an installed but unreadable key must not be reported as missing")
	}
}

// The genuinely-absent case must still report MissingKeyError, or the fix
// would collapse both facts into the other one.
func TestNewGenerator_AbsentKeyIsMissing(t *testing.T) {
	_, err := NewGenerator(GeneratorConfig{Key: secrets.MustNewSecureString("")})

	var missing *MissingKeyError
	if !errors.As(err, &missing) {
		t.Fatalf("expected *MissingKeyError, got %#v", err)
	}
	var unusable *UnusableKeyError
	if errors.As(err, &unusable) {
		t.Error("an unset key must not be reported as unusable")
	}
}

func TestNewGenerator_NilKeyIsMissing(t *testing.T) {
	_, err := NewGenerator(GeneratorConfig{})

	var missing *MissingKeyError
	if !errors.As(err, &missing) {
		t.Fatalf("expected *MissingKeyError, got %#v", err)
	}
}
