package external

import (
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// fixedClock returns a constant Unix timestamp so tests pin signatures
// against a known wall-clock.
func fixedClock(now time.Time) func() time.Time {
	return func() time.Time { return now }
}

func TestNewGenerator_RequiresKey(t *testing.T) {
	if _, err := NewGenerator(GeneratorConfig{}); err == nil {
		t.Fatal("expected error when Key missing")
	}
}

func TestGenerate_ProducesTokenWithoutPrependedUsername(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("secret"), Clock: fixedClock(now)})
	creds, err := g.Generate("attachments/abc")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if creds.Username != "attachments/abc" {
		t.Errorf("Username = %q", creds.Username)
	}
	parts := strings.Split(creds.Password.Plaintext(), ":")
	if len(parts) != 2 {
		t.Fatalf("password must be ts:sig; got %q (%d parts)", creds.Password.Plaintext(), len(parts))
	}
	if parts[0] != "1700000000" {
		t.Errorf("ts = %q, want 1700000000", parts[0])
	}
	if len(parts[1]) != 64 {
		t.Errorf("signature length = %d, want 64 hex chars", len(parts[1]))
	}
}

func TestGenerate_PrependedUsername(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g, _ := NewGenerator(GeneratorConfig{
		Key: []byte("secret"), Clock: fixedClock(now), PrependUsername: true,
	})
	creds, _ := g.Generate("uid")
	parts := strings.Split(creds.Password.Plaintext(), ":")
	if len(parts) != 3 {
		t.Fatalf("password must be id:ts:sig; got %q", creds.Password.Plaintext())
	}
	if parts[0] != "uid" {
		t.Errorf("password[0] = %q, want uid", parts[0])
	}
}

func TestGenerate_RejectsEmptyIdentity(t *testing.T) {
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("k")})
	if _, err := g.Generate(""); err == nil {
		t.Fatal("expected error for empty identity")
	}
}

func TestValidate_HappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("secret"), Clock: fixedClock(now)})
	creds, _ := g.Generate("attachments/abc")
	issued, err := g.Validate(creds, 5*time.Minute)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !issued.Equal(now) {
		t.Errorf("issued = %v, want %v", issued, now)
	}
}

func TestValidate_RejectsExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("k"), Clock: fixedClock(now)})
	creds, _ := g.Generate("uid")
	// Move the clock forward past the window.
	g.cfg.Clock = fixedClock(now.Add(10 * time.Minute))
	if _, err := g.Validate(creds, time.Minute); err == nil {
		t.Fatal("expected expiration error")
	}
}

func TestValidate_RejectsSignatureTamper(t *testing.T) {
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("k"), Clock: fixedClock(time.Unix(1, 0))})
	creds, _ := g.Generate("uid")
	parts := strings.Split(creds.Password.Plaintext(), ":")
	// Flip the last hex char of the signature.
	flipped := parts[0] + ":" + flipLastChar(parts[1])
	bad := &Credentials{Username: creds.Username, Password: secrets.MustNewSecureString(flipped)}
	if _, err := g.Validate(bad, 0); err == nil {
		t.Fatal("expected signature mismatch")
	}
}

func TestValidate_RejectsMalformedPassword(t *testing.T) {
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("k")})
	bad := &Credentials{Username: "u", Password: secrets.MustNewSecureString("no-colon")}
	if _, err := g.Validate(bad, 0); err == nil {
		t.Fatal("expected malformed error")
	}
}

func TestValidate_RejectsNilCredentials(t *testing.T) {
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("k")})
	if _, err := g.Validate(nil, 0); err == nil {
		t.Fatal("expected nil-creds error")
	}
}

func TestValidate_PrependedUsername(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("k"), Clock: fixedClock(now), PrependUsername: true})
	creds, _ := g.Generate("uid")
	if _, err := g.Validate(creds, time.Minute); err != nil {
		t.Fatalf("Validate prepended: %v", err)
	}
	// Wrong username in the password must fail.
	parts := strings.Split(creds.Password.Plaintext(), ":")
	tampered := &Credentials{Username: creds.Username, Password: secrets.MustNewSecureString("other:" + parts[1] + ":" + parts[2])}
	if _, err := g.Validate(tampered, time.Minute); err == nil {
		t.Fatal("expected mismatch error for tampered identity")
	}
}

func flipLastChar(s string) string {
	if s == "" {
		return s
	}
	last := s[len(s)-1]
	flipped := byte('0')
	if last == '0' {
		flipped = '1'
	}
	return s[:len(s)-1] + string([]byte{flipped})
}

func TestNewGenerator_DefaultsClockToNow(t *testing.T) {
	g, err := NewGenerator(GeneratorConfig{Key: []byte("k")})
	if err != nil {
		t.Fatalf("NewGenerator: %v", err)
	}
	creds, err := g.Generate("uid")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Validate against the same generator within a permissive window.
	if _, err := g.Validate(creds, time.Minute); err != nil {
		t.Errorf("default clock round-trip failed: %v", err)
	}
}

// Destroy must wipe the protected password so a credential that has been
// written to a response cannot be recovered from the issuing struct, and it
// must tolerate repeated and nil calls (handlers defer it).
func TestCredentials_Destroy_WipesPassword(t *testing.T) {
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("secret")})
	creds, err := g.Generate("id")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if creds.Password.Plaintext() == "" {
		t.Fatal("expected a non-empty password before Destroy")
	}
	creds.Destroy()
	if got := creds.Password.Plaintext(); got != "" {
		t.Errorf("password survived Destroy: %q", got)
	}
}

func TestCredentials_Destroy_IdempotentAndNilSafe(t *testing.T) {
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("secret")})
	creds, _ := g.Generate("id")
	creds.Destroy()
	creds.Destroy()
	(*Credentials)(nil).Destroy()
}

// A destroyed credential must fail validation rather than passing with an
// empty password.
func TestValidate_RejectsDestroyedCredentials(t *testing.T) {
	g, _ := NewGenerator(GeneratorConfig{Key: []byte("secret")})
	creds, _ := g.Generate("id")
	creds.Destroy()
	if _, err := g.Validate(creds, time.Hour); err == nil {
		t.Error("expected error validating a destroyed credential")
	}
}
