package config

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestPostgresConfig_DSN_URLWins(t *testing.T) {
	cfg := PostgresConfig{
		URL: secrets.NewSecureString("postgres://user:pass@remote:5432/mydb?sslmode=require"),
	}
	got := cfg.DSN()
	want := "postgres://user:pass@remote:5432/mydb?sslmode=require"
	if got != want {
		t.Errorf("DSN() with URL = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_StructFields(t *testing.T) {
	cfg := PostgresConfig{
		Host:     "db.example.com",
		Port:     5432,
		Database: "signaldb",
		User:     "siguser",
		Password: secrets.NewSecureString("s3cr3t"),
		SSLMode:  "require",
	}
	got := cfg.DSN()
	want := "postgres://siguser:s3cr3t@db.example.com:5432/signaldb?sslmode=require"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_DefaultsHostPort(t *testing.T) {
	cfg := PostgresConfig{
		Database: "mydb",
		User:     "admin",
	}
	got := cfg.DSN()
	// Host defaults to "localhost", port to 5432, sslMode to "disable".
	want := "postgres://admin:@localhost:5432/mydb?sslmode=disable"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_DefaultSSLMode(t *testing.T) {
	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "db",
		User:     "u",
	}
	got := cfg.DSN()
	want := "postgres://u:@localhost:5432/db?sslmode=disable"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_NilURLFallsBackToFields(t *testing.T) {
	cfg := PostgresConfig{
		URL:      nil,
		Host:     "pg",
		Port:     5433,
		Database: "testdb",
		User:     "testuser",
		SSLMode:  "verify-full",
	}
	got := cfg.DSN()
	want := "postgres://testuser:@pg:5433/testdb?sslmode=verify-full"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_EmptyURLPlaintextFallsBackToFields(t *testing.T) {
	// A SecureString created from empty string returns "" from Plaintext(),
	// so DSN should fall back to the structured fields.
	cfg := PostgresConfig{
		URL:      secrets.NewSecureString(""),
		Host:     "fallback",
		Port:     5432,
		Database: "fb",
		User:     "fbuser",
		SSLMode:  "disable",
	}
	got := cfg.DSN()
	want := "postgres://fbuser:@fallback:5432/fb?sslmode=disable"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_NilPassword(t *testing.T) {
	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "db",
		User:     "user",
		Password: nil,
		SSLMode:  "disable",
	}
	got := cfg.DSN()
	want := "postgres://user:@localhost:5432/db?sslmode=disable"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_SpecialCharsInPassword(t *testing.T) {
	// url.QueryEscape escapes special characters in passwords.
	cfg := PostgresConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "db",
		User:     "user",
		Password: secrets.NewSecureString("p@ss w0rd!"),
		SSLMode:  "disable",
	}
	got := cfg.DSN()
	// url.QueryEscape("p@ss w0rd!") == "p%40ss+w0rd%21"
	if got == "" {
		t.Fatal("expected non-empty DSN")
	}
	// Must not contain raw unencoded '@' from the password.
	const rawAtInPassword = "p@ss"
	if contains(got[len("postgres://user:"):], rawAtInPassword) {
		t.Errorf("DSN password portion not escaped: %q", got)
	}
}

// contains is a simple substring check to avoid importing strings in the test.
func contains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
