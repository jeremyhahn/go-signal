package config

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestPostgresConfig_DSN_URLWins(t *testing.T) {
	cfg := PostgresConfig{
		URL: secrets.MustNewSecureString(t.Context(), "postgres://user:pass@remote:5432/mydb?sslmode=require"),
	}
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
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
		Password: secrets.MustNewSecureString(t.Context(), "s3cr3t"),
		SSLMode:  "require",
	}
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
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
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
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
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
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
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
	want := "postgres://testuser:@pg:5433/testdb?sslmode=verify-full"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}
}

func TestPostgresConfig_DSN_EmptyURLPlaintextFallsBackToFields(t *testing.T) {
	// A SecureString created from empty string returns "" from Plaintext(),
	// so DSN should fall back to the structured fields.
	cfg := PostgresConfig{
		URL:      secrets.MustNewSecureString(t.Context(), ""),
		Host:     "fallback",
		Port:     5432,
		Database: "fb",
		User:     "fbuser",
		SSLMode:  "disable",
	}
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
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
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
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
		Password: secrets.MustNewSecureString(t.Context(), "p@ss w0rd!"),
		SSLMode:  "disable",
	}
	got, err := cfg.DSN(t.Context())
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
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

// TestPostgresConfig_DSN_UnopenableSecretIsAnError: a configured URL or
// password that cannot be opened must fail the DSN. Falling through to the
// structured fields would connect to a localhost default with TLS disabled, or
// with an empty password, instead of the database the operator configured.
func TestPostgresConfig_DSN_UnopenableSecretIsAnError(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := map[string]struct {
		cfg   PostgresConfig
		field string
	}{
		"url": {
			cfg:   PostgresConfig{URL: secrets.MustNewSecureString(t.Context(), "postgres://u:p@remote:5432/db?sslmode=require")},
			field: "url",
		},
		"password": {
			cfg: PostgresConfig{
				Host: "db", Database: "d", User: "u", SSLMode: "require",
				Password: secrets.MustNewSecureString(t.Context(), "s3cr3t"),
			},
			field: "password",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := tc.cfg.DSN(canceled)
			var dsnErr *PostgresSecretError
			if !errors.As(err, &dsnErr) {
				t.Fatalf("err = %T (%v), want *PostgresSecretError", err, err)
			}
			if dsnErr.Field != tc.field {
				t.Errorf("Field = %q, want %q", dsnErr.Field, tc.field)
			}
			var unavailable *secrets.UnavailableSecretError
			if !errors.As(err, &unavailable) {
				t.Errorf("err = %v, want it to wrap *secrets.UnavailableSecretError", err)
			}
			if got != "" {
				t.Errorf("DSN = %q alongside the error, want empty", got)
			}
		})
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
