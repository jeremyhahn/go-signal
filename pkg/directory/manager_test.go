package directory

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestNewDirectoryManager_NotNil(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewDirectoryManager_StoresLogger(t *testing.T) {
	logger := testLogger()
	m := NewDirectoryManager(logger)
	if m.logger != logger {
		t.Error("logger not stored correctly")
	}
}

func TestGetAuthToken_ReturnsCredentials(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	creds, err := m.GetAuthToken(context.Background(), "user-uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Username != "user-uuid-1" {
		t.Errorf("got username %q, want %q", creds.Username, "user-uuid-1")
	}
	if creds.Password.Plaintext(t.Context()) == "" {
		t.Fatal("expected non-empty password")
	}
}

func TestGetAuthToken_UniquePasswords(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	creds1, err := m.GetAuthToken(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds2, err := m.GetAuthToken(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds1.Password.Plaintext(t.Context()) == creds2.Password.Plaintext(t.Context()) {
		t.Error("expected unique passwords for each call")
	}
}

func TestGetAuthToken_PreservesAccountUUID(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	tests := []string{"abc-123", "def-456", ""}
	for _, uuid := range tests {
		creds, err := m.GetAuthToken(context.Background(), uuid)
		if err != nil {
			t.Fatalf("unexpected error for uuid %q: %v", uuid, err)
		}
		if creds.Username != uuid {
			t.Errorf("got username %q, want %q", creds.Username, uuid)
		}
	}
}

// Sealing the issued password runs under the caller's context, so a caller
// that has already given up gets an error, not a credential.
func TestGetAuthToken_CancelledContext(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	creds, err := m.GetAuthToken(ctx, "user-1")
	if err == nil {
		t.Fatal("expected a cancelled context to fail issuance")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want it to wrap context.Canceled", err)
	}
	if creds != nil {
		t.Error("a failed issuance must not return a credential")
	}
}

func TestSetSharedSecret_EmptyStringClearsSecret(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), ""))
	if m.state.Load().secret != nil {
		t.Error("expected nil sharedSecret after empty string")
	}
}

func TestSetSharedSecret_NonEmptyStoresSecret(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "my-secret"))
	if m.state.Load().secret.Plaintext(t.Context()) != "my-secret" {
		t.Errorf("expected sharedSecret %q, got %q", "my-secret", m.state.Load().secret.Plaintext(t.Context()))
	}
}

func TestSetSharedSecret_ResetToEmpty(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "first-secret"))
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), ""))
	if m.state.Load().secret != nil {
		t.Error("expected nil sharedSecret after reset with empty string")
	}
}

func TestSetSharedSecret_OverwriteExisting(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "first"))
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "second"))
	if m.state.Load().secret.Plaintext(t.Context()) != "second" {
		t.Errorf("expected sharedSecret %q, got %q", "second", m.state.Load().secret.Plaintext(t.Context()))
	}
}

func TestGetAuthToken_WithSharedSecret_IsDeterministic(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "deterministic-secret"))
	creds1, err := m.GetAuthToken(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds2, err := m.GetAuthToken(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds1.Password.Plaintext(t.Context()) != creds2.Password.Plaintext(t.Context()) {
		t.Error("HMAC password must be deterministic for the same input")
	}
}

func TestGetAuthToken_WithSharedSecret_DifferentUUIDs(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "deterministic-secret"))
	creds1, err := m.GetAuthToken(context.Background(), "uuid-one")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds2, err := m.GetAuthToken(context.Background(), "uuid-two")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds1.Password.Plaintext(t.Context()) == creds2.Password.Plaintext(t.Context()) {
		t.Error("different UUIDs must produce different HMAC passwords")
	}
}

func TestGetAuthToken_WithSharedSecret_UsernameIsAccountUUID(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "any-secret"))
	const accountUUID = "account-uuid-123"
	creds, err := m.GetAuthToken(context.Background(), accountUUID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Username != accountUUID {
		t.Errorf("expected username %q, got %q", accountUUID, creds.Username)
	}
}

func TestGetAuthToken_WithSharedSecret_PasswordIsHexHMAC(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "any-secret"))
	creds, err := m.GetAuthToken(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// HMAC-SHA256 is 32 bytes → 64 hex characters.
	if len(creds.Password.Plaintext(t.Context())) != 64 {
		t.Errorf("expected 64-char hex password, got len %d: %q", len(creds.Password.Plaintext(t.Context())), creds.Password.Plaintext(t.Context()))
	}
}

func TestGetAuthToken_WithSharedSecret_DiffersFromStubMode(t *testing.T) {
	mStub := NewDirectoryManager(testLogger())
	mHMAC := NewDirectoryManager(testLogger())
	_ = mHMAC.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), "test-secret"))

	const uuid = "shared-uuid"
	credsStub, _ := mStub.GetAuthToken(context.Background(), uuid)
	credsHMAC, _ := mHMAC.GetAuthToken(context.Background(), uuid)
	// Stub mode returns a random UUID (36 chars); HMAC mode returns 64 hex chars.
	if len(credsHMAC.Password.Plaintext(t.Context())) != 64 {
		t.Errorf("HMAC password length = %d, want 64", len(credsHMAC.Password.Plaintext(t.Context())))
	}
	if len(credsStub.Password.Plaintext(t.Context())) == 64 {
		t.Error("stub password should not be 64 chars (random UUID is 36)")
	}
}

func TestGetAuthToken_TableDriven_WithAndWithoutSecret(t *testing.T) {
	cases := []struct {
		name           string
		secret         string
		uuid           string
		wantPassLen    int
		wantPassLenMsg string
	}{
		{"no-secret", "", "u1", 36, "random UUID is 36 chars"},
		{"with-secret", "s3cr3t", "u1", 64, "HMAC-SHA256 hex is 64 chars"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewDirectoryManager(testLogger())
			if tc.secret != "" {
				_ = m.SetSharedSecret(t.Context(), secrets.MustNewSecureString(t.Context(), tc.secret))
			}
			creds, err := m.GetAuthToken(context.Background(), tc.uuid)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if creds.Username != tc.uuid {
				t.Errorf("username = %q, want %q", creds.Username, tc.uuid)
			}
			if len(creds.Password.Plaintext(t.Context())) != tc.wantPassLen {
				t.Errorf("password len = %d, want %d (%s): %q",
					len(creds.Password.Plaintext(t.Context())), tc.wantPassLen, tc.wantPassLenMsg, creds.Password.Plaintext(t.Context()))
			}
		})
	}
}
