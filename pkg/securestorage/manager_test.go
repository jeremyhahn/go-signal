package securestorage

import (
	"context"
	"log/slog"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestNewSecureStorageManager_NotNil(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewSecureStorageManager_StoresLogger(t *testing.T) {
	logger := testLogger()
	m := NewSecureStorageManager(logger)
	if m.logger != logger {
		t.Error("logger not stored correctly")
	}
}

func TestGetAuth_ReturnsCredentials(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	creds, err := m.GetAuth(context.Background(), "user-uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Username != "user-uuid-1" {
		t.Errorf("got username %q, want %q", creds.Username, "user-uuid-1")
	}
	if creds.Password.Plaintext() == "" {
		t.Fatal("expected non-empty password")
	}
}

func TestGetAuth_UniquePasswords(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	creds1, err := m.GetAuth(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds2, err := m.GetAuth(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds1.Password.Plaintext() == creds2.Password.Plaintext() {
		t.Error("expected unique passwords for each call")
	}
}

func TestGetAuth_PreservesAccountUUID(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	tests := []string{"abc-123", "def-456", ""}
	for _, uuid := range tests {
		creds, err := m.GetAuth(context.Background(), uuid)
		if err != nil {
			t.Fatalf("unexpected error for uuid %q: %v", uuid, err)
		}
		if creds.Username != uuid {
			t.Errorf("got username %q, want %q", creds.Username, uuid)
		}
	}
}

func TestGetAuth_CancelledContext(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	creds, err := m.GetAuth(ctx, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Username != "user-1" {
		t.Errorf("got username %q, want %q", creds.Username, "user-1")
	}
}
