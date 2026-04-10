package directory

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
	if creds.Password == "" {
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
	if creds1.Password == creds2.Password {
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

func TestGetAuthToken_CancelledContext(t *testing.T) {
	m := NewDirectoryManager(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	creds, err := m.GetAuthToken(ctx, "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Username != "user-1" {
		t.Errorf("got username %q, want %q", creds.Username, "user-1")
	}
}
