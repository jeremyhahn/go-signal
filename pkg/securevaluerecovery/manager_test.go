package securevaluerecovery

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

func TestNewSVRManager_NotNil(t *testing.T) {
	m := NewSVRManager(testLogger())
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewSVRManager_StoresLogger(t *testing.T) {
	logger := testLogger()
	m := NewSVRManager(logger)
	if m.logger != logger {
		t.Error("logger not stored correctly")
	}
}

func TestGetAuth_ReturnsCredentials(t *testing.T) {
	m := NewSVRManager(testLogger())
	creds, err := m.GetAuth(context.Background(), "user-uuid-1", "backup")
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

func TestGetAuth_UniquePasswords(t *testing.T) {
	m := NewSVRManager(testLogger())
	creds1, err := m.GetAuth(context.Background(), "user-1", "svr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds2, err := m.GetAuth(context.Background(), "user-1", "svr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds1.Password == creds2.Password {
		t.Error("expected unique passwords for each call")
	}
}

func TestGetAuth_PreservesAccountUUID(t *testing.T) {
	m := NewSVRManager(testLogger())
	tests := []struct {
		uuid string
		name string
	}{
		{"abc-123", "backup"},
		{"def-456", "svr"},
		{"", "backup"},
	}
	for _, tt := range tests {
		creds, err := m.GetAuth(context.Background(), tt.uuid, tt.name)
		if err != nil {
			t.Fatalf("unexpected error for uuid %q name %q: %v", tt.uuid, tt.name, err)
		}
		if creds.Username != tt.uuid {
			t.Errorf("got username %q, want %q", creds.Username, tt.uuid)
		}
	}
}

func TestGetAuth_CancelledContext(t *testing.T) {
	m := NewSVRManager(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	creds, err := m.GetAuth(ctx, "user-1", "backup")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Username != "user-1" {
		t.Errorf("got username %q, want %q", creds.Username, "user-1")
	}
}

func TestCheckAuth_AllPasswordsNoMatch(t *testing.T) {
	m := NewSVRManager(testLogger())
	passwords := []string{"pass1", "pass2", "pass3"}
	resp, err := m.CheckAuth(context.Background(), "user-1", "backup", passwords)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Matches) != 3 {
		t.Fatalf("got %d matches, want 3", len(resp.Matches))
	}
	for _, pw := range passwords {
		v, ok := resp.Matches[pw]
		if !ok {
			t.Errorf("missing match for password %q", pw)
			continue
		}
		if v != "no-match" {
			t.Errorf("got match %q for %q, want %q", v, pw, "no-match")
		}
	}
}

func TestCheckAuth_EmptyPasswords(t *testing.T) {
	m := NewSVRManager(testLogger())
	resp, err := m.CheckAuth(context.Background(), "user-1", "backup", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Matches) != 0 {
		t.Errorf("got %d matches, want 0", len(resp.Matches))
	}
}

func TestCheckAuth_NilPasswords(t *testing.T) {
	m := NewSVRManager(testLogger())
	resp, err := m.CheckAuth(context.Background(), "user-1", "backup", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Matches) != 0 {
		t.Errorf("got %d matches, want 0", len(resp.Matches))
	}
}

func TestCheckAuth_SinglePassword(t *testing.T) {
	m := NewSVRManager(testLogger())
	resp, err := m.CheckAuth(context.Background(), "user-1", "svr", []string{"only-one"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(resp.Matches))
	}
	if resp.Matches["only-one"] != "no-match" {
		t.Errorf("got %q, want %q", resp.Matches["only-one"], "no-match")
	}
}

func TestCheckAuth_CancelledContext(t *testing.T) {
	m := NewSVRManager(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := m.CheckAuth(ctx, "user-1", "backup", []string{"pw"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(resp.Matches))
	}
}
