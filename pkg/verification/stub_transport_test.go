package verification

import (
	"context"
	"log/slog"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(noopWriter{}, nil))
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestNewStubTransport_NotNil(t *testing.T) {
	logger := discardLogger()
	transport := NewStubTransport(logger)
	if transport == nil {
		t.Fatal("expected non-nil StubTransport")
	}
}

func TestStubTransport_Name(t *testing.T) {
	transport := NewStubTransport(discardLogger())
	if got := transport.Name(); got != "stub" {
		t.Errorf("Name() = %q, want %q", got, "stub")
	}
}

func TestStubTransport_SendCode_ReturnsNil(t *testing.T) {
	transport := NewStubTransport(discardLogger())
	err := transport.SendCode(context.Background(), "+15551234567", "123456")
	if err != nil {
		t.Errorf("SendCode() = %v, want nil", err)
	}
}

func TestStubTransport_SendCode_WithOptions(t *testing.T) {
	transport := NewStubTransport(discardLogger())
	// SendOption is variadic; passing extras must not panic or error.
	err := transport.SendCode(context.Background(), "+15559999999", "999999", WithCarrier("tmobile"))
	if err != nil {
		t.Errorf("SendCode() with option = %v, want nil", err)
	}
}

func TestStubTransport_ImplementsInterface(t *testing.T) {
	var _ VerificationTransport = (*StubTransport)(nil)
}

// --- redactDestination ---

func TestRedactDestination_ShortNumber(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "****"},
		{"1", "****"},
		{"+123", "****"},
		{"1234", "****"},
	}
	for _, tt := range tests {
		got := redactDestination(tt.input)
		if got != tt.want {
			t.Errorf("redactDestination(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRedactDestination_LongNumber(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"+15551234567", "+155****"},
		{"+447911123456", "+447****"},
		{"12345", "1234****"},
	}
	for _, tt := range tests {
		got := redactDestination(tt.input)
		if got != tt.want {
			t.Errorf("redactDestination(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
