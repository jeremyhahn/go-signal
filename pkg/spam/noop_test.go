package spam

import (
	"context"
	"testing"
	"time"
)

func TestNoOpChecker_AlwaysAllows(t *testing.T) {
	checker := &NoOpChecker{}
	checkCtx := &CheckContext{
		SenderUUID:    "sender-uuid",
		RecipientUUID: "recipient-uuid",
		SenderIP:      "127.0.0.1",
		UserAgent:     "Signal-Android/1.0",
		MessageType:   1,
		Timestamp:     time.Now(),
	}

	result, err := checker.Check(context.Background(), checkCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckAllow {
		t.Errorf("expected SpamCheckAllow, got %v", result)
	}
}

func TestNoOpChecker_AllowsWithNilContext(t *testing.T) {
	checker := &NoOpChecker{}
	// Minimal check context — all zero values.
	checkCtx := &CheckContext{}

	result, err := checker.Check(context.Background(), checkCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckAllow {
		t.Errorf("expected SpamCheckAllow, got %v", result)
	}
}

func TestNoOpChecker_ImplementsInterface(t *testing.T) {
	var _ SpamChecker = &NoOpChecker{}
}
