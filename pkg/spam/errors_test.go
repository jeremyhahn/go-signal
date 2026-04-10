package spam

import (
	"strings"
	"testing"
)

func TestSpamBlockedError_Error(t *testing.T) {
	err := &SpamBlockedError{Reason: "rate limit exceeded"}
	msg := err.Error()
	if !strings.Contains(msg, "spam blocked") {
		t.Errorf("expected 'spam blocked' in error message, got: %q", msg)
	}
	if !strings.Contains(msg, "rate limit exceeded") {
		t.Errorf("expected reason in error message, got: %q", msg)
	}
}

func TestSpamBlockedError_EmptyReason(t *testing.T) {
	err := &SpamBlockedError{}
	msg := err.Error()
	if !strings.Contains(msg, "spam blocked") {
		t.Errorf("expected 'spam blocked' in error message with empty reason, got: %q", msg)
	}
}

func TestSpamChallengeRequiredError_Error(t *testing.T) {
	err := &SpamChallengeRequiredError{ChallengeType: "captcha"}
	msg := err.Error()
	if !strings.Contains(msg, "spam challenge required") {
		t.Errorf("expected 'spam challenge required' in error message, got: %q", msg)
	}
	if !strings.Contains(msg, "captcha") {
		t.Errorf("expected challenge type in error message, got: %q", msg)
	}
}

func TestSpamChallengeRequiredError_PushType(t *testing.T) {
	err := &SpamChallengeRequiredError{ChallengeType: "push"}
	msg := err.Error()
	if !strings.Contains(msg, "push") {
		t.Errorf("expected 'push' in error message, got: %q", msg)
	}
}
