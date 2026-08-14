package common

import (
	"context"
	"errors"
	"testing"
	"time"
)

type retryableError struct{ msg string }

func (r *retryableError) Error() string   { return r.msg }
func (r *retryableError) Retryable() bool { return true }

type permanentError struct{ msg string }

func (p *permanentError) Error() string   { return p.msg }
func (p *permanentError) Retryable() bool { return false }

func TestWithRetry_SucceedsOnFirstAttempt(t *testing.T) {
	calls := 0
	got, err := WithRetry(context.Background(), RetryConfig{InitialBackoff: time.Millisecond}, func(_ context.Context) (int, error) {
		calls++
		return 42, nil
	})
	if err != nil {
		t.Fatalf("WithRetry: %v", err)
	}
	if got != 42 {
		t.Errorf("got = %d", got)
	}
	if calls != 1 {
		t.Errorf("calls = %d", calls)
	}
}

func TestWithRetry_RetriesOnRetryableError(t *testing.T) {
	calls := 0
	cfg := RetryConfig{MaxAttempts: 4, InitialBackoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond}
	got, err := WithRetry(context.Background(), cfg, func(_ context.Context) (string, error) {
		calls++
		if calls < 3 {
			return "", &retryableError{msg: "transient"}
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("WithRetry: %v", err)
	}
	if got != "ok" {
		t.Errorf("got = %q", got)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestWithRetry_StopsOnPermanentError(t *testing.T) {
	calls := 0
	_, err := WithRetry(context.Background(), RetryConfig{MaxAttempts: 5, InitialBackoff: time.Millisecond}, func(_ context.Context) (int, error) {
		calls++
		return 0, &permanentError{msg: "fatal"}
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("permanent error should not retry; calls = %d", calls)
	}
}

func TestWithRetry_ExhaustsAttempts(t *testing.T) {
	calls := 0
	_, err := WithRetry(context.Background(), RetryConfig{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond}, func(_ context.Context) (int, error) {
		calls++
		return 0, &retryableError{msg: "still failing"}
	})
	if err == nil {
		t.Fatal("expected exhaustion error")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestWithRetry_AbortsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	calls := 0
	_, err := WithRetry(ctx, RetryConfig{MaxAttempts: 10, InitialBackoff: 100 * time.Millisecond, MaxBackoff: time.Second}, func(_ context.Context) (int, error) {
		calls++
		return 0, &retryableError{msg: "slow"}
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
	if calls > 2 {
		t.Errorf("calls = %d; should have been aborted earlier", calls)
	}
}

func TestIsRetryable(t *testing.T) {
	if !IsRetryable(&retryableError{}) {
		t.Error("retryableError should be retryable")
	}
	if IsRetryable(&permanentError{}) {
		t.Error("permanentError should not be retryable")
	}
	if IsRetryable(errors.New("plain")) {
		t.Error("plain errors are not retryable")
	}
}
