package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newCaptureLogger returns a *Logger that writes JSON events to buf
// so assertions can decode + inspect specific fields.
func newCaptureLogger() (*Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	return New(slog.New(handler)), buf
}

func decodeOne(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("no audit event captured")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("decode: %v (raw=%q)", err, line)
	}
	return got
}

func TestEmit_FillsTimestampWhenZero(t *testing.T) {
	l, buf := newCaptureLogger()
	ev := l.Emit(context.Background(), Event{
		Action:  ActionDeleteAccount,
		Outcome: OutcomeSuccess,
		Actor:   "alice",
	})
	if ev.At.IsZero() {
		t.Error("Emit should fill At")
	}
	got := decodeOne(t, buf)
	if got["action"] != string(ActionDeleteAccount) {
		t.Errorf("action = %v", got["action"])
	}
	if got["outcome"] != string(OutcomeSuccess) {
		t.Errorf("outcome = %v", got["outcome"])
	}
}

func TestEmit_PreservesSuppliedTimestamp(t *testing.T) {
	l, _ := newCaptureLogger()
	at := time.Unix(1_700_000_000, 0).UTC()
	ev := l.Emit(context.Background(), Event{
		At:      at,
		Action:  ActionChangeNumber,
		Outcome: OutcomeSuccess,
	})
	if !ev.At.Equal(at) {
		t.Errorf("At = %v", ev.At)
	}
}

func TestEmit_OmitsEmptyOptionalFields(t *testing.T) {
	l, buf := newCaptureLogger()
	l.Emit(context.Background(), Event{Action: ActionChangeNumber, Outcome: OutcomeSuccess})
	got := decodeOne(t, buf)
	for _, k := range []string{"actor", "target", "sourceIP", "userAgent", "requestID"} {
		if _, present := got[k]; present {
			t.Errorf("empty %q should be omitted", k)
		}
	}
}

func TestEmit_EmitsAllPopulatedFields(t *testing.T) {
	l, buf := newCaptureLogger()
	l.Emit(context.Background(), Event{
		Action:    ActionLinkDevice,
		Outcome:   OutcomeSuccess,
		Actor:     "alice-uuid",
		Target:    "alice-uuid",
		SourceIP:  "10.0.0.1",
		UserAgent: "Signal-iOS/7.0",
		RequestID: "req-abc",
		Details:   map[string]any{"deviceID": float64(2), "deviceName": "iPhone"},
	})
	got := decodeOne(t, buf)
	checks := map[string]any{
		"action":             string(ActionLinkDevice),
		"outcome":            string(OutcomeSuccess),
		"actor":              "alice-uuid",
		"target":             "alice-uuid",
		"sourceIP":           "10.0.0.1",
		"userAgent":          "Signal-iOS/7.0",
		"requestID":          "req-abc",
		"details.deviceID":   float64(2),
		"details.deviceName": "iPhone",
	}
	for k, want := range checks {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
}

func TestSuccess_FailureDenied_OutcomeLabels(t *testing.T) {
	l, buf := newCaptureLogger()
	l.Success(context.Background(), ActionDeleteAccount, "alice", nil)
	l.Failure(context.Background(), ActionChangeNumber, "alice", map[string]any{"reason": "lock"})
	l.Denied(context.Background(), ActionDeleteAccount, "", nil)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 events, got %d", len(lines))
	}
	outcomes := []string{}
	for _, line := range lines {
		var got map[string]any
		_ = json.Unmarshal([]byte(line), &got)
		outcomes = append(outcomes, got["outcome"].(string))
	}
	want := []string{"success", "failure", "denied"}
	for i, w := range want {
		if outcomes[i] != w {
			t.Errorf("event[%d] outcome = %s, want %s", i, outcomes[i], w)
		}
	}
}

func TestNew_NilLoggerUsesDefault(t *testing.T) {
	l := New(nil)
	if l.out == nil {
		t.Error("expected default logger")
	}
}

func TestSuccessHelper_DefaultsTargetToActor(t *testing.T) {
	l, buf := newCaptureLogger()
	l.Success(context.Background(), ActionSetRegistrationLock, "alice", nil)
	got := decodeOne(t, buf)
	if got["target"] != "alice" {
		t.Errorf("target = %v, want alice", got["target"])
	}
}
