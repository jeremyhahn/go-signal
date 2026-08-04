package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/calling"
)

func TestCallQualitySurveyPublisher_Publish_Validation(t *testing.T) {
	// Validation paths don't touch the database and run on every CI box.
	p := &CallQualitySurveyPublisher{}
	if err := p.Publish(context.Background(), nil); err == nil {
		t.Error("expected error for nil survey")
	}
	if err := p.Publish(context.Background(), &calling.CallQualitySurveyMessage{ResponseID: " \t"}); err == nil {
		t.Error("expected error for blank ResponseID")
	}
}

func TestMsToTime_RoundtripsMilliseconds(t *testing.T) {
	in := int64(1_700_000_000_123) // 2023-11-14 22:13:20.123Z
	got := msToTime(in)
	if got.UnixMilli() != in {
		t.Errorf("msToTime(%d).UnixMilli() = %d", in, got.UnixMilli())
	}
}

func TestCallQualitySurveyPublisher_Publish_HappyPath(t *testing.T) {
	c := newTestClient(t)
	p := NewCallQualitySurveyPublisher(c)
	ctx := context.Background()

	msg := &calling.CallQualitySurveyMessage{
		ResponseID:      "r1",
		SubmissionTime:  1_700_000_000_000,
		UserSatisfied:   true,
		StartTimestamp:  1_700_000_000_000,
		EndTimestamp:    1_700_000_030_000,
		CallType:        "VIDEO",
		Success:         true,
		CallEndReason:   "HANGUP",
		QualityIssues:   []string{"AUDIO_DROPOUTS"},
		AdditionalNotes: "noisy room",
		DebugLogURL:     "https://logs.example/abc",
		ClientPlatform:  "ios",
		ClientVersion:   "7.0.0",
		RemoteAddr:      "203.0.113.1",
	}
	if err := p.Publish(ctx, msg); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Read the row back and verify every column round-trips.
	var (
		responseID    string
		userSatisfied bool
		startTS       time.Time
		callType      string
		callEndReason string
		qualityIssues []string
		clientVersion string
	)
	err := c.Pool().QueryRow(ctx,
		`SELECT response_id, user_satisfied, start_timestamp, call_type,
		        call_end_reason, quality_issues, client_version
		   FROM call_quality_surveys
		  WHERE response_id = $1`, "r1").
		Scan(&responseID, &userSatisfied, &startTS, &callType, &callEndReason, &qualityIssues, &clientVersion)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if responseID != "r1" || !userSatisfied || callType != "VIDEO" || callEndReason != "HANGUP" {
		t.Errorf("row mismatch: id=%q satisfied=%v type=%q reason=%q",
			responseID, userSatisfied, callType, callEndReason)
	}
	if len(qualityIssues) != 1 || qualityIssues[0] != "AUDIO_DROPOUTS" {
		t.Errorf("quality_issues = %+v", qualityIssues)
	}
	if !strings.Contains(clientVersion, "7.0.0") {
		t.Errorf("client_version = %q", clientVersion)
	}
}

func TestCallQualitySurveyPublisher_Publish_IsIdempotentOnDuplicateResponseID(t *testing.T) {
	c := newTestClient(t)
	p := NewCallQualitySurveyPublisher(c)
	ctx := context.Background()

	msg := &calling.CallQualitySurveyMessage{
		ResponseID:     "dup-1",
		SubmissionTime: 1_700_000_000_000,
		StartTimestamp: 1_700_000_000_000,
		EndTimestamp:   1_700_000_030_000,
		CallType:       "VIDEO",
	}
	if err := p.Publish(ctx, msg); err != nil {
		t.Fatalf("Publish 1: %v", err)
	}
	// Second submission with same ResponseID must be absorbed silently,
	// without re-writing the row.
	msg2 := *msg
	msg2.CallType = "AUDIO" // would be a different value if the row were overwritten.
	if err := p.Publish(ctx, &msg2); err != nil {
		t.Fatalf("Publish 2 (duplicate): %v", err)
	}

	var callType string
	if err := c.Pool().QueryRow(ctx,
		`SELECT call_type FROM call_quality_surveys WHERE response_id = $1`, "dup-1").
		Scan(&callType); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if callType != "VIDEO" {
		t.Errorf("duplicate insert overwrote row: call_type = %q, want VIDEO", callType)
	}
}

func TestCallQualitySurveyPublisher_Publish_HandlesEmptyQualityIssues(t *testing.T) {
	c := newTestClient(t)
	p := NewCallQualitySurveyPublisher(c)
	ctx := context.Background()

	// Survey with QualityIssues == nil must persist as an empty array
	// (the column has NOT NULL DEFAULT '{}'), not crash on the scan.
	msg := &calling.CallQualitySurveyMessage{
		ResponseID:     "empty-issues",
		SubmissionTime: 1_700_000_000_000,
		StartTimestamp: 1_700_000_000_000,
		EndTimestamp:   1_700_000_030_000,
		CallType:       "AUDIO",
	}
	if err := p.Publish(ctx, msg); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	var issues []string
	if err := c.Pool().QueryRow(ctx,
		`SELECT quality_issues FROM call_quality_surveys WHERE response_id = $1`, "empty-issues").
		Scan(&issues); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected empty quality_issues, got %+v", issues)
	}
}
