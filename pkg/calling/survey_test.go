package calling

import (
	"context"
	"testing"
)

func TestNewLogSurveyPublisher_NotNil(t *testing.T) {
	p := NewLogSurveyPublisher(testLogger())
	if p == nil {
		t.Fatal("expected non-nil publisher")
	}
}

func TestNewLogSurveyPublisher_StoresLogger(t *testing.T) {
	logger := testLogger()
	p := NewLogSurveyPublisher(logger)
	if p.logger != logger {
		t.Error("logger not stored correctly")
	}
}

func TestLogSurveyPublisher_Publish_ReturnsNil(t *testing.T) {
	p := NewLogSurveyPublisher(testLogger())
	survey := &CallQualitySurveyMessage{
		ResponseID:    "test-id",
		UserSatisfied: true,
		CallType:      "AUDIO_CALL",
		CallEndReason: "CALLER_HUNG_UP",
	}
	err := p.Publish(context.Background(), survey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLogSurveyPublisher_Publish_AllFields(t *testing.T) {
	p := NewLogSurveyPublisher(testLogger())
	survey := &CallQualitySurveyMessage{
		ResponseID:      "resp-123",
		SubmissionTime:  1710500000000,
		UserSatisfied:   false,
		StartTimestamp:  1710500000000,
		EndTimestamp:    1710500060000,
		CallType:        "VIDEO_CALL",
		Success:         false,
		CallEndReason:   "NETWORK_ERROR",
		QualityIssues:   []string{"audio_choppy", "video_frozen"},
		AdditionalNotes: "Very poor quality",
		DebugLogURL:     "https://debug.signal.org/abc",
		ClientPlatform:  "android",
		ClientVersion:   "5.0.0",
		RemoteAddr:      "192.168.1.1",
	}
	err := p.Publish(context.Background(), survey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
