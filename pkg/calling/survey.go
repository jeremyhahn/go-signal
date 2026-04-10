package calling

import (
	"context"
	"log/slog"
)

// SurveyPublisher abstracts publishing of call quality survey data. This
// interface enables pluggable backends (logging for dev, Pub/Sub for production).
type SurveyPublisher interface {
	Publish(ctx context.Context, survey *CallQualitySurveyMessage) error
}

// LogSurveyPublisher logs survey data to slog for development and testing.
type LogSurveyPublisher struct {
	logger *slog.Logger
}

// NewLogSurveyPublisher creates a new LogSurveyPublisher.
func NewLogSurveyPublisher(logger *slog.Logger) *LogSurveyPublisher {
	return &LogSurveyPublisher{logger: logger}
}

// Publish logs the survey data at info level.
func (p *LogSurveyPublisher) Publish(ctx context.Context, survey *CallQualitySurveyMessage) error {
	p.logger.InfoContext(ctx, "call quality survey received",
		slog.String("responseId", survey.ResponseID),
		slog.Bool("userSatisfied", survey.UserSatisfied),
		slog.String("callType", survey.CallType),
		slog.Bool("success", survey.Success),
		slog.String("callEndReason", survey.CallEndReason),
		slog.Int64("startTimestamp", survey.StartTimestamp),
		slog.Int64("endTimestamp", survey.EndTimestamp),
		slog.String("clientPlatform", survey.ClientPlatform),
		slog.String("clientVersion", survey.ClientVersion),
	)
	return nil
}
