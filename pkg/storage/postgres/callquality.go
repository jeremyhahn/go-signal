package postgres

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/jeremyhahn/go-signal/pkg/calling"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// CallQualitySurveyPublisher persists call-quality survey rows to the
// Postgres `call_quality_surveys` table. Mirrors Java Signal-Server's
// behavior: call-quality is the one table that lives in Postgres even when
// the rest of the deployment uses DynamoDB, because the analytics pipeline
// reads it directly via SQL.
//
// Implements calling.SurveyPublisher. Duplicate response_ids (idempotent
// retries from a misbehaving client) are silently absorbed via ON CONFLICT
// DO NOTHING — the first submission wins.
type CallQualitySurveyPublisher struct {
	q Querier
}

// Compile-time interface satisfaction check.
var _ calling.SurveyPublisher = (*CallQualitySurveyPublisher)(nil)

// NewCallQualitySurveyPublisher returns a publisher backed by c.
func NewCallQualitySurveyPublisher(c *Client) *CallQualitySurveyPublisher {
	return &CallQualitySurveyPublisher{q: c.Pool()}
}

// Publish inserts the supplied survey into call_quality_surveys. A nil
// survey is rejected with an InvalidArgument error so a buggy caller is
// surfaced rather than silently swallowed. The numeric timestamps on the
// CallQualitySurveyMessage are interpreted as Unix milliseconds (Java
// parity); we convert to TIMESTAMPTZ before insert.
func (p *CallQualitySurveyPublisher) Publish(ctx context.Context, survey *calling.CallQualitySurveyMessage) error {
	if survey == nil {
		return errors.New("postgres: nil survey")
	}
	if strings.TrimSpace(survey.ResponseID) == "" {
		return errors.New("postgres: survey ResponseID is required")
	}
	issues := survey.QualityIssues
	if issues == nil {
		issues = []string{}
	}
	const stmt = `
		INSERT INTO call_quality_surveys (
			response_id, submission_timestamp, user_satisfied,
			start_timestamp, end_timestamp, call_type, success,
			call_end_reason, quality_issues, additional_notes,
			debug_log_url, client_platform, client_version, remote_addr
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (response_id) DO NOTHING`
	_, err := p.q.Exec(ctx, stmt,
		survey.ResponseID,
		msToTime(survey.SubmissionTime),
		survey.UserSatisfied,
		msToTime(survey.StartTimestamp),
		msToTime(survey.EndTimestamp),
		survey.CallType,
		survey.Success,
		survey.CallEndReason,
		issues,
		survey.AdditionalNotes,
		survey.DebugLogURL,
		survey.ClientPlatform,
		survey.ClientVersion,
		survey.RemoteAddr,
	)
	if err != nil {
		// pgconn errors keep more useful diagnostics than the wrapping
		// pgx ones; surface them so the caller's log includes the SQLSTATE.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: insert call_quality_survey: "+pgErr.Code, err)
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: insert call_quality_survey", err)
	}
	return nil
}

// msToTime decodes a Unix-milliseconds timestamp into time.Time. Zero
// values map to the Unix epoch — preserved verbatim so the analytics
// pipeline can spot missing-timestamp rows.
func msToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond))
}

// keepPGXImport keeps the pgx package live; QueryRow / Exec types come
// from the Querier interface but pgx is the canonical implementation.
var _ pgx.Tx = nil
