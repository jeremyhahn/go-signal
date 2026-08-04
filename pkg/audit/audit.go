// Package audit is the structured audit-event sink for sensitive
// operations. Every operation Java Signal-Server flags as
// account-level-mutating (ChangeNumber, DeleteAccount, LinkDevice,
// SetRegistrationLock) emits an Event through a *Logger; production
// deployments wire the *Logger to a dedicated sink (separate log
// stream, append-only Postgres table, or external SIEM) so audit
// records survive log-rotation policies that may discard regular
// application logs.
//
// Event emission is non-blocking-by-default: events are written via
// slog.Handler.Handle which copies the attributes into the handler's
// buffer immediately. If the sink is slow, the slog handler's own
// buffering / dropping policy applies — never extend the request hot
// path past the handler call.
package audit

import (
	"context"
	"log/slog"
	"time"
)

// Outcome is the success/failure label on an audit Event.
type Outcome string

const (
	// OutcomeSuccess marks an operation that completed successfully.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure marks an operation that was authorized but failed
	// during execution. Distinguish from OutcomeDenied which means the
	// caller wasn't allowed to attempt the operation.
	OutcomeFailure Outcome = "failure"
	// OutcomeDenied marks an authorization rejection — used for
	// attempted ChangeNumber / DeleteAccount without proper auth.
	OutcomeDenied Outcome = "denied"
)

// Action identifies the sensitive operation. Add new constants here
// as additional handlers wire audit emission.
type Action string

const (
	ActionChangeNumber        Action = "ChangeNumber"
	ActionDeleteAccount       Action = "DeleteAccount"
	ActionLinkDevice          Action = "LinkDevice"
	ActionUnlinkDevice        Action = "UnlinkDevice"
	ActionSetRegistrationLock Action = "SetRegistrationLock"
)

// Event is one audit record. Fields land as slog attributes so
// structured-log queries can filter on any of them.
type Event struct {
	// At is the timestamp the event was emitted. Zero means the
	// Logger fills it with the current UTC time.
	At time.Time
	// Action is the operation classifier (see ActionXxx constants).
	Action Action
	// Outcome is success / failure / denied.
	Outcome Outcome
	// Actor is the principal performing the action — typically the
	// authenticated account UUID. Empty for unauthenticated calls
	// (denied actions in particular).
	Actor string
	// Target is the principal the action affects. For most actions
	// this equals Actor; admin operations (e.g., a future
	// AdminDeleteAccount) target a different account.
	Target string
	// SourceIP records the inbound IP for audit-trail reconstruction.
	SourceIP string
	// UserAgent records the client's User-Agent.
	UserAgent string
	// RequestID, when present, ties the audit event back to the
	// structured-log request entries via the same trace correlation.
	RequestID string
	// Details holds operation-specific context (e.g., old/new number
	// hashes for ChangeNumber). Values must be safe to log — no raw
	// secrets, no PINs, no profile keys.
	Details map[string]any
}

// Logger emits audit Events through an slog handler.
type Logger struct {
	out *slog.Logger
}

// New constructs a Logger that emits events via the supplied
// *slog.Logger. Pass slog.Default() to ride along with the
// application logs; pass a dedicated handler for an isolated audit
// sink.
func New(out *slog.Logger) *Logger {
	if out == nil {
		out = slog.Default()
	}
	return &Logger{out: out}
}

// Emit writes ev. Always non-blocking past the slog handler — the
// caller never waits on storage. Returns the Event with At filled in
// so callers can attach the same record to a metrics tag.
func (l *Logger) Emit(ctx context.Context, ev Event) Event {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	attrs := []slog.Attr{
		slog.Time("at", ev.At),
		slog.String("action", string(ev.Action)),
		slog.String("outcome", string(ev.Outcome)),
	}
	if ev.Actor != "" {
		attrs = append(attrs, slog.String("actor", ev.Actor))
	}
	if ev.Target != "" {
		attrs = append(attrs, slog.String("target", ev.Target))
	}
	if ev.SourceIP != "" {
		attrs = append(attrs, slog.String("sourceIP", ev.SourceIP))
	}
	if ev.UserAgent != "" {
		attrs = append(attrs, slog.String("userAgent", ev.UserAgent))
	}
	if ev.RequestID != "" {
		attrs = append(attrs, slog.String("requestID", ev.RequestID))
	}
	for k, v := range ev.Details {
		attrs = append(attrs, slog.Any("details."+k, v))
	}
	l.out.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
	return ev
}

// Success is the common-case helper for a successful sensitive
// operation.
func (l *Logger) Success(ctx context.Context, action Action, actor string, details map[string]any) {
	l.Emit(ctx, Event{Action: action, Outcome: OutcomeSuccess, Actor: actor, Target: actor, Details: details})
}

// Failure emits an outcome="failure" event for an operation that the
// caller was authorized to attempt but that did not complete.
func (l *Logger) Failure(ctx context.Context, action Action, actor string, details map[string]any) {
	l.Emit(ctx, Event{Action: action, Outcome: OutcomeFailure, Actor: actor, Target: actor, Details: details})
}

// Denied emits an outcome="denied" event for an unauthenticated /
// unauthorized attempt. Actor may be empty.
func (l *Logger) Denied(ctx context.Context, action Action, actor string, details map[string]any) {
	l.Emit(ctx, Event{Action: action, Outcome: OutcomeDenied, Actor: actor, Details: details})
}
