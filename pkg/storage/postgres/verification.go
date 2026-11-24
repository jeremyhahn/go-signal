package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// Compile-time interface satisfaction check.
var _ verification.VerificationSessionStore = (*VerificationSessionStore)(nil)

// VerificationSessionStore implements verification.VerificationSessionStore in Postgres; Code is never persisted (json:"-").
type VerificationSessionStore struct {
	q Querier
}

// NewVerificationSessionStore constructs a VerificationSessionStore backed by
// the given Querier.
func NewVerificationSessionStore(q Querier) *VerificationSessionStore {
	return &VerificationSessionStore{q: q}
}

// Create stores a new session; an existing ID is an error.
func (s *VerificationSessionStore) Create(ctx context.Context, session *verification.VerificationSession) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres verification: nil session")
	}
	if session.ID == "" {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres verification: empty session ID")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: marshal", err)
	}

	_, err = s.q.Exec(ctx, `
		INSERT INTO verification_sessions (id, data, expires_at, created_at)
		VALUES ($1, $2, $3, NOW())`,
		session.ID,
		data,
		session.ExpiresAt,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return signalerrors.New(signalerrors.ErrAlreadyExists, "postgres verification: session already exists: "+session.ID)
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: insert", err)
	}
	return nil
}

// Get retrieves a verification session by ID. Returns
// *verification.SessionNotFoundError when the session is absent.
func (s *VerificationSessionStore) Get(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	var raw []byte
	err := s.q.QueryRow(ctx, `
		SELECT data FROM verification_sessions WHERE id = $1`,
		sessionID,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &verification.SessionNotFoundError{SessionID: sessionID}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: get", err)
	}

	var sess verification.VerificationSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: unmarshal", err)
	}
	return &sess, nil
}

// Update replaces an existing verification session's data and expires_at.
// Returns *verification.SessionNotFoundError when no session with that ID
// exists.
func (s *VerificationSessionStore) Update(ctx context.Context, session *verification.VerificationSession) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres verification: nil session")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: marshal", err)
	}

	tag, err := s.q.Exec(ctx, `
		UPDATE verification_sessions
		SET data       = $2,
		    expires_at = $3
		WHERE id = $1`,
		session.ID,
		data,
		session.ExpiresAt,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: update", err)
	}
	if tag.RowsAffected() == 0 {
		return &verification.SessionNotFoundError{SessionID: session.ID}
	}
	return nil
}

// Delete removes a verification session by ID. Returns
// *verification.SessionNotFoundError when no session with that ID exists,
// matching the qrdb implementation's behavior.
func (s *VerificationSessionStore) Delete(ctx context.Context, sessionID string) error {
	tag, err := s.q.Exec(ctx, `
		DELETE FROM verification_sessions WHERE id = $1`,
		sessionID,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: delete", err)
	}
	if tag.RowsAffected() == 0 {
		return &verification.SessionNotFoundError{SessionID: sessionID}
	}
	return nil
}

// Count returns the number of verification sessions currently in the store.
func (s *VerificationSessionStore) Count(ctx context.Context) (int, error) {
	var n int
	if err := s.q.QueryRow(ctx, `SELECT COUNT(*) FROM verification_sessions`).Scan(&n); err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: count", err)
	}
	return n, nil
}

// DeleteExpired removes sessions past expires_at in one statement.
func (s *VerificationSessionStore) DeleteExpired(ctx context.Context) error {
	_, err := s.q.Exec(ctx, `
		DELETE FROM verification_sessions WHERE expires_at < NOW()`)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres verification: delete expired", err)
	}
	return nil
}
