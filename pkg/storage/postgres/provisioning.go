package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/jeremyhahn/go-signal/pkg/devices"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Compile-time interface satisfaction check.
var _ devices.ProvisioningStore = (*ProvisioningStore)(nil)

// ProvisioningStore is a Postgres-backed implementation of
// devices.ProvisioningStore. Sessions are keyed by verification code,
// matching the schema: provisioning_sessions(code TEXT PK, account_uuid UUID,
// expires_at TIMESTAMPTZ).
type ProvisioningStore struct {
	q Querier
}

// NewProvisioningStore constructs a ProvisioningStore backed by the given
// Querier.
func NewProvisioningStore(q Querier) *ProvisioningStore {
	return &ProvisioningStore{q: q}
}

// StoreSession persists a provisioning session. It overwrites any existing
// session stored under the same code (INSERT … ON CONFLICT DO UPDATE),
// matching the qrdb implementation's "store replaces" semantics: the caller
// that generated the code owns the namespace and re-issuing a code for the
// same linking attempt is safe.
func (s *ProvisioningStore) StoreSession(ctx context.Context, session *devices.ProvisioningSession) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres provisioning: nil session")
	}
	if session.Code == "" {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres provisioning: empty code")
	}

	_, err := s.q.Exec(ctx, `
		INSERT INTO provisioning_sessions (code, account_uuid, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (code) DO UPDATE
			SET account_uuid = EXCLUDED.account_uuid,
			    expires_at   = EXCLUDED.expires_at`,
		session.Code,
		session.UUID,
		session.ExpiresAt,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres provisioning: upsert", err)
	}
	return nil
}

// GetSession retrieves a provisioning session by verification code. Returns
// *devices.InvalidProvisioningCodeError when the code is absent.
func (s *ProvisioningStore) GetSession(ctx context.Context, code string) (*devices.ProvisioningSession, error) {
	var sess devices.ProvisioningSession
	sess.Code = code

	err := s.q.QueryRow(ctx, `
		SELECT account_uuid, expires_at
		FROM provisioning_sessions
		WHERE code = $1`,
		code,
	).Scan(&sess.UUID, &sess.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &devices.InvalidProvisioningCodeError{Code: code}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres provisioning: get", err)
	}
	return &sess, nil
}

// DeleteSession removes a provisioning session by code. The operation is
// idempotent: deleting a missing session returns nil.
func (s *ProvisioningStore) DeleteSession(ctx context.Context, code string) error {
	_, err := s.q.Exec(ctx, `
		DELETE FROM provisioning_sessions WHERE code = $1`,
		code,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres provisioning: delete", err)
	}
	return nil
}
