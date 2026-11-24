package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

// Compile-time interface satisfaction check.
var _ recoverypassword.Store = (*RecoveryPasswordStore)(nil)

// RecoveryPasswordStore is a Postgres-backed implementation of
// recoverypassword.Store. Reads are direct against the pool; writes use the
// pool too — every operation is a single statement so transactions add no
// value here.
type RecoveryPasswordStore struct {
	q   Querier
	now func() time.Time
}

// NewRecoveryPasswordStore returns a store backed by c.
func NewRecoveryPasswordStore(c *Client) *RecoveryPasswordStore {
	return &RecoveryPasswordStore{q: c.Pool(), now: time.Now}
}

// SetClock overrides the wall-clock used to evaluate row expiration. Intended
// for tests; production code uses time.Now.
func (s *RecoveryPasswordStore) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// Get returns the row for pni or NotFoundError when no row exists or the
// stored row's expires_at has elapsed. Expired rows are deleted as a side
// effect so subsequent Get calls do not have to repeat the comparison.
func (s *RecoveryPasswordStore) Get(ctx context.Context, pni string) (*recoverypassword.SaltedTokenHash, error) {
	var hash, salt string
	var expiresAt time.Time
	err := s.q.QueryRow(ctx, `
		SELECT hash, salt, expires_at
		FROM registration_recovery_passwords
		WHERE pni = $1`, pni,
	).Scan(&hash, &salt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &recoverypassword.NotFoundError{PNI: pni}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres recoverypassword: get", err)
	}

	if !s.now().Before(expiresAt) {
		if _, delErr := s.q.Exec(ctx, `
			DELETE FROM registration_recovery_passwords
			WHERE pni = $1 AND expires_at = $2`, pni, expiresAt); delErr != nil {
			// Best-effort: logging happens at Manager level; surface the
			// not-found result regardless.
			_ = delErr
		}
		return nil, &recoverypassword.NotFoundError{PNI: pni}
	}

	return &recoverypassword.SaltedTokenHash{Hash: hash, Salt: salt}, nil
}

// Put inserts or replaces the entry for pni. Uses ON CONFLICT (pni) so a
// concurrent re-register flow simply overwrites the previous row in place.
func (s *RecoveryPasswordStore) Put(ctx context.Context, pni string, hash *recoverypassword.SaltedTokenHash, expiresAt time.Time) error {
	if hash == nil {
		return &recoverypassword.InvalidArgumentError{Field: "hash", Message: "must not be nil"}
	}

	_, err := s.q.Exec(ctx, `
		INSERT INTO registration_recovery_passwords (pni, hash, salt, expires_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (pni) DO UPDATE
			SET hash       = EXCLUDED.hash,
			    salt       = EXCLUDED.salt,
			    expires_at = EXCLUDED.expires_at,
			    updated_at = NOW()`,
		pni, hash.Hash, hash.Salt, expiresAt,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres recoverypassword: put", err)
	}
	return nil
}

// Delete removes the entry for pni. Idempotent: deleting a missing row is
// not an error.
func (s *RecoveryPasswordStore) Delete(ctx context.Context, pni string) error {
	if _, err := s.q.Exec(ctx,
		`DELETE FROM registration_recovery_passwords WHERE pni = $1`, pni,
	); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres recoverypassword: delete", err)
	}
	return nil
}
