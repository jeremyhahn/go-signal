package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// Compile-time interface satisfaction check.
var _ profiles.ProfileStore = (*ProfileStore)(nil)

// ProfileStore is a Postgres-backed implementation of profiles.ProfileStore.
//
// Schema: profiles(account_uuid, version) PRIMARY KEY with a partial unique
// index profiles_latest_idx ON (account_uuid) WHERE is_latest=TRUE enforces
// at most one latest row per account. Set promotes the supplied version to
// latest atomically inside a transaction: it first demotes all existing rows
// for the account, then upserts the new row with is_latest=TRUE.
type ProfileStore struct {
	q Querier
}

// NewProfileStore constructs a ProfileStore backed by the given Querier.
func NewProfileStore(q Querier) *ProfileStore {
	return &ProfileStore{q: q}
}

// Set stores a profile version and promotes it to latest. The operation runs
// in a transaction: existing is_latest rows for the account are demoted before
// the upsert, guaranteeing the partial unique index is never violated.
func (s *ProfileStore) Set(ctx context.Context, profile *profiles.Profile) error {
	if profile == nil {
		return &profiles.InvalidArgumentError{Field: "profile", Message: "nil profile"}
	}
	if profile.UUID == "" {
		return &profiles.InvalidArgumentError{Field: "uuid", Message: "empty UUID"}
	}
	if profile.Version == "" {
		return &profiles.InvalidArgumentError{Field: "version", Message: "empty version"}
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: marshal", err)
	}

	// Both statements must execute atomically. If q is already a pgx.Tx the
	// inner batch still works correctly; if it is a pool, BeginTx opens a
	// fresh transaction and rolls back on any error.
	type txQuerier interface {
		Querier
		BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	}

	runInTx := func(tx Querier) error {
		// Demote all current is_latest rows for this account so the partial
		// unique index has no conflicting row before the upsert below.
		if _, err := tx.Exec(ctx,
			`UPDATE profiles SET is_latest = FALSE, updated_at = NOW()
			 WHERE account_uuid = $1 AND is_latest = TRUE`,
			profile.UUID,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: demote latest", err)
		}

		// Upsert the supplied version and mark it as latest.
		if _, err := tx.Exec(ctx, `
			INSERT INTO profiles (account_uuid, version, data, is_latest, updated_at)
			VALUES ($1, $2, $3, TRUE, NOW())
			ON CONFLICT (account_uuid, version) DO UPDATE
				SET data       = EXCLUDED.data,
				    is_latest  = TRUE,
				    updated_at = NOW()`,
			profile.UUID,
			profile.Version,
			data,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: upsert", err)
		}
		return nil
	}

	// If the Querier is already a transaction, run directly to avoid nesting.
	if tx, ok := s.q.(pgx.Tx); ok {
		return runInTx(tx)
	}

	// Pool path: open a transaction for the two-statement atomic update.
	if pool, ok := s.q.(txQuerier); ok {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: begin tx", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := runInTx(tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	// Querier is neither a pool nor a tx (e.g., a test double). Run the two
	// statements without a transaction wrapper — callers providing mock
	// Queriers in tests must handle ordering themselves.
	return runInTx(s.q)
}

// Get retrieves a specific version of a profile.
func (s *ProfileStore) Get(ctx context.Context, uuid, version string) (*profiles.Profile, error) {
	var raw []byte
	err := s.q.QueryRow(ctx,
		`SELECT data FROM profiles WHERE account_uuid = $1 AND version = $2`,
		uuid, version,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &profiles.ProfileNotFoundError{UUID: uuid, Version: version}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: get", err)
	}
	var p profiles.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: unmarshal", err)
	}
	return &p, nil
}

// GetLatest retrieves the most recently promoted profile version for an account.
func (s *ProfileStore) GetLatest(ctx context.Context, uuid string) (*profiles.Profile, error) {
	var raw []byte
	err := s.q.QueryRow(ctx,
		`SELECT data FROM profiles WHERE account_uuid = $1 AND is_latest = TRUE`,
		uuid,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &profiles.ProfileNotFoundError{UUID: uuid}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: get latest", err)
	}
	var p profiles.Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: unmarshal", err)
	}
	return &p, nil
}

// Delete removes all profile versions for a UUID, including the latest row.
// Silently succeeds when no rows exist (mirrors the qrdb implementation).
func (s *ProfileStore) Delete(ctx context.Context, uuid string) error {
	if _, err := s.q.Exec(ctx,
		`DELETE FROM profiles WHERE account_uuid = $1`, uuid,
	); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres profiles: delete", err)
	}
	return nil
}
