//go:build fido2

package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// Compile-time interface satisfaction check.
var _ fido2.FIDO2AccountsStore = (*FIDO2AccountsStore)(nil)

// FIDO2AccountsStore is a Postgres-backed implementation of
// fido2.FIDO2AccountsStore. Credential blobs and session blobs are stored
// as JSONB in the data column; account_uuid and expires_at are promoted
// columns used for indexed queries.
type FIDO2AccountsStore struct {
	q Querier
}

// NewFIDO2AccountsStore constructs a FIDO2AccountsStore backed by q.
// Pass *pgxpool.Pool for normal use or pgx.Tx to participate in a caller
// transaction.
func NewFIDO2AccountsStore(q Querier) *FIDO2AccountsStore {
	return &FIDO2AccountsStore{q: q}
}

// CreateCredential persists a new FIDO2 credential. Returns
// *fido2.CredentialExistsError on a primary-key collision.
func (s *FIDO2AccountsStore) CreateCredential(ctx context.Context, cred *fido2.FIDO2Credential) error {
	if cred == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres fido2: nil credential")
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: marshal credential", err)
	}
	_, err = s.q.Exec(ctx, `
		INSERT INTO fido2_credentials (credential_id, account_uuid, data, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())`,
		cred.CredentialID,
		cred.AccountUUID,
		data,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return &fido2.CredentialExistsError{CredentialID: cred.CredentialID}
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: insert credential", err)
	}
	return nil
}

// GetCredential retrieves a credential by its unique identifier. Returns
// *fido2.CredentialNotFoundError when absent.
func (s *FIDO2AccountsStore) GetCredential(ctx context.Context, credentialID string) (*fido2.FIDO2Credential, error) {
	var raw []byte
	err := s.q.QueryRow(ctx,
		`SELECT data FROM fido2_credentials WHERE credential_id = $1`,
		credentialID,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &fido2.CredentialNotFoundError{CredentialID: credentialID}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: get credential", err)
	}
	var cred fido2.FIDO2Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: unmarshal credential", err)
	}
	return &cred, nil
}

// GetCredentialsByAccount returns all credentials registered to the account,
// ordered by their original created_at timestamp (oldest first).
func (s *FIDO2AccountsStore) GetCredentialsByAccount(ctx context.Context, accountUUID string) ([]*fido2.FIDO2Credential, error) {
	rows, err := s.q.Query(ctx,
		`SELECT data FROM fido2_credentials WHERE account_uuid = $1 ORDER BY created_at`,
		accountUUID,
	)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: query credentials by account", err)
	}
	defer rows.Close()

	// Non-nil empty slice on no rows; matches the memory/qrdb backends'
	// behavior so callers can use `len(out) == 0` uniformly.
	out := []*fido2.FIDO2Credential{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: scan credential row", err)
		}
		var cred fido2.FIDO2Credential
		if err := json.Unmarshal(raw, &cred); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: unmarshal credential", err)
		}
		out = append(out, &cred)
	}
	if err := rows.Err(); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: iterate credentials", err)
	}
	return out, nil
}

// UpdateCredential overwrites an existing credential's data blob and bumps
// updated_at. Returns *fido2.CredentialNotFoundError when the credential
// does not exist.
func (s *FIDO2AccountsStore) UpdateCredential(ctx context.Context, cred *fido2.FIDO2Credential) error {
	if cred == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres fido2: nil credential")
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: marshal credential", err)
	}
	tag, err := s.q.Exec(ctx,
		`UPDATE fido2_credentials SET data = $2, updated_at = NOW() WHERE credential_id = $1`,
		cred.CredentialID,
		data,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: update credential", err)
	}
	if tag.RowsAffected() == 0 {
		return &fido2.CredentialNotFoundError{CredentialID: cred.CredentialID}
	}
	return nil
}

// DeleteCredential removes a credential by ID. Returns
// *fido2.CredentialNotFoundError when it does not exist.
func (s *FIDO2AccountsStore) DeleteCredential(ctx context.Context, credentialID string) error {
	tag, err := s.q.Exec(ctx,
		`DELETE FROM fido2_credentials WHERE credential_id = $1`,
		credentialID,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: delete credential", err)
	}
	if tag.RowsAffected() == 0 {
		return &fido2.CredentialNotFoundError{CredentialID: credentialID}
	}
	return nil
}

// StoreSession persists a WebAuthn ceremony session. Uses INSERT...ON CONFLICT
// DO UPDATE so callers can re-store an existing session (e.g., after nonce
// refresh) without a prior delete — matching the qrdb upsert semantics.
func (s *FIDO2AccountsStore) StoreSession(ctx context.Context, session *fido2.FIDO2Session) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres fido2: nil session")
	}
	data, err := json.Marshal(session)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: marshal session", err)
	}
	_, err = s.q.Exec(ctx, `
		INSERT INTO fido2_sessions (id, account_uuid, data, expires_at, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE
			SET account_uuid = EXCLUDED.account_uuid,
			    data         = EXCLUDED.data,
			    expires_at   = EXCLUDED.expires_at`,
		session.ID,
		nullableString(session.AccountUUID),
		data,
		session.ExpiresAt,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: upsert session", err)
	}
	return nil
}

// GetSession retrieves a WebAuthn session by ID. Returns
// *fido2.SessionNotFoundError when absent.
func (s *FIDO2AccountsStore) GetSession(ctx context.Context, sessionID string) (*fido2.FIDO2Session, error) {
	var raw []byte
	err := s.q.QueryRow(ctx,
		`SELECT data FROM fido2_sessions WHERE id = $1`,
		sessionID,
	).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &fido2.SessionNotFoundError{SessionID: sessionID}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: get session", err)
	}
	var sess fido2.FIDO2Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: unmarshal session", err)
	}
	return &sess, nil
}

// DeleteSession removes a session by ID. Returns *fido2.SessionNotFoundError
// when absent, matching the qrdb impl's non-idempotent behavior.
func (s *FIDO2AccountsStore) DeleteSession(ctx context.Context, sessionID string) error {
	tag, err := s.q.Exec(ctx,
		`DELETE FROM fido2_sessions WHERE id = $1`,
		sessionID,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres fido2: delete session", err)
	}
	if tag.RowsAffected() == 0 {
		return &fido2.SessionNotFoundError{SessionID: sessionID}
	}
	return nil
}
