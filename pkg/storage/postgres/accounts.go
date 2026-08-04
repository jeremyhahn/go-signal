package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Compile-time interface satisfaction check.
var _ accounts.AccountStore = (*AccountStore)(nil)

// AccountStore is a Postgres-backed implementation of accounts.AccountStore.
//
// Schema design: the `data` JSONB column is the authoritative serialization
// of the Account struct (including embedded Devices). The promoted columns
// (aci, pni, e164, username_hash, username_link_handle, version) are
// projections used for indexing and uniqueness; they are written from the
// Account struct on every insert/update and stay in sync with `data`.
//
// Optimistic locking: Update applies WHERE version = current_version - 1,
// matching the qrdb contract that account.Version must be exactly one
// greater than the stored version.
type AccountStore struct {
	q Querier
}

// NewAccountStore constructs an AccountStore backed by the given Querier.
// Pass *pgxpool.Pool for normal use; pass pgx.Tx to participate in an outer
// transaction (e.g., a multi-store change-number flow).
func NewAccountStore(q Querier) *AccountStore {
	return &AccountStore{q: q}
}

// Create persists a new account, enforcing unique aci/pni/e164/username_hash
// via Postgres UNIQUE constraints. Conflicts on any of those are mapped to
// AccountAlreadyExistsError. The whole Account is serialized to JSONB.
func (s *AccountStore) Create(ctx context.Context, account *accounts.Account) error {
	if account == nil {
		return &accounts.InvalidArgumentError{Field: "account", Message: "nil account"}
	}
	if account.UUID == "" {
		return &accounts.InvalidArgumentError{Field: "uuid", Message: "empty UUID"}
	}

	data, err := json.Marshal(account)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: marshal", err)
	}

	_, err = s.q.Exec(ctx, `
		INSERT INTO accounts (
			aci, pni, e164, username_hash, username_link_handle,
			version, data, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())`,
		account.UUID,
		nullableUUID(account.PNI),
		account.Number,
		nullableBytes(account.UsernameHash),
		nullableString(account.Username),
		account.Version,
		data,
	)
	if err != nil {
		if conflictID, ok := s.identifyConflict(err, account); ok {
			return &accounts.AccountAlreadyExistsError{Identifier: conflictID}
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: insert", err)
	}
	return nil
}

// Get retrieves an account by ACI.
func (s *AccountStore) Get(ctx context.Context, uuid string) (*accounts.Account, error) {
	return s.scanOne(ctx,
		`SELECT data FROM accounts WHERE aci = $1`, uuid)
}

// GetByNumber retrieves an account by E.164 phone number.
func (s *AccountStore) GetByNumber(ctx context.Context, number string) (*accounts.Account, error) {
	return s.scanOne(ctx,
		`SELECT data FROM accounts WHERE e164 = $1`, number)
}

// GetByPNI retrieves an account by Phone Number Identity.
func (s *AccountStore) GetByPNI(ctx context.Context, pni string) (*accounts.Account, error) {
	return s.scanOne(ctx,
		`SELECT data FROM accounts WHERE pni = $1`, pni)
}

// Update persists changes to an existing account with optimistic locking.
// account.Version must be exactly one greater than the currently stored
// version; any other value returns *VersionConflictError.
func (s *AccountStore) Update(ctx context.Context, account *accounts.Account) error {
	if account == nil {
		return &accounts.InvalidArgumentError{Field: "account", Message: "nil account"}
	}

	data, err := json.Marshal(account)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: marshal", err)
	}

	tag, err := s.q.Exec(ctx, `
		UPDATE accounts SET
			pni = $2,
			e164 = $3,
			username_hash = $4,
			username_link_handle = $5,
			version = $6,
			data = $7,
			updated_at = NOW()
		WHERE aci = $1 AND version = $6 - 1`,
		account.UUID,
		nullableUUID(account.PNI),
		account.Number,
		nullableBytes(account.UsernameHash),
		nullableString(account.Username),
		account.Version,
		data,
	)
	if err != nil {
		if conflictID, ok := s.identifyConflict(err, account); ok {
			return &accounts.AccountAlreadyExistsError{Identifier: conflictID}
		}
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: update", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// Zero rows: either the account doesn't exist or the version mismatched.
	// Distinguish by reading the current row.
	current, err := s.Get(ctx, account.UUID)
	if err != nil {
		return err
	}
	return &accounts.VersionConflictError{
		AccountUUID:     account.UUID,
		ExpectedVersion: current.Version + 1,
		ActualVersion:   account.Version,
	}
}

// ListAll iterates every row in `accounts`, decoding the JSONB into
// Account and yielding to fn. Uses a single SELECT over the data
// column; pgx's row iteration streams server-side rather than
// materialising the whole result set in memory.
func (s *AccountStore) ListAll(ctx context.Context, fn func(*accounts.Account) error) error {
	rows, err := s.q.Query(ctx, `SELECT data FROM accounts`)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: list query", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: list scan", err)
		}
		var acct accounts.Account
		if err := json.Unmarshal(raw, &acct); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: list unmarshal", err)
		}
		if err := fn(&acct); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Delete removes an account by ACI. Cascades from accounts(aci) clean up
// per-account child tables (pre-keys, profiles, etc.) automatically.
func (s *AccountStore) Delete(ctx context.Context, uuid string) error {
	tag, err := s.q.Exec(ctx, `DELETE FROM accounts WHERE aci = $1`, uuid)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: delete", err)
	}
	if tag.RowsAffected() == 0 {
		return &accounts.AccountNotFoundError{Identifier: uuid}
	}
	return nil
}

// scanOne runs a single-row SELECT data and decodes the JSONB into Account.
// Row absence is mapped to AccountNotFoundError using the trailing arg as
// the identifier hint (matches the qrdb impl's behavior).
func (s *AccountStore) scanOne(ctx context.Context, sql string, ident string) (*accounts.Account, error) {
	var raw []byte
	if err := s.q.QueryRow(ctx, sql, ident).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &accounts.AccountNotFoundError{Identifier: ident}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: query", err)
	}
	var acct accounts.Account
	if err := json.Unmarshal(raw, &acct); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres accounts: unmarshal", err)
	}
	return &acct, nil
}

// identifyConflict inspects err for a unique-constraint violation and
// returns (conflictingIdentifier, true) when one is detected. The
// identifier is the value the caller was trying to insert that already
// exists — useful for the AccountAlreadyExistsError message. Constraint
// names are mapped explicitly so a future schema rename surfaces here.
func (s *AccountStore) identifyConflict(err error, account *accounts.Account) (string, bool) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return "", false
	}
	switch pgErr.ConstraintName {
	case "accounts_pkey":
		return account.UUID, true
	case "accounts_pni_key":
		return account.PNI, true
	case "accounts_e164_key":
		return account.Number, true
	case "accounts_username_hash_key":
		return string(account.UsernameHash), true
	case "accounts_username_link_handle_key":
		return account.Username, true
	}
	return account.UUID, true
}

// nullableString converts an empty Go string to a NULL Postgres value.
// Uniqueness on a TEXT column with NULLs allows multiple unset rows.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableUUID is the UUID-typed equivalent of nullableString. Postgres
// rejects empty strings as UUIDs, so empties must be sent as NULL.
func nullableUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableBytes converts a nil/empty byte slice to a NULL Postgres value.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
