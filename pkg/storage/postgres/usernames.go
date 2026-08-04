package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// Compile-time interface satisfaction check.
var _ usernames.UsernameStore = (*UsernameStore)(nil)

const reservationTTL = 5 * time.Minute

// UsernameStore is a Postgres-backed implementation of usernames.UsernameStore.
//
// Single-statement methods use the pool via q directly. ReserveHash,
// ConfirmHash, DeleteHash, and SetLink each need atomicity across multiple
// statements and use c.WithTx.
type UsernameStore struct {
	q Querier
	c *Client
}

// NewUsernameStore constructs a UsernameStore backed by c.
func NewUsernameStore(c *Client) *UsernameStore {
	return &UsernameStore{q: c.Pool(), c: c}
}

// ReserveHash selects the first candidate hash that is neither confirmed by
// another account nor actively reserved by another account, reserves it for
// uuid, and returns the chosen hash and a random token. The same account
// calling again replaces its prior reservation via ON CONFLICT DO UPDATE.
func (s *UsernameStore) ReserveHash(ctx context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	if uuid == "" {
		return nil, "", &usernames.InvalidArgumentError{Field: "uuid", Message: "empty UUID"}
	}
	if len(hashes) == 0 {
		return nil, "", &usernames.InvalidArgumentError{Field: "hashes", Message: "no candidates provided"}
	}

	var chosen []byte
	var token string

	err := s.c.WithTx(ctx, func(tx pgx.Tx) error {
		// Drop expired reservations up-front. The UNIQUE constraint on
		// username_hash in usernames_reserved is unconditional — a partial
		// index keyed on `expires_at > NOW()` is not expressible because
		// NOW() is STABLE, not IMMUTABLE. So an expired-but-not-yet-swept
		// row would block another account from re-reserving the same hash
		// even though the reservation has logically lapsed.
		if _, err := tx.Exec(ctx,
			`DELETE FROM usernames_reserved WHERE expires_at < NOW()`); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: sweep expired", err)
		}

		// Collect hashes confirmed by a different account.
		blockedByConfirmed, err := fetchBlockedConfirmed(ctx, tx, uuid, hashes)
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: query confirmed", err)
		}

		// Collect hashes actively reserved by a different account.
		blockedByReserved, err := fetchBlockedReserved(ctx, tx, uuid, hashes)
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: query reserved", err)
		}

		// Pick the first candidate that is not blocked.
		for _, h := range hashes {
			if blockedByConfirmed[hex.EncodeToString(h)] || blockedByReserved[hex.EncodeToString(h)] {
				continue
			}
			chosen = h
			break
		}
		if chosen == nil {
			return &usernames.UsernameHashConflictError{Hash: hashes[0]}
		}

		tok, err := newToken()
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: generate token", err)
		}
		token = tok

		expiresAt := time.Now().Add(reservationTTL)
		// ON CONFLICT (account_uuid) replaces the prior reservation for this
		// account, handling same-account re-reserve atomically.
		_, err = tx.Exec(ctx, `
			INSERT INTO usernames_reserved (account_uuid, username_hash, token, expires_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (account_uuid) DO UPDATE
				SET username_hash = EXCLUDED.username_hash,
				    token         = EXCLUDED.token,
				    expires_at    = EXCLUDED.expires_at`,
			uuid, chosen, token, expiresAt,
		)
		if err != nil {
			// The UNIQUE constraint on username_hash fires when another
			// concurrent transaction just reserved the same hash between our
			// SELECT and this INSERT. Surface as a conflict.
			if IsUniqueViolation(err) {
				return &usernames.UsernameHashConflictError{Hash: chosen}
			}
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: upsert reservation", err)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return chosen, token, nil
}

// fetchBlockedConfirmed returns the hex-encoded set of hashes from candidates
// that are confirmed by a different account than uuid.
func fetchBlockedConfirmed(ctx context.Context, q Querier, uuid string, hashes [][]byte) (map[string]bool, error) {
	rows, err := q.Query(ctx, `
		SELECT username_hash FROM usernames_confirmed
		WHERE username_hash = ANY($1) AND account_uuid != $2`,
		hashSlice(hashes), uuid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHexSet(rows)
}

// fetchBlockedReserved returns the hex-encoded set of hashes from candidates
// that are reserved by a different account and have not yet expired.
func fetchBlockedReserved(ctx context.Context, q Querier, uuid string, hashes [][]byte) (map[string]bool, error) {
	rows, err := q.Query(ctx, `
		SELECT username_hash FROM usernames_reserved
		WHERE username_hash = ANY($1)
		  AND account_uuid != $2
		  AND expires_at > NOW()`,
		hashSlice(hashes), uuid,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHexSet(rows)
}

// scanHexSet reads a single-column BYTEA result set into a set keyed by
// hex-encoded hash.
func scanHexSet(rows pgx.Rows) (map[string]bool, error) {
	blocked := make(map[string]bool)
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		blocked[hex.EncodeToString(h)] = true
	}
	return blocked, rows.Err()
}

// hashSlice converts [][]byte to [][]byte for pgx ANY($1) binding. pgx
// encodes [][]byte as a Postgres BYTEA[] which ANY can match against BYTEA
// columns, so no additional conversion is required.
func hashSlice(hashes [][]byte) [][]byte { return hashes }

// ConfirmHash promotes a reservation to a confirmed username hash. The token
// and hash must match an active (non-expired) reservation for uuid.
func (s *UsernameStore) ConfirmHash(ctx context.Context, uuid string, hash []byte, token string) error {
	return s.c.WithTx(ctx, func(tx pgx.Tx) error {
		var storedHash []byte
		var storedToken string
		var expiresAt time.Time

		err := tx.QueryRow(ctx, `
			SELECT username_hash, token, expires_at
			FROM usernames_reserved
			WHERE account_uuid = $1`,
			uuid,
		).Scan(&storedHash, &storedToken, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return &usernames.InvalidReservationTokenError{UUID: uuid}
		}
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: get reservation", err)
		}

		if storedToken != token || !bytes.Equal(storedHash, hash) || time.Now().After(expiresAt) {
			return &usernames.InvalidReservationTokenError{UUID: uuid}
		}

		if _, err := tx.Exec(ctx, `
			DELETE FROM usernames_reserved WHERE account_uuid = $1`, uuid); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: delete reservation", err)
		}

		// UPSERT on account_uuid handles the case where this account previously
		// confirmed a different hash; the old row is replaced in place.
		_, err = tx.Exec(ctx, `
			INSERT INTO usernames_confirmed (username_hash, account_uuid, confirmed_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (account_uuid) DO UPDATE
				SET username_hash  = EXCLUDED.username_hash,
				    confirmed_at   = NOW()`,
			hash, uuid,
		)
		if err != nil {
			// PK conflict: another account already confirmed this exact hash.
			if IsUniqueViolation(err) {
				return &usernames.UsernameHashConflictError{Hash: hash}
			}
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: upsert confirmed", err)
		}
		return nil
	})
}

// LookupByHash returns the account UUID that owns the given confirmed hash.
func (s *UsernameStore) LookupByHash(ctx context.Context, hash []byte) (string, error) {
	var id string
	err := s.q.QueryRow(ctx, `
		SELECT account_uuid FROM usernames_confirmed WHERE username_hash = $1`, hash,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", &usernames.UsernameNotFoundError{Hash: hash}
	}
	if err != nil {
		return "", signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: lookup", err)
	}
	return id, nil
}

// DeleteHash removes the confirmed hash and any pending reservation for uuid.
// It is idempotent: deleting a non-existent mapping is not an error.
func (s *UsernameStore) DeleteHash(ctx context.Context, uuid string) error {
	return s.c.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			DELETE FROM usernames_confirmed WHERE account_uuid = $1`, uuid); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: delete confirmed", err)
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM usernames_reserved WHERE account_uuid = $1`, uuid); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: delete reservation", err)
		}
		return nil
	})
}

// HashForUUID returns the confirmed username hash for an account UUID, or
// *usernames.UsernameNotFoundError when no row exists.
func (s *UsernameStore) HashForUUID(ctx context.Context, uuid string) ([]byte, error) {
	var hash []byte
	err := s.q.QueryRow(ctx, `
		SELECT hash FROM usernames_confirmed WHERE account_uuid = $1`, uuid,
	).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &usernames.UsernameNotFoundError{Hash: []byte(uuid)}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: hash for uuid", err)
	}
	return hash, nil
}

// LinkForUUID returns the link currently published for an account UUID, or
// *usernames.UsernameLinkNotFoundError when no row exists.
func (s *UsernameStore) LinkForUUID(ctx context.Context, uuid string) (*usernames.UsernameLink, error) {
	var link usernames.UsernameLink
	err := s.q.QueryRow(ctx, `
		SELECT handle, account_uuid, encrypted_username
		FROM username_links
		WHERE account_uuid = $1`, uuid,
	).Scan(&link.UsernameLinkHandle, &link.UUID, &link.EncryptedUsername)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &usernames.UsernameLinkNotFoundError{Handle: uuid}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: link for uuid", err)
	}
	return &link, nil
}

// SetLink stores or replaces the username link for link.UUID. Any prior link
// for the same account UUID is removed first so the UNIQUE constraint on
// account_uuid is never violated by a stale row with a different handle.
func (s *UsernameStore) SetLink(ctx context.Context, link *usernames.UsernameLink) error {
	if link == nil {
		return &usernames.InvalidArgumentError{Field: "link", Message: "nil link"}
	}
	if link.UUID == "" || link.UsernameLinkHandle == "" {
		return &usernames.InvalidArgumentError{Field: "link", Message: "missing UUID or handle"}
	}

	return s.c.WithTx(ctx, func(tx pgx.Tx) error {
		// Remove any previous link row for this account that differs from the
		// new handle. Without this delete the ON CONFLICT DO UPDATE on (handle)
		// would leave the old row orphaned and the UNIQUE(account_uuid)
		// constraint would block insertion of a new handle for the same account.
		if _, err := tx.Exec(ctx, `
			DELETE FROM username_links
			WHERE account_uuid = $1 AND handle != $2`,
			link.UUID, link.UsernameLinkHandle,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: delete old link", err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO username_links (handle, account_uuid, encrypted_username)
			VALUES ($1, $2, $3)
			ON CONFLICT (handle) DO UPDATE
				SET account_uuid        = EXCLUDED.account_uuid,
				    encrypted_username  = EXCLUDED.encrypted_username`,
			link.UsernameLinkHandle, link.UUID, link.EncryptedUsername,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: upsert link", err)
		}
		return nil
	})
}

// GetLink retrieves a username link by its handle.
func (s *UsernameStore) GetLink(ctx context.Context, handle string) (*usernames.UsernameLink, error) {
	var link usernames.UsernameLink
	err := s.q.QueryRow(ctx, `
		SELECT handle, account_uuid, encrypted_username
		FROM username_links
		WHERE handle = $1`, handle,
	).Scan(&link.UsernameLinkHandle, &link.UUID, &link.EncryptedUsername)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &usernames.UsernameLinkNotFoundError{Handle: handle}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: get link", err)
	}
	return &link, nil
}

// DeleteLink removes the username link for the given account UUID. Idempotent.
func (s *UsernameStore) DeleteLink(ctx context.Context, uuid string) error {
	if _, err := s.q.Exec(ctx, `
		DELETE FROM username_links WHERE account_uuid = $1`, uuid); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: delete link", err)
	}
	return nil
}

// DeleteExpiredReservations removes every row in usernames_reserved
// whose expires_at is in the past. Returns the number of rows removed.
func (s *UsernameStore) DeleteExpiredReservations(ctx context.Context) (int, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM usernames_reserved WHERE expires_at < NOW()`)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "postgres usernames: delete expired reservations", err)
	}
	return int(tag.RowsAffected()), nil
}

// newToken generates a 16-byte cryptographically random token encoded as a
// 32-character lowercase hex string.
func newToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
