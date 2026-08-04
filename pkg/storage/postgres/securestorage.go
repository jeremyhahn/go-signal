package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
)

// Compile-time interface satisfaction check.
var _ securestorage.ManifestStore = (*ManifestStore)(nil)

// ManifestStore is a Postgres-backed implementation of
// securestorage.ManifestStore. Manifests and items are stored as raw BYTEA
// (the blobs are end-to-end encrypted; the server never interprets them).
//
// PutManifest requires a transaction to safely enforce the monotonic version
// increment (SELECT FOR UPDATE + conditional INSERT/UPDATE), so the constructor
// takes *Client rather than the bare Querier interface.
type ManifestStore struct {
	client *Client
}

// NewManifestStore constructs a ManifestStore backed by client.
func NewManifestStore(client *Client) *ManifestStore {
	return &ManifestStore{client: client}
}

// GetManifest retrieves the current manifest for the account. Returns
// *securestorage.ManifestNotFoundError when no manifest has been stored yet.
func (s *ManifestStore) GetManifest(ctx context.Context, accountUUID string) (*securestorage.StorageManifest, error) {
	return getManifest(ctx, s.client.pool, accountUUID)
}

// getManifest is shared by GetManifest and the PutManifest transaction so both
// paths use the same query against whichever Querier they hold (pool or tx).
func getManifest(ctx context.Context, q Querier, accountUUID string) (*securestorage.StorageManifest, error) {
	var version uint64
	var value []byte
	err := q.QueryRow(ctx,
		`SELECT version, value FROM storage_manifests WHERE account_uuid = $1`,
		accountUUID,
	).Scan(&version, &value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &securestorage.ManifestNotFoundError{AccountUUID: accountUUID}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: get manifest", err)
	}
	return &securestorage.StorageManifest{Version: version, Value: value}, nil
}

// PutManifest stores a new manifest. The incoming version must be strictly
// greater than the currently stored version. The check and write are executed
// inside a READ COMMITTED transaction with a SELECT FOR UPDATE on the existing
// row so concurrent callers serialise correctly.
func (s *ManifestStore) PutManifest(ctx context.Context, accountUUID string, m *securestorage.StorageManifest) error {
	if m == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres ss: nil manifest")
	}
	return s.client.WithTx(ctx, func(tx pgx.Tx) error {
		// Lock the existing row (if any) before reading the version; this
		// prevents a concurrent PutManifest from racing past the version check.
		var current uint64
		err := tx.QueryRow(ctx,
			`SELECT version FROM storage_manifests WHERE account_uuid = $1 FOR UPDATE`,
			accountUUID,
		).Scan(&current)

		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// No existing manifest — any version >= 1 is acceptable.
		case err != nil:
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: lock manifest", err)
		default:
			if m.Version <= current {
				return &securestorage.ManifestVersionConflictError{
					AccountUUID:      accountUUID,
					StoredVersion:    current,
					SubmittedVersion: m.Version,
				}
			}
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO storage_manifests (account_uuid, version, value, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (account_uuid) DO UPDATE
				SET version    = EXCLUDED.version,
				    value      = EXCLUDED.value,
				    updated_at = EXCLUDED.updated_at`,
			accountUUID,
			m.Version,
			m.Value,
		)
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: upsert manifest", err)
		}
		return nil
	})
}

// GetItem retrieves a storage item by key for the account. Returns
// *securestorage.StorageItemNotFoundError when absent.
func (s *ManifestStore) GetItem(ctx context.Context, accountUUID string, key []byte) (*securestorage.StorageItem, error) {
	var value []byte
	err := s.client.pool.QueryRow(ctx,
		`SELECT value FROM storage_items WHERE account_uuid = $1 AND item_key = $2`,
		accountUUID,
		key,
	).Scan(&value)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &securestorage.StorageItemNotFoundError{AccountUUID: accountUUID, Key: key}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: get item", err)
	}
	return &securestorage.StorageItem{Key: key, Value: value}, nil
}

// PutItem stores an item, overwriting any previously stored value.
func (s *ManifestStore) PutItem(ctx context.Context, accountUUID string, item *securestorage.StorageItem) error {
	if item == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres ss: nil item")
	}
	_, err := s.client.pool.Exec(ctx, `
		INSERT INTO storage_items (account_uuid, item_key, value, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (account_uuid, item_key) DO UPDATE
			SET value      = EXCLUDED.value,
			    updated_at = EXCLUDED.updated_at`,
		accountUUID,
		item.Key,
		item.Value,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: upsert item", err)
	}
	return nil
}

// DeleteItem removes an item by key. Returns
// *securestorage.StorageItemNotFoundError when absent, matching the qrdb
// non-idempotent behavior.
func (s *ManifestStore) DeleteItem(ctx context.Context, accountUUID string, key []byte) error {
	tag, err := s.client.pool.Exec(ctx,
		`DELETE FROM storage_items WHERE account_uuid = $1 AND item_key = $2`,
		accountUUID,
		key,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: delete item", err)
	}
	if tag.RowsAffected() == 0 {
		return &securestorage.StorageItemNotFoundError{AccountUUID: accountUUID, Key: key}
	}
	return nil
}

// DeleteAll removes all items and the manifest for the account atomically.
func (s *ManifestStore) DeleteAll(ctx context.Context, accountUUID string) error {
	return s.client.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM storage_items WHERE account_uuid = $1`, accountUUID,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: delete items", err)
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM storage_manifests WHERE account_uuid = $1`, accountUUID,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres ss: delete manifest", err)
		}
		return nil
	})
}
