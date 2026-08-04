package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// Compile-time interface satisfaction check.
var _ keys.PreKeyStore = (*PreKeyStore)(nil)

// PreKeyStore is a Postgres-backed implementation of keys.PreKeyStore.
//
// TakeEC and TakeKEM use DELETE...RETURNING with a sub-select on MIN(key_id)
// to atomically consume the lowest-keyID one-time key in a single round-trip,
// eliminating the list-then-delete race present in KV backends. Concurrent
// Takes for the same device serialize naturally at the row lock level.
//
// StoreECPreKeys and StoreKEMPreKeys clear existing keys for the device before
// inserting to match the qrdb contract: the stored set reflects exactly the
// caller's intent, not a union with whatever was previously there.
type PreKeyStore struct {
	q Querier
}

// NewPreKeyStore constructs a PreKeyStore backed by the given Querier.
// Pass *pgxpool.Pool for normal use; pass pgx.Tx to participate in an outer
// transaction.
func NewPreKeyStore(q Querier) *PreKeyStore {
	return &PreKeyStore{q: q}
}

// StoreECPreKeys replaces the one-time EC pre-key batch for a device.
// The replacement runs in a transaction: existing keys are deleted first,
// then the new batch is inserted via a pgx.Batch for a single round-trip.
func (s *PreKeyStore) StoreECPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*keys.PreKey) error {
	return withTxQuerier(ctx, s.q, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM prekeys_ec_onetime WHERE account_uuid=$1 AND device_id=$2`,
			uuid, deviceID,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: delete ec", err)
		}
		if len(preKeys) == 0 {
			return nil
		}
		b := &pgx.Batch{}
		for _, pk := range preKeys {
			if pk == nil {
				continue
			}
			b.Queue(
				`INSERT INTO prekeys_ec_onetime (account_uuid, device_id, key_id, public_key)
				 VALUES ($1, $2, $3, $4)
				 ON CONFLICT (account_uuid, device_id, key_id) DO UPDATE SET public_key = EXCLUDED.public_key`,
				uuid, deviceID, pk.KeyID, pk.PublicKey,
			)
		}
		br := tx.SendBatch(ctx, b)
		defer func() { _ = br.Close() }()
		for range preKeys {
			if _, err := br.Exec(); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: insert ec", err)
			}
		}
		return nil
	})
}

// StoreKEMPreKeys replaces the one-time KEM pre-key batch for a device.
func (s *PreKeyStore) StoreKEMPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error {
	return withTxQuerier(ctx, s.q, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM prekeys_kem_onetime WHERE account_uuid=$1 AND device_id=$2`,
			uuid, deviceID,
		); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: delete kem", err)
		}
		if len(preKeys) == 0 {
			return nil
		}
		b := &pgx.Batch{}
		for _, pk := range preKeys {
			if pk == nil {
				continue
			}
			b.Queue(
				`INSERT INTO prekeys_kem_onetime (account_uuid, device_id, key_id, public_key, signature)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (account_uuid, device_id, key_id) DO UPDATE
				     SET public_key = EXCLUDED.public_key, signature = EXCLUDED.signature`,
				uuid, deviceID, pk.KeyID, pk.PublicKey, pk.Signature,
			)
		}
		br := tx.SendBatch(ctx, b)
		defer func() { _ = br.Close() }()
		for range preKeys {
			if _, err := br.Exec(); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: insert kem", err)
			}
		}
		return nil
	})
}

// StoreKEMLastResortPreKey persists or replaces the last-resort KEM pre-key
// for a device. The key is never consumed during session establishment.
func (s *PreKeyStore) StoreKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64, preKey *keys.KEMSignedPreKey) error {
	if preKey == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres prekeys: nil last-resort key")
	}
	_, err := s.q.Exec(ctx,
		`INSERT INTO prekeys_kem_lastresort (account_uuid, device_id, key_id, public_key, signature)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (account_uuid, device_id) DO UPDATE
		     SET key_id = EXCLUDED.key_id,
		         public_key = EXCLUDED.public_key,
		         signature = EXCLUDED.signature`,
		uuid, deviceID, preKey.KeyID, preKey.PublicKey, preKey.Signature,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: upsert kem last-resort", err)
	}
	return nil
}

// StoreSignedPreKey persists or replaces the current signed EC pre-key for a device.
func (s *PreKeyStore) StoreSignedPreKey(ctx context.Context, uuid string, deviceID uint64, signedPreKey *keys.SignedPreKey) error {
	if signedPreKey == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres prekeys: nil signed pre-key")
	}
	_, err := s.q.Exec(ctx,
		`INSERT INTO prekeys_ec_signed (account_uuid, device_id, key_id, public_key, signature)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (account_uuid, device_id) DO UPDATE
		     SET key_id = EXCLUDED.key_id,
		         public_key = EXCLUDED.public_key,
		         signature = EXCLUDED.signature`,
		uuid, deviceID, signedPreKey.KeyID, signedPreKey.PublicKey, signedPreKey.Signature,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: upsert signed", err)
	}
	return nil
}

// TakeEC atomically deletes and returns the one-time EC pre-key with the
// lowest key_id for the device. DELETE...RETURNING with a correlated
// MIN(key_id) sub-select is a single statement — no separate read, no race.
func (s *PreKeyStore) TakeEC(ctx context.Context, uuid string, deviceID uint64) (*keys.PreKey, error) {
	var pk keys.PreKey
	err := s.q.QueryRow(ctx,
		`DELETE FROM prekeys_ec_onetime
		 WHERE account_uuid=$1
		   AND device_id=$2
		   AND key_id=(
		       SELECT MIN(key_id) FROM prekeys_ec_onetime
		       WHERE account_uuid=$1 AND device_id=$2
		   )
		 RETURNING key_id, public_key`,
		uuid, deviceID,
	).Scan(&pk.KeyID, &pk.PublicKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &keys.PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "EC"}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: take ec", err)
	}
	return &pk, nil
}

// TakeKEM atomically deletes and returns the one-time KEM pre-key with the
// lowest key_id for the device. Does not fall back to the last-resort key —
// callers must call GetKEMLastResortPreKey when this returns KeyNotFoundError.
func (s *PreKeyStore) TakeKEM(ctx context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	var pk keys.KEMSignedPreKey
	err := s.q.QueryRow(ctx,
		`DELETE FROM prekeys_kem_onetime
		 WHERE account_uuid=$1
		   AND device_id=$2
		   AND key_id=(
		       SELECT MIN(key_id) FROM prekeys_kem_onetime
		       WHERE account_uuid=$1 AND device_id=$2
		   )
		 RETURNING key_id, public_key, signature`,
		uuid, deviceID,
	).Scan(&pk.KeyID, &pk.PublicKey, &pk.Signature)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &keys.PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "KEM"}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: take kem", err)
	}
	return &pk, nil
}

// GetKEMLastResortPreKey returns the last-resort KEM pre-key without consuming it.
func (s *PreKeyStore) GetKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	var pk keys.KEMSignedPreKey
	err := s.q.QueryRow(ctx,
		`SELECT key_id, public_key, signature FROM prekeys_kem_lastresort
		 WHERE account_uuid=$1 AND device_id=$2`,
		uuid, deviceID,
	).Scan(&pk.KeyID, &pk.PublicKey, &pk.Signature)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &keys.PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "KEM last-resort"}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: get kem last-resort", err)
	}
	pk.IsLastResort = true
	return &pk, nil
}

// GetSignedPreKey returns the current signed EC pre-key for a device.
func (s *PreKeyStore) GetSignedPreKey(ctx context.Context, uuid string, deviceID uint64) (*keys.SignedPreKey, error) {
	var spk keys.SignedPreKey
	err := s.q.QueryRow(ctx,
		`SELECT key_id, public_key, signature FROM prekeys_ec_signed
		 WHERE account_uuid=$1 AND device_id=$2`,
		uuid, deviceID,
	).Scan(&spk.KeyID, &spk.PublicKey, &spk.Signature)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &keys.PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "signed"}
		}
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: get signed", err)
	}
	return &spk, nil
}

// GetPreKeyCount returns the current counts of remaining one-time pre-keys and
// whether a last-resort KEM key exists. Three selects run inside a single
// implicit read: no transaction needed since each count is independent.
func (s *PreKeyStore) GetPreKeyCount(ctx context.Context, uuid string, deviceID uint64) (*keys.PreKeyState, error) {
	var state keys.PreKeyState
	err := s.q.QueryRow(ctx,
		`SELECT
		     (SELECT COUNT(*) FROM prekeys_ec_onetime    WHERE account_uuid=$1 AND device_id=$2),
		     (SELECT COUNT(*) FROM prekeys_kem_onetime   WHERE account_uuid=$1 AND device_id=$2),
		     (SELECT EXISTS   (SELECT 1 FROM prekeys_kem_lastresort WHERE account_uuid=$1 AND device_id=$2))`,
		uuid, deviceID,
	).Scan(&state.ECCount, &state.KEMCount, &state.HasLastResort)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: get count", err)
	}
	return &state, nil
}

// DeleteAllForDevice removes every pre-key row (all four tables) for the
// given (uuid, device_id) pair. Wraps in a transaction for atomicity.
func (s *PreKeyStore) DeleteAllForDevice(ctx context.Context, uuid string, deviceID uint64) error {
	return withTxQuerier(ctx, s.q, func(tx pgx.Tx) error {
		for _, table := range preKeyTables {
			if _, err := tx.Exec(ctx,
				`DELETE FROM `+table+` WHERE account_uuid=$1 AND device_id=$2`,
				uuid, deviceID,
			); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: delete device from "+table, err)
			}
		}
		return nil
	})
}

// DeleteAllForAccount removes every pre-key row across all devices for the
// given account UUID. Wraps in a transaction for atomicity.
func (s *PreKeyStore) DeleteAllForAccount(ctx context.Context, uuid string) error {
	return withTxQuerier(ctx, s.q, func(tx pgx.Tx) error {
		for _, table := range preKeyTables {
			if _, err := tx.Exec(ctx,
				`DELETE FROM `+table+` WHERE account_uuid=$1`,
				uuid,
			); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: delete account from "+table, err)
			}
		}
		return nil
	})
}

// preKeyTables enumerates all four pre-key tables in deletion-safe order
// (one-time before singleton to avoid any FK ordering edge cases, though
// all four cascade from accounts(aci)).
var preKeyTables = [4]string{
	"prekeys_ec_onetime",
	"prekeys_kem_onetime",
	"prekeys_ec_signed",
	"prekeys_kem_lastresort",
}

// ListAccountUUIDs returns every distinct account UUID with rows in
// any pre-key table. The orphan-prekey sweeper diffs this against the
// accounts table to find rows whose owning account is gone.
func (s *PreKeyStore) ListAccountUUIDs(ctx context.Context) ([]string, error) {
	const stmt = `
		SELECT account_uuid FROM prekeys_ec_onetime
		UNION
		SELECT account_uuid FROM prekeys_kem_onetime
		UNION
		SELECT account_uuid FROM prekeys_ec_signed
		UNION
		SELECT account_uuid FROM prekeys_kem_lastresort`
	rows, err := s.q.Query(ctx, stmt)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: list account uuids", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: scan uuid", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// withTxQuerier begins a transaction on the underlying pool when q is a
// *pgxpool.Pool, or borrows the existing transaction when q is already a
// pgx.Tx. This lets PreKeyStore methods compose correctly whether they are
// called inside or outside a caller-managed transaction.
func withTxQuerier(ctx context.Context, q Querier, fn func(pgx.Tx) error) error {
	if tx, ok := q.(pgx.Tx); ok {
		return fn(tx)
	}
	// q is a pool — acquire a connection and wrap in a transaction.
	type beginner interface {
		BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	}
	b, ok := q.(beginner)
	if !ok {
		return signalerrors.New(signalerrors.ErrInternal, "postgres prekeys: querier does not support transactions")
	}
	tx, err := b.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres prekeys: begin tx", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
