package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jeremyhahn/go-signal/pkg/backups"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Compile-time interface satisfaction checks.
var (
	_ backups.Store                 = (*BackupStore)(nil)
	_ backups.RedeemedReceiptsStore = (*RedeemedReceiptsStore)(nil)
)

// BackupStore is a Postgres-backed implementation of [backups.Store].
type BackupStore struct {
	q   Querier
	now func() time.Time
}

// NewBackupStore returns a store backed by c.
func NewBackupStore(c *Client) *BackupStore {
	return &BackupStore{q: c.Pool(), now: func() time.Time { return time.Now().UTC() }}
}

// SetClock overrides the time source. Intended for tests.
func (s *BackupStore) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func hashBackupID(id backups.BackupID) []byte {
	sum := sha256.Sum256(id[:])
	out := make([]byte, 16)
	copy(out, sum[:16])
	return out
}

func generateDirName() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])[:16]
}

// SetPublicKey implements [backups.Store]. Uses INSERT … ON CONFLICT with a
// WHERE clause that rejects updates when the supplied public_key differs
// from the stored one — the canonical "set once, idempotent on re-set"
// semantic for backup-id commitments.
func (s *BackupStore) SetPublicKey(
	ctx context.Context,
	id backups.BackupID,
	level backups.BackupLevel,
	publicKey []byte,
) error {
	hashed := hashBackupID(id)
	now := s.now()
	tag, err := s.q.Exec(ctx, `
		INSERT INTO backups (
			hashed_backup_id, public_key, backup_level,
			backup_dir, media_dir, last_refresh, last_media_refresh
		)
		VALUES ($1, $2, $3, $4, $5, $6, $6)
		ON CONFLICT (hashed_backup_id) DO UPDATE
			SET backup_level = EXCLUDED.backup_level,
			    last_refresh = EXCLUDED.last_refresh
			WHERE backups.public_key = EXCLUDED.public_key`,
		hashed, publicKey, int(level), generateDirName(), generateDirName(), now,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: set public key", err)
	}
	if tag.RowsAffected() == 0 {
		// ON CONFLICT … WHERE matched zero rows: a row exists with a
		// different stored public key.
		return &backups.PublicKeyConflictError{BackupID: id}
	}
	return nil
}

// RetrieveAuthenticationData implements [backups.Store].
func (s *BackupStore) RetrieveAuthenticationData(
	ctx context.Context,
	id backups.BackupID,
) (*backups.AuthenticationData, bool, error) {
	var publicKey []byte
	var backupDir, mediaDir string
	err := s.q.QueryRow(ctx, `
		SELECT public_key, backup_dir, media_dir
		FROM backups
		WHERE hashed_backup_id = $1`,
		hashBackupID(id),
	).Scan(&publicKey, &backupDir, &mediaDir)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: retrieve auth data", err)
	}
	return &backups.AuthenticationData{
		PublicKey: publicKey,
		BackupDir: backupDir,
		MediaDir:  mediaDir,
	}, true, nil
}

// AddMessageBackup implements [backups.Store].
func (s *BackupStore) AddMessageBackup(ctx context.Context, user backups.AuthenticatedUser) error {
	tag, err := s.q.Exec(ctx, `
		UPDATE backups
		SET last_refresh = $1
		WHERE hashed_backup_id = $2`,
		s.now(), hashBackupID(user.BackupID),
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: add message backup", err)
	}
	if tag.RowsAffected() == 0 {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	return nil
}

// TTLRefresh implements [backups.Store].
func (s *BackupStore) TTLRefresh(ctx context.Context, user backups.AuthenticatedUser) (*backups.StoredAttributes, error) {
	now := s.now()
	q := `
		UPDATE backups
		SET last_refresh = $1
		WHERE hashed_backup_id = $2
		RETURNING hashed_backup_id, backup_dir, media_dir, last_refresh, last_media_refresh, bytes_used, num_objects`
	args := []any{now, hashBackupID(user.BackupID)}
	if user.CredentialType == backups.CredentialTypeMedia {
		q = `
		UPDATE backups
		SET last_refresh = $1, last_media_refresh = $1
		WHERE hashed_backup_id = $2
		RETURNING hashed_backup_id, backup_dir, media_dir, last_refresh, last_media_refresh, bytes_used, num_objects`
	}
	row := s.q.QueryRow(ctx, q, args...)
	attrs, err := scanAttributes(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: ttl refresh", err)
	}
	return attrs, nil
}

// DescribeBackup implements [backups.Store].
func (s *BackupStore) DescribeBackup(ctx context.Context, user backups.AuthenticatedUser) (*backups.Description, error) {
	var bytesUsed int64
	err := s.q.QueryRow(ctx, `
		SELECT bytes_used
		FROM backups
		WHERE hashed_backup_id = $1`,
		hashBackupID(user.BackupID),
	).Scan(&bytesUsed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: describe", err)
	}
	desc := &backups.Description{CDN: 3}
	if user.CredentialType == backups.CredentialTypeMedia {
		desc.MediaUsedSpace = &bytesUsed
	}
	return desc, nil
}

// TrackMedia implements [backups.Store].
func (s *BackupStore) TrackMedia(ctx context.Context, user backups.AuthenticatedUser, countDelta, bytesDelta int64) error {
	tag, err := s.q.Exec(ctx, `
		UPDATE backups
		SET num_objects = GREATEST(num_objects + $1, 0),
		    bytes_used  = GREATEST(bytes_used + $2, 0)
		WHERE hashed_backup_id = $3`,
		countDelta, bytesDelta, hashBackupID(user.BackupID),
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: track media", err)
	}
	if tag.RowsAffected() == 0 {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	return nil
}

// GetMediaUsage implements [backups.Store].
func (s *BackupStore) GetMediaUsage(ctx context.Context, user backups.AuthenticatedUser) (*backups.TimestampedUsageInfo, error) {
	var bytesUsed, numObjects int64
	var recalcAt *time.Time
	err := s.q.QueryRow(ctx, `
		SELECT bytes_used, num_objects, usage_recalc_at
		FROM backups
		WHERE hashed_backup_id = $1`,
		hashBackupID(user.BackupID),
	).Scan(&bytesUsed, &numObjects, &recalcAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: get media usage", err)
	}
	out := &backups.TimestampedUsageInfo{
		Usage: backups.UsageInfo{BytesUsed: bytesUsed, NumObjects: numObjects},
	}
	if recalcAt != nil {
		out.LastRecalculationTime = *recalcAt
	}
	return out, nil
}

// SetMediaUsage implements [backups.Store].
func (s *BackupStore) SetMediaUsage(ctx context.Context, user backups.AuthenticatedUser, usage backups.UsageInfo) error {
	tag, err := s.q.Exec(ctx, `
		UPDATE backups
		SET bytes_used = $1, num_objects = $2, usage_recalc_at = $3
		WHERE hashed_backup_id = $4`,
		usage.BytesUsed, usage.NumObjects, s.now(), hashBackupID(user.BackupID),
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: set media usage", err)
	}
	if tag.RowsAffected() == 0 {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	return nil
}

// SetMediaUsageFor implements [backups.Store] for the worker path.
func (s *BackupStore) SetMediaUsageFor(ctx context.Context, attrs backups.StoredAttributes, usage backups.UsageInfo) error {
	tag, err := s.q.Exec(ctx, `
		UPDATE backups
		SET bytes_used = $1, num_objects = $2, usage_recalc_at = $3
		WHERE hashed_backup_id = $4`,
		usage.BytesUsed, usage.NumObjects, s.now(), attrs.HashedBackupID,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: set media usage for", err)
	}
	if tag.RowsAffected() == 0 {
		return &backups.NotFoundError{}
	}
	return nil
}

// ScheduleBackupDeletion implements [backups.Store]. Rotates the user's
// directories in a single statement, queueing the old backup_dir into
// backups_pending_deletion. Wrapped in a transaction so the pending-row
// insert and the directory rotation either both succeed or neither does.
func (s *BackupStore) ScheduleBackupDeletion(ctx context.Context, user backups.AuthenticatedUser) error {
	hashed := hashBackupID(user.BackupID)
	conn, ok := s.q.(beginner)
	if !ok {
		return signalerrors.New(signalerrors.ErrInternal, "postgres backups: schedule deletion requires a pool-typed Querier")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: begin tx", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingDir string
	var lastRefresh time.Time
	err = tx.QueryRow(ctx, `
		SELECT backup_dir, last_refresh
		FROM backups
		WHERE hashed_backup_id = $1`,
		hashed,
	).Scan(&existingDir, &lastRefresh)
	if errors.Is(err, pgx.ErrNoRows) {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: load for deletion", err)
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO backups_pending_deletion (hashed_backup_id, prefix, last_refresh)
		VALUES ($1, $2, $3)
		ON CONFLICT (hashed_backup_id, prefix) DO NOTHING`,
		hashed, existingDir, lastRefresh,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: queue pending deletion", err)
	}
	if tag.RowsAffected() == 0 {
		return &backups.PendingDeletionError{BackupID: user.BackupID}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE backups
		SET backup_dir = $1,
		    media_dir = $2,
		    bytes_used = 0,
		    num_objects = 0
		WHERE hashed_backup_id = $3`,
		generateDirName(), generateDirName(), hashed,
	); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: rotate dirs", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: commit deletion", err)
	}
	return nil
}

// StartExpiration is a no-op for postgres today (no lease semantics).
// A future change may switch to SELECT … FOR UPDATE SKIP LOCKED to lease
// rows across multiple worker replicas; the no-op default is correct as
// long as a single worker runs.
func (s *BackupStore) StartExpiration(_ context.Context, _ backups.ExpiredBackup) error {
	return nil
}

// FinishExpiration removes the pending-deletion row.
func (s *BackupStore) FinishExpiration(ctx context.Context, expired backups.ExpiredBackup) error {
	if _, err := s.q.Exec(ctx, `
		DELETE FROM backups_pending_deletion
		WHERE hashed_backup_id = $1 AND prefix = $2`,
		expired.HashedBackupID, expired.PrefixToDelete,
	); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: finish expiration", err)
	}
	return nil
}

// ListBackupAttributes streams every row to fn.
func (s *BackupStore) ListBackupAttributes(ctx context.Context, _ int, fn func(backups.StoredAttributes) error) error {
	rows, err := s.q.Query(ctx, `
		SELECT hashed_backup_id, backup_dir, media_dir, last_refresh, last_media_refresh, bytes_used, num_objects
		FROM backups`)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: list attributes", err)
	}
	defer rows.Close()
	for rows.Next() {
		attrs, err := scanAttributesRow(rows)
		if err != nil {
			return err
		}
		if err := fn(*attrs); err != nil {
			return err
		}
	}
	return rows.Err()
}

// GetExpiredBackups streams live + pending-deletion rows to fn.
func (s *BackupStore) GetExpiredBackups(
	ctx context.Context,
	_ int,
	purgeTime time.Time,
	fn func(backups.ExpiredBackup) error,
) error {
	// Live rows with last_refresh < purgeTime.
	rows, err := s.q.Query(ctx, `
		SELECT hashed_backup_id, backup_dir, media_dir, last_refresh, last_media_refresh
		FROM backups
		WHERE last_refresh < $1`,
		purgeTime,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: scan expired", err)
	}
	for rows.Next() {
		var hashed []byte
		var backupDir, mediaDir string
		var lastRefresh, lastMediaRefresh time.Time
		if err := rows.Scan(&hashed, &backupDir, &mediaDir, &lastRefresh, &lastMediaRefresh); err != nil {
			rows.Close()
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: scan expired row", err)
		}
		expType := backups.ExpireMedia
		prefix := backupDir + "/" + mediaDir
		if lastMediaRefresh.Before(purgeTime) {
			expType = backups.ExpireAll
			prefix = backupDir
		}
		if err := fn(backups.ExpiredBackup{
			HashedBackupID: hashed,
			ExpirationType: expType,
			LastRefresh:    lastRefresh,
			PrefixToDelete: prefix,
		}); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Pending-deletion rows always reported as garbage-collection.
	rows, err = s.q.Query(ctx, `
		SELECT hashed_backup_id, prefix, last_refresh
		FROM backups_pending_deletion`)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: scan pending", err)
	}
	defer rows.Close()
	for rows.Next() {
		var hashed []byte
		var prefix string
		var lastRefresh time.Time
		if err := rows.Scan(&hashed, &prefix, &lastRefresh); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: scan pending row", err)
		}
		if err := fn(backups.ExpiredBackup{
			HashedBackupID: hashed,
			ExpirationType: backups.ExpireGarbageCollection,
			LastRefresh:    lastRefresh,
			PrefixToDelete: prefix,
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// beginner is a thin shim around pgx pools / connections that expose Begin.
// The package-level Querier doesn't have Begin, so transactional methods
// type-assert to this interface and bail out cleanly if the caller injected
// a non-pool Querier (e.g. a single-statement test mock).
type beginner interface {
	Querier
	Begin(ctx context.Context) (pgx.Tx, error)
}

// scanAttributes scans a single row into StoredAttributes from a QueryRow.
func scanAttributes(row pgx.Row) (*backups.StoredAttributes, error) {
	var hashed []byte
	var backupDir, mediaDir string
	var lastRefresh, lastMediaRefresh time.Time
	var bytesUsed, numObjects int64
	if err := row.Scan(&hashed, &backupDir, &mediaDir, &lastRefresh, &lastMediaRefresh, &bytesUsed, &numObjects); err != nil {
		return nil, err
	}
	return &backups.StoredAttributes{
		HashedBackupID:   hashed,
		BackupDir:        backupDir,
		MediaDir:         mediaDir,
		LastRefresh:      lastRefresh,
		LastMediaRefresh: lastMediaRefresh,
		BytesUsed:        bytesUsed,
		NumObjects:       numObjects,
	}, nil
}

// scanAttributesRow scans from pgx.Rows.
func scanAttributesRow(rows pgx.Rows) (*backups.StoredAttributes, error) {
	var hashed []byte
	var backupDir, mediaDir string
	var lastRefresh, lastMediaRefresh time.Time
	var bytesUsed, numObjects int64
	if err := rows.Scan(&hashed, &backupDir, &mediaDir, &lastRefresh, &lastMediaRefresh, &bytesUsed, &numObjects); err != nil {
		return nil, err
	}
	return &backups.StoredAttributes{
		HashedBackupID:   hashed,
		BackupDir:        backupDir,
		MediaDir:         mediaDir,
		LastRefresh:      lastRefresh,
		LastMediaRefresh: lastMediaRefresh,
		BytesUsed:        bytesUsed,
		NumObjects:       numObjects,
	}, nil
}

// --- RedeemedReceiptsStore --------------------------------------------------

// RedeemedReceiptsStore is a Postgres-backed implementation of
// [backups.RedeemedReceiptsStore].
type RedeemedReceiptsStore struct {
	q   Querier
	now func() time.Time
}

// NewRedeemedReceiptsStore returns a store backed by c.
func NewRedeemedReceiptsStore(c *Client) *RedeemedReceiptsStore {
	return &RedeemedReceiptsStore{q: c.Pool(), now: func() time.Time { return time.Now().UTC() }}
}

// SetClock overrides the time source. Intended for tests.
func (s *RedeemedReceiptsStore) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// Put implements [backups.RedeemedReceiptsStore].
func (s *RedeemedReceiptsStore) Put(
	ctx context.Context,
	receiptSerial []byte,
	expiration time.Time,
	receiptLevel uint64,
	accountUUID string,
) (bool, error) {
	now := s.now()
	var (
		existingExpiration time.Time
		existingAccount    string
	)
	err := s.q.QueryRow(ctx, `
		SELECT expires_at, account_uuid
		FROM backup_redeemed_receipts
		WHERE receipt_serial = $1`, receiptSerial,
	).Scan(&existingExpiration, &existingAccount)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// First redemption.
	case err != nil:
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: load redeemed receipt", err)
	default:
		if existingExpiration.After(now) {
			return existingAccount == accountUUID, nil
		}
		// Lazy-expire and fall through.
		if _, err := s.q.Exec(ctx,
			`DELETE FROM backup_redeemed_receipts WHERE receipt_serial = $1`,
			receiptSerial,
		); err != nil {
			return false, signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: evict expired receipt", err)
		}
	}

	if _, err := s.q.Exec(ctx, `
		INSERT INTO backup_redeemed_receipts (receipt_serial, expires_at, receipt_level, account_uuid)
		VALUES ($1, $2, $3, $4)`,
		receiptSerial, expiration, int64(receiptLevel), accountUUID,
	); err != nil {
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "postgres backups: insert redeemed receipt", err)
	}
	return true, nil
}
