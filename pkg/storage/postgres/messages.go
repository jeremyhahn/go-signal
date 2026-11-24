package postgres

import (
	"context"
	"encoding/json"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// Compile-time interface satisfaction check.
var _ messages.MessageStore = (*MessageStore)(nil)

// MessageStore implements messages.MessageStore as a per-device queue ordered by BIGSERIAL seq, written back to Envelope.ID; expires_at is NULL on insert.
type MessageStore struct {
	q Querier
}

// NewMessageStore constructs a MessageStore backed by the given Querier.
// Pass *pgxpool.Pool for normal use; pass pgx.Tx to participate in an outer
// transaction.
func NewMessageStore(q Querier) *MessageStore {
	return &MessageStore{q: q}
}

// Insert queues envelope and returns its seq, also written to envelope.ID.
func (s *MessageStore) Insert(ctx context.Context, destinationUUID string, destinationDevice uint64, envelope *messages.Envelope) (uint64, error) {
	if envelope == nil {
		return 0, &messages.InvalidArgumentError{Field: "envelope", Message: "nil envelope"}
	}
	if envelope.ServerGUID == "" {
		return 0, &messages.InvalidArgumentError{Field: "serverGuid", Message: "empty server GUID"}
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: marshal", err)
	}

	var seq uint64
	err = s.q.QueryRow(ctx, `
		INSERT INTO messages (account_uuid, device_id, server_guid, envelope)
		VALUES ($1, $2, $3, $4)
		RETURNING seq`,
		destinationUUID,
		destinationDevice,
		envelope.ServerGUID,
		data,
	).Scan(&seq)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: insert", err)
	}

	envelope.ID = seq
	return seq, nil
}

// GetMessagesForDevice retrieves all pending envelopes for a device in
// insertion order (seq ASC).
func (s *MessageStore) GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) ([]*messages.Envelope, error) {
	rows, err := s.q.Query(ctx, `
		SELECT envelope
		FROM messages
		WHERE account_uuid = $1 AND device_id = $2
		ORDER BY seq ASC`,
		destinationUUID,
		destinationDevice,
	)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: query", err)
	}
	defer rows.Close()

	out := make([]*messages.Envelope, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: scan", err)
		}
		var env messages.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: unmarshal", err)
		}
		out = append(out, &env)
	}
	if err := rows.Err(); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: rows", err)
	}
	return out, nil
}

// HasMessagesForDevice checks for a pending envelope with LIMIT 1.
func (s *MessageStore) HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) (bool, error) {
	var exists bool
	err := s.q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM messages
			WHERE account_uuid = $1 AND device_id = $2
			LIMIT 1
		)`,
		destinationUUID, destinationDevice,
	).Scan(&exists)
	if err != nil {
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: has", err)
	}
	return exists, nil
}

// Delete removes the envelope with the given account and GUID, or returns *MessageNotFoundError.
func (s *MessageStore) Delete(ctx context.Context, destinationUUID string, serverGUID string) error {
	tag, err := s.q.Exec(ctx,
		`DELETE FROM messages WHERE account_uuid = $1 AND server_guid = $2`,
		destinationUUID,
		serverGUID,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: delete", err)
	}
	if tag.RowsAffected() == 0 {
		return &messages.MessageNotFoundError{ServerGUID: serverGUID}
	}
	return nil
}

// DeleteForDevice removes every queued message for a specific device.
func (s *MessageStore) DeleteForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) error {
	_, err := s.q.Exec(ctx,
		`DELETE FROM messages WHERE account_uuid = $1 AND device_id = $2`,
		destinationUUID,
		destinationDevice,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: delete for device", err)
	}
	return nil
}

// DeleteForAccount removes every queued message for all devices of an account.
func (s *MessageStore) DeleteForAccount(ctx context.Context, uuid string) error {
	_, err := s.q.Exec(ctx,
		`DELETE FROM messages WHERE account_uuid = $1`,
		uuid,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: delete for account", err)
	}
	return nil
}

// RemoveExpired deletes messages whose expires_at is before cutoff and returns the count; NULL expiries stay.
func (s *MessageStore) RemoveExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.q.Exec(ctx,
		`DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at < $1`,
		before.UTC(),
	)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "postgres messages: remove expired", err)
	}
	return tag.RowsAffected(), nil
}
