package qrdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// Key layout:
//
//	msg:{uuid}:{device}:{seq}     → JSON Envelope (per-device queue, ordered
//	                                  lexicographically by seq so scans are
//	                                  in insertion order)
//	msg:byguid:{uuid}:{guid}      → "{uuid}/{device}/{seq}" (mirror used by
//	                                  Delete-by-GUID)
//
// seq is a zero-padded uint64 assigned monotonically by the process. Across
// instances it is not globally monotonic, which is fine — consumers only
// need insertion order within a single (uuid, device) queue, and the
// server's ServerTimestamp field is the authoritative ordering signal for
// cross-instance scenarios once that pathway exists.

const (
	messageKeyPrefix  = "msg:"
	messageGUIDPrefix = "msg:byguid:"
)

var _ messages.MessageStore = (*MessageStore)(nil)

// MessageStore is a qrdb-backed implementation of messages.MessageStore.
type MessageStore struct {
	kv  KVStore
	seq atomic.Uint64
}

// NewMessageStore returns a MessageStore that persists to kv.
func NewMessageStore(kv KVStore) *MessageStore { return &MessageStore{kv: kv} }

func messageKey(uuid string, device uint64, seq uint64) string {
	return fmt.Sprintf("%s%s:%d:%020d", messageKeyPrefix, uuid, device, seq)
}
func messageGUIDKey(uuid, guid string) string {
	return fmt.Sprintf("%s%s:%s", messageGUIDPrefix, uuid, guid)
}
func messageDevicePrefix(uuid string, device uint64) string {
	return fmt.Sprintf("%s%s:%d:", messageKeyPrefix, uuid, device)
}
func messageAccountPrefix(uuid string) string {
	return fmt.Sprintf("%s%s:", messageKeyPrefix, uuid)
}

// Insert appends a message to the per-device queue. Returns the assigned
// sequence number, which callers surface to clients as the internal
// message ID.
func (s *MessageStore) Insert(ctx context.Context, destinationUUID string, destinationDevice uint64, envelope *messages.Envelope) (uint64, error) {
	if envelope == nil {
		return 0, &messages.InvalidArgumentError{Field: "envelope", Message: "nil envelope"}
	}
	if envelope.ServerGUID == "" {
		return 0, &messages.InvalidArgumentError{Field: "serverGuid", Message: "empty server GUID"}
	}

	seq := s.seq.Add(1)
	envelope.ID = seq

	data, err := json.Marshal(envelope)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: marshal", err)
	}

	primaryKey := messageKey(destinationUUID, destinationDevice, seq)
	if err := s.kv.Put(ctx, primaryKey, data); err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: put", err)
	}
	// Mirror for Delete-by-GUID: store the full primary key so Delete can
	// round-trip directly without reconstructing.
	if err := s.kv.Put(ctx, messageGUIDKey(destinationUUID, envelope.ServerGUID), []byte(primaryKey)); err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: put guid mirror", err)
	}
	return seq, nil
}

// GetMessagesForDevice returns all pending envelopes for a device in
// insertion order.
func (s *MessageStore) GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) ([]*messages.Envelope, error) {
	out := make([]*messages.Envelope, 0)
	err := s.kv.Scan(ctx, messageDevicePrefix(destinationUUID, destinationDevice), func(key string, value []byte) error {
		var env messages.Envelope
		if err := json.Unmarshal(value, &env); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "unmarshal "+key, err)
		}
		out = append(out, &env)
		return nil
	})
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: scan", err)
	}
	return out, nil
}

// HasMessagesForDevice reports whether any pending envelope exists
// for the device. Uses a Scan with an early-exit sentinel so the
// underlying KV store stops iterating after the first match — a
// device with 10K pending envelopes still pays only one read here.
// The prior implementation used List which materialised every
// matching key into a slice just to compare len > 0.
func (s *MessageStore) HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) (bool, error) {
	found := false
	err := s.kv.Scan(ctx, messageDevicePrefix(destinationUUID, destinationDevice), func(_ string, _ []byte) error {
		found = true
		return errStopScan
	})
	if err != nil && !errors.Is(err, errStopScan) {
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: scan", err)
	}
	return found, nil
}

// Delete removes a single envelope identified by server GUID.
func (s *MessageStore) Delete(ctx context.Context, destinationUUID string, serverGUID string) error {
	primaryKey, err := getOrNotFound(ctx, s.kv, messageGUIDKey(destinationUUID, serverGUID))
	if errors.Is(err, ErrNotFound) {
		return &messages.MessageNotFoundError{ServerGUID: serverGUID}
	}
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: lookup guid", err)
	}
	if err := s.kv.Delete(ctx, string(primaryKey)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: delete primary", err)
	}
	if err := s.kv.Delete(ctx, messageGUIDKey(destinationUUID, serverGUID)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: delete mirror", err)
	}
	return nil
}

// DeleteForDevice removes every message queued for a specific device.
func (s *MessageStore) DeleteForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) error {
	prefix := messageDevicePrefix(destinationUUID, destinationDevice)
	return s.deletePrefix(ctx, prefix, destinationUUID)
}

// DeleteForAccount removes every message for an account across all devices.
func (s *MessageStore) DeleteForAccount(ctx context.Context, uuid string) error {
	prefix := messageAccountPrefix(uuid)
	return s.deletePrefix(ctx, prefix, uuid)
}

// RemoveExpired is a no-op for the qrdb backend: the envelope JSON stored
// today carries no expires_at field, so there is nothing to sweep. The
// method exists to satisfy [messages.MessageStore] and lets the sweep
// worker run uniformly against every backend.
func (s *MessageStore) RemoveExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

// deletePrefix removes every primary-key message under prefix and the
// matching GUID mirrors. The mirrors are cleaned up by unmarshaling each
// envelope to recover its ServerGUID — simpler than tracking a reverse
// locator.
func (s *MessageStore) deletePrefix(ctx context.Context, prefix, uuid string) error {
	toDelete := make([]string, 0)
	guids := make([]string, 0)
	err := s.kv.Scan(ctx, prefix, func(key string, value []byte) error {
		toDelete = append(toDelete, key)
		var env messages.Envelope
		if err := json.Unmarshal(value, &env); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "unmarshal "+key, err)
		}
		if env.ServerGUID != "" {
			guids = append(guids, env.ServerGUID)
		}
		return nil
	})
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: scan", err)
	}
	for _, key := range toDelete {
		if err := s.kv.Delete(ctx, key); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: delete primary", err)
		}
	}
	for _, guid := range guids {
		if err := s.kv.Delete(ctx, messageGUIDKey(uuid, guid)); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb messages: delete mirror", err)
		}
	}
	return nil
}
