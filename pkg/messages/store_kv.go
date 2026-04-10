package messages

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync/atomic"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

const kvMessagePrefix = "signal/messages/"

// KVMessageStore implements MessageStore using a KVClient backend.
type KVMessageStore struct {
	kv    store.KVClient
	idSeq atomic.Uint64
}

// NewKVMessageStore returns a new KVMessageStore backed by the given KVClient.
func NewKVMessageStore(kv store.KVClient) *KVMessageStore {
	return &KVMessageStore{kv: kv}
}

// Insert persists a new message envelope for delivery.
func (s *KVMessageStore) Insert(ctx context.Context, destinationUUID string, destinationDevice uint64, envelope *Envelope) (uint64, error) {
	id := s.idSeq.Add(1)
	envelope.ID = id

	did := strconv.FormatUint(destinationDevice, 10)
	key := kvMessagePrefix + destinationUUID + "/" + did + "/" + envelope.ServerGUID

	data, err := json.Marshal(envelope)
	if err != nil {
		return 0, &InvalidArgumentError{Field: "envelope", Message: "failed to marshal: " + err.Error()}
	}

	if err := s.kv.Put(ctx, key, data); err != nil {
		return 0, err
	}

	return id, nil
}

// GetMessagesForDevice retrieves all pending messages for a specific device.
func (s *KVMessageStore) GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) ([]*Envelope, error) {
	did := strconv.FormatUint(destinationDevice, 10)
	prefix := kvMessagePrefix + destinationUUID + "/" + did + "/"

	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	envelopes := make([]*Envelope, 0, len(keys))
	for _, k := range keys {
		data, err := s.kv.Get(ctx, k)
		if err != nil {
			var knf *store.KeyNotFoundError
			if errors.As(err, &knf) {
				continue
			}
			return nil, err
		}
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, err
		}
		envelopes = append(envelopes, &env)
	}

	return envelopes, nil
}

// Delete removes a specific message by destination UUID and server GUID.
func (s *KVMessageStore) Delete(ctx context.Context, destinationUUID string, serverGUID string) error {
	prefix := kvMessagePrefix + destinationUUID + "/"

	var found bool
	err := s.kv.Scan(ctx, prefix, func(key string, value []byte) error {
		var env Envelope
		if err := json.Unmarshal(value, &env); err != nil {
			return err
		}
		if env.ServerGUID == serverGUID {
			found = true
			return s.kv.Delete(ctx, key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return &MessageNotFoundError{ServerGUID: serverGUID}
	}
	return nil
}

// DeleteForDevice removes all messages for a specific device.
func (s *KVMessageStore) DeleteForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) error {
	did := strconv.FormatUint(destinationDevice, 10)
	prefix := kvMessagePrefix + destinationUUID + "/" + did + "/"
	return s.deleteByPrefix(ctx, prefix)
}

// DeleteForAccount removes all messages for an entire account.
func (s *KVMessageStore) DeleteForAccount(ctx context.Context, uuid string) error {
	prefix := kvMessagePrefix + uuid + "/"
	return s.deleteByPrefix(ctx, prefix)
}

// deleteByPrefix lists and deletes all keys with the given prefix.
func (s *KVMessageStore) deleteByPrefix(ctx context.Context, prefix string) error {
	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.kv.Delete(ctx, k); err != nil {
			var knf *store.KeyNotFoundError
			if errors.As(err, &knf) {
				continue
			}
			return err
		}
	}
	return nil
}
