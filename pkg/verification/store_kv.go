package verification

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

const kvSessionPrefix = "signal/verification/"

// kvSession is an internal representation that includes the Code field for
// JSON serialization to the KV store. The public VerificationSession uses
// json:"-" on Code which would drop it during marshaling.
type kvSession struct {
	VerificationSession
	Code string `json:"code"`
}

// KVVerificationSessionStore is a KVClient-backed implementation of
// VerificationSessionStore.
type KVVerificationSessionStore struct {
	kv store.KVClient
}

// NewKVVerificationSessionStore returns a new KV-backed session store.
func NewKVVerificationSessionStore(kv store.KVClient) *KVVerificationSessionStore {
	return &KVVerificationSessionStore{kv: kv}
}

// Create stores a new verification session in the KV store.
func (s *KVVerificationSessionStore) Create(ctx context.Context, session *VerificationSession) error {
	data, err := marshalSession(session)
	if err != nil {
		return err
	}
	return s.kv.Put(ctx, kvSessionPrefix+session.ID, data)
}

// Get retrieves a verification session by ID from the KV store.
func (s *KVVerificationSessionStore) Get(ctx context.Context, sessionID string) (*VerificationSession, error) {
	data, err := s.kv.Get(ctx, kvSessionPrefix+sessionID)
	if err != nil {
		if isKeyNotFound(err) {
			return nil, &SessionNotFoundError{SessionID: sessionID}
		}
		return nil, err
	}
	return unmarshalSession(data)
}

// Update replaces an existing verification session in the KV store.
func (s *KVVerificationSessionStore) Update(ctx context.Context, session *VerificationSession) error {
	exists, err := s.kv.Exists(ctx, kvSessionPrefix+session.ID)
	if err != nil {
		return err
	}
	if !exists {
		return &SessionNotFoundError{SessionID: session.ID}
	}
	data, err := marshalSession(session)
	if err != nil {
		return err
	}
	return s.kv.Put(ctx, kvSessionPrefix+session.ID, data)
}

// Delete removes a verification session by ID from the KV store.
func (s *KVVerificationSessionStore) Delete(ctx context.Context, sessionID string) error {
	exists, err := s.kv.Exists(ctx, kvSessionPrefix+sessionID)
	if err != nil {
		return err
	}
	if !exists {
		return &SessionNotFoundError{SessionID: sessionID}
	}
	return s.kv.Delete(ctx, kvSessionPrefix+sessionID)
}

// Count returns the number of sessions currently in the KV store.
func (s *KVVerificationSessionStore) Count(ctx context.Context) (int, error) {
	keys, err := s.kv.List(ctx, kvSessionPrefix)
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

// DeleteExpired removes all sessions from the KV store whose ExpiresAt is in
// the past. It scans the prefix, unmarshals each record, and deletes expired
// entries.
func (s *KVVerificationSessionStore) DeleteExpired(ctx context.Context) error {
	now := time.Now()
	var toDelete []string

	if err := s.kv.Scan(ctx, kvSessionPrefix, func(key string, value []byte) error {
		sess, err := unmarshalSession(value)
		if err != nil {
			// Skip records that cannot be parsed.
			return nil
		}
		if now.After(sess.ExpiresAt) {
			toDelete = append(toDelete, key)
		}
		return nil
	}); err != nil {
		return err
	}

	for _, key := range toDelete {
		if err := s.kv.Delete(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// marshalSession serializes a VerificationSession to JSON, preserving the
// Code field which is tagged json:"-" on the public struct.
func marshalSession(session *VerificationSession) ([]byte, error) {
	kv := kvSession{
		VerificationSession: *session,
		Code:                session.Code,
	}
	return json.Marshal(&kv)
}

// unmarshalSession deserializes a VerificationSession from JSON, restoring
// the Code field.
func unmarshalSession(data []byte) (*VerificationSession, error) {
	var kv kvSession
	if err := json.Unmarshal(data, &kv); err != nil {
		return nil, err
	}
	kv.VerificationSession.Code = kv.Code
	return &kv.VerificationSession, nil
}

// isKeyNotFound checks whether the given error is a store.KeyNotFoundError.
func isKeyNotFound(err error) bool {
	_, ok := err.(*store.KeyNotFoundError)
	return ok
}
