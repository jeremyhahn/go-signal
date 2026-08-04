package qrdb

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// Key layout: verification:{sessionID} → JSON VerificationSession.
const verificationKeyPrefix = "verification:"

// timeNow is swappable for tests; callers use it instead of time.Now().
// Tests that mutate this var must NOT call t.Parallel(), since concurrent
// swap/restore races against itself and against any reader. Use a per-test
// save+restore guarded by serial test execution.
var timeNow = time.Now

var _ verification.VerificationSessionStore = (*VerificationSessionStore)(nil)

// VerificationSessionStore is a qrdb-backed implementation of
// verification.VerificationSessionStore.
type VerificationSessionStore struct {
	kv KVStore
}

// NewVerificationSessionStore returns a store that persists to kv.
func NewVerificationSessionStore(kv KVStore) *VerificationSessionStore {
	return &VerificationSessionStore{kv: kv}
}

func verificationKey(sessionID string) string { return verificationKeyPrefix + sessionID }

// Create stores a new verification session. Returns an error if a session
// already exists at the same ID.
func (s *VerificationSessionStore) Create(ctx context.Context, session *verification.VerificationSession) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb verification: nil session")
	}
	if session.ID == "" {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb verification: empty session ID")
	}

	exists, err := s.kv.Exists(ctx, verificationKey(session.ID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: exists", err)
	}
	if exists {
		return signalerrors.New(signalerrors.ErrAlreadyExists, "qrdb verification: session already exists: "+session.ID)
	}

	return s.put(ctx, session)
}

// Get retrieves a session by ID.
func (s *VerificationSessionStore) Get(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	data, err := getOrNotFound(ctx, s.kv, verificationKey(sessionID))
	if errors.Is(err, ErrNotFound) {
		return nil, &verification.SessionNotFoundError{SessionID: sessionID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: get", err)
	}

	var sess verification.VerificationSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: unmarshal", err)
	}
	return &sess, nil
}

// Update replaces an existing session.
func (s *VerificationSessionStore) Update(ctx context.Context, session *verification.VerificationSession) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb verification: nil session")
	}
	exists, err := s.kv.Exists(ctx, verificationKey(session.ID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: exists", err)
	}
	if !exists {
		return &verification.SessionNotFoundError{SessionID: session.ID}
	}
	return s.put(ctx, session)
}

// Delete removes a session by ID.
func (s *VerificationSessionStore) Delete(ctx context.Context, sessionID string) error {
	exists, err := s.kv.Exists(ctx, verificationKey(sessionID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: exists", err)
	}
	if !exists {
		return &verification.SessionNotFoundError{SessionID: sessionID}
	}
	if err := s.kv.Delete(ctx, verificationKey(sessionID)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: delete", err)
	}
	return nil
}

// Count returns the number of sessions currently stored.
func (s *VerificationSessionStore) Count(ctx context.Context) (int, error) {
	keys, err := s.kv.List(ctx, verificationKeyPrefix)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: list", err)
	}
	return len(keys), nil
}

// DeleteExpired removes every session whose ExpiresAt is before now. It
// scans the full prefix and issues one Delete per expired entry; for high
// session counts a native-index approach would scale better, but at the
// volumes verification sessions see (bounded by rate limits) this is fine.
func (s *VerificationSessionStore) DeleteExpired(ctx context.Context) error {
	now := timeNow()
	keys, err := s.kv.List(ctx, verificationKeyPrefix)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: list", err)
	}
	for _, key := range keys {
		data, err := getOrNotFound(ctx, s.kv, key)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: get "+key, err)
		}
		var sess verification.VerificationSession
		if err := json.Unmarshal(data, &sess); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: unmarshal "+key, err)
		}
		if sess.ExpiresAt.Before(now) {
			if err := s.kv.Delete(ctx, key); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: delete "+key, err)
			}
		}
	}
	return nil
}

func (s *VerificationSessionStore) put(ctx context.Context, session *verification.VerificationSession) error {
	data, err := json.Marshal(session)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: marshal", err)
	}
	if err := s.kv.Put(ctx, verificationKey(session.ID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb verification: put", err)
	}
	return nil
}
