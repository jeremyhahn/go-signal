package qrdb

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

// Compile-time interface satisfaction check.
var _ recoverypassword.Store = (*RecoveryPasswordStore)(nil)

// recoveryPasswordKeyPrefix prefixes every stored entry. The full key is
// `signal:rrp:<pni>` (PNI as canonical UUID string), matching the stable
// "domain:resource:identifier" pattern used by the other qrdb stores.
// #nosec G101 -- key prefix, not a credential.
const recoveryPasswordKeyPrefix = "signal:rrp:"

// recoveryPasswordEntry is the value persisted under each key. JSON keeps
// the on-disk form human-debuggable, the volume is low (one row per account),
// and read-side parsing is trivial.
type recoveryPasswordEntry struct {
	Hash      string    `json:"hash"`
	Salt      string    `json:"salt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// RecoveryPasswordStore is a qrdb-backed implementation of
// recoverypassword.Store.
type RecoveryPasswordStore struct {
	kv  KVStore
	now func() time.Time
}

// NewRecoveryPasswordStore returns a store that persists to kv.
func NewRecoveryPasswordStore(kv KVStore) *RecoveryPasswordStore {
	return &RecoveryPasswordStore{kv: kv, now: time.Now}
}

// SetClock overrides the clock used for expiry checks. Intended for tests.
func (s *RecoveryPasswordStore) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *RecoveryPasswordStore) key(pni string) string {
	return recoveryPasswordKeyPrefix + pni
}

// Get returns the recovery password hash for pni, or NotFoundError when the
// key is absent or the entry has expired. Expired rows are eagerly deleted
// so the caller observes the same idempotent semantics as the memory store.
func (s *RecoveryPasswordStore) Get(ctx context.Context, pni string) (*recoverypassword.SaltedTokenHash, error) {
	data, err := getOrNotFound(ctx, s.kv, s.key(pni))
	if errors.Is(err, ErrNotFound) {
		return nil, &recoverypassword.NotFoundError{PNI: pni}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb recoverypassword: get", err)
	}

	var entry recoveryPasswordEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb recoverypassword: unmarshal", err)
	}
	if !s.now().Before(entry.ExpiresAt) {
		// Best-effort cleanup of the expired row; the surfaced error is the
		// not-found result regardless.
		_ = s.kv.Delete(ctx, s.key(pni))
		return nil, &recoverypassword.NotFoundError{PNI: pni}
	}
	return &recoverypassword.SaltedTokenHash{Hash: entry.Hash, Salt: entry.Salt}, nil
}

// Put inserts or replaces the entry for pni.
func (s *RecoveryPasswordStore) Put(ctx context.Context, pni string, hash *recoverypassword.SaltedTokenHash, expiresAt time.Time) error {
	if hash == nil {
		return &recoverypassword.InvalidArgumentError{Field: "hash", Message: "must not be nil"}
	}
	entry := recoveryPasswordEntry{
		Hash:      hash.Hash,
		Salt:      hash.Salt,
		ExpiresAt: expiresAt,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb recoverypassword: marshal", err)
	}
	if err := s.kv.Put(ctx, s.key(pni), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb recoverypassword: put", err)
	}
	return nil
}

// Delete removes the entry for pni. Idempotent.
func (s *RecoveryPasswordStore) Delete(ctx context.Context, pni string) error {
	if err := s.kv.Delete(ctx, s.key(pni)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb recoverypassword: delete", err)
	}
	return nil
}
