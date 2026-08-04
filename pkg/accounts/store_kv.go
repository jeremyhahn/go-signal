package accounts

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

const (
	kvAccountPrefix  = "signal/accounts/"
	kvByNumberPrefix = "signal/accounts/by-number/"
	kvByPNIPrefix    = "signal/accounts/by-pni/"
)

// KVAccountStore implements AccountStore using a KVClient backend.
type KVAccountStore struct {
	kv store.KVClient
}

// NewKVAccountStore returns a new KVAccountStore backed by the given KVClient.
func NewKVAccountStore(kv store.KVClient) *KVAccountStore {
	return &KVAccountStore{kv: kv}
}

// Create persists a new account and its phone-number index.
func (s *KVAccountStore) Create(ctx context.Context, account *Account) error {
	key := kvAccountPrefix + account.UUID
	exists, err := s.kv.Exists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return &AccountAlreadyExistsError{Identifier: account.UUID}
	}

	data, err := json.Marshal(account)
	if err != nil {
		return &InvalidArgumentError{Field: "account", Message: "failed to marshal: " + err.Error()}
	}

	if err := s.kv.Put(ctx, key, data); err != nil {
		return err
	}

	// Write the secondary indexes. If any write fails, roll back the records
	// already written so a partial failure cannot leave the primary record
	// reachable by UUID but missing from the by-number/by-PNI indexes.
	if account.Number != "" {
		if err := s.kv.Put(ctx, kvByNumberPrefix+account.Number, []byte(account.UUID)); err != nil {
			_ = s.kv.Delete(ctx, key)
			return err
		}
	}
	if account.PNI != "" {
		if err := s.kv.Put(ctx, kvByPNIPrefix+account.PNI, []byte(account.UUID)); err != nil {
			_ = s.kv.Delete(ctx, key)
			if account.Number != "" {
				_ = s.kv.Delete(ctx, kvByNumberPrefix+account.Number)
			}
			return err
		}
	}

	return nil
}

// Get retrieves an account by UUID.
func (s *KVAccountStore) Get(ctx context.Context, uuid string) (*Account, error) {
	data, err := s.kv.Get(ctx, kvAccountPrefix+uuid)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &AccountNotFoundError{Identifier: uuid}
		}
		return nil, err
	}

	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, &InvalidArgumentError{Field: "account", Message: "failed to unmarshal: " + err.Error()}
	}
	return &account, nil
}

// GetByNumber retrieves an account by phone number using the secondary index.
func (s *KVAccountStore) GetByNumber(ctx context.Context, number string) (*Account, error) {
	uuidBytes, err := s.kv.Get(ctx, kvByNumberPrefix+number)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &AccountNotFoundError{Identifier: number}
		}
		return nil, err
	}

	return s.Get(ctx, string(uuidBytes))
}

// GetByPNI retrieves an account by its Phone Number Identity UUID via
// the secondary index.
func (s *KVAccountStore) GetByPNI(ctx context.Context, pni string) (*Account, error) {
	uuidBytes, err := s.kv.Get(ctx, kvByPNIPrefix+pni)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &AccountNotFoundError{Identifier: pni}
		}
		return nil, err
	}
	return s.Get(ctx, string(uuidBytes))
}

// Update persists changes to an existing account.
func (s *KVAccountStore) Update(ctx context.Context, account *Account) error {
	key := kvAccountPrefix + account.UUID
	exists, err := s.kv.Exists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return &AccountNotFoundError{Identifier: account.UUID}
	}

	// Read the old account to check if the number changed.
	oldData, err := s.kv.Get(ctx, key)
	if err != nil {
		return err
	}
	var old Account
	if err := json.Unmarshal(oldData, &old); err != nil {
		return &InvalidArgumentError{Field: "account", Message: "failed to unmarshal old account: " + err.Error()}
	}

	data, err := json.Marshal(account)
	if err != nil {
		return &InvalidArgumentError{Field: "account", Message: "failed to marshal: " + err.Error()}
	}

	if err := s.kv.Put(ctx, key, data); err != nil {
		return err
	}

	// rollback fully reconstructs the pre-update state — the primary record AND
	// both secondary indexes — from the old account snapshot. It is invoked on
	// any secondary-index failure so a partial write cannot leave the account
	// reachable by UUID but mis-indexed by number/PNI (or vice versa). It is
	// best-effort: rollback errors are ignored since there is nothing further
	// to do without a transactional KV.
	rollback := func() {
		_ = s.kv.Put(ctx, key, oldData)
		if old.Number != "" {
			_ = s.kv.Put(ctx, kvByNumberPrefix+old.Number, []byte(old.UUID))
		}
		if old.PNI != "" {
			_ = s.kv.Put(ctx, kvByPNIPrefix+old.PNI, []byte(old.UUID))
		}
		// Remove index entries that belong only to the (now-aborted) new state.
		if account.Number != old.Number && account.Number != "" {
			_ = s.kv.Delete(ctx, kvByNumberPrefix+account.Number)
		}
		if account.PNI != old.PNI && account.PNI != "" {
			_ = s.kv.Delete(ctx, kvByPNIPrefix+account.PNI)
		}
	}

	// Update the number index if it changed. Write the new entry BEFORE
	// deleting the old one so a mid-sequence failure never leaves the number
	// with no index at all.
	if old.Number != account.Number {
		if account.Number != "" {
			if err := s.kv.Put(ctx, kvByNumberPrefix+account.Number, []byte(account.UUID)); err != nil {
				rollback()
				return err
			}
		}
		if old.Number != "" {
			if err := s.kv.Delete(ctx, kvByNumberPrefix+old.Number); err != nil {
				var knf *store.KeyNotFoundError
				if !errors.As(err, &knf) {
					rollback()
					return err
				}
			}
		}
	}

	// Update the PNI index on change (number-change flows regenerate PNI),
	// new-before-old for the same reason.
	if old.PNI != account.PNI {
		if account.PNI != "" {
			if err := s.kv.Put(ctx, kvByPNIPrefix+account.PNI, []byte(account.UUID)); err != nil {
				rollback()
				return err
			}
		}
		if old.PNI != "" {
			if err := s.kv.Delete(ctx, kvByPNIPrefix+old.PNI); err != nil {
				var knf *store.KeyNotFoundError
				if !errors.As(err, &knf) {
					rollback()
					return err
				}
			}
		}
	}

	return nil
}

// Delete removes an account by UUID and its phone-number index.
func (s *KVAccountStore) Delete(ctx context.Context, uuid string) error {
	key := kvAccountPrefix + uuid

	data, err := s.kv.Get(ctx, key)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return &AccountNotFoundError{Identifier: uuid}
		}
		return err
	}

	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return &InvalidArgumentError{Field: "account", Message: "failed to unmarshal: " + err.Error()}
	}

	if err := s.kv.Delete(ctx, key); err != nil {
		return err
	}

	if account.Number != "" {
		if err := s.kv.Delete(ctx, kvByNumberPrefix+account.Number); err != nil {
			var knf *store.KeyNotFoundError
			if !errors.As(err, &knf) {
				return err
			}
		}
	}
	if account.PNI != "" {
		if err := s.kv.Delete(ctx, kvByPNIPrefix+account.PNI); err != nil {
			var knf *store.KeyNotFoundError
			if !errors.As(err, &knf) {
				return err
			}
		}
	}

	return nil
}

// ListAll iterates every primary account record under the KV's
// kvAccountPrefix, decoding the JSON payload and yielding to fn. The
// secondary-index entries under kvByNumberPrefix / kvByPNIPrefix are
// nested inside the same root prefix so we filter them out here.
func (s *KVAccountStore) ListAll(ctx context.Context, fn func(*Account) error) error {
	return s.kv.Scan(ctx, kvAccountPrefix, func(key string, value []byte) error {
		// Skip secondary-index entries — those live under nested
		// prefixes ("signal/accounts/by-number/" etc.).
		if len(key) > len(kvAccountPrefix) {
			suffix := key[len(kvAccountPrefix):]
			for i := 0; i < len(suffix); i++ {
				if suffix[i] == '/' {
					return nil
				}
			}
		}
		var acct Account
		if err := json.Unmarshal(value, &acct); err != nil {
			return err
		}
		return fn(&acct)
	})
}
