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

	if account.Number != "" {
		if err := s.kv.Put(ctx, kvByNumberPrefix+account.Number, []byte(account.UUID)); err != nil {
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

	// Update secondary index if the number changed.
	if old.Number != account.Number {
		if old.Number != "" {
			if err := s.kv.Delete(ctx, kvByNumberPrefix+old.Number); err != nil {
				var knf *store.KeyNotFoundError
				if !errors.As(err, &knf) {
					return err
				}
			}
		}
		if account.Number != "" {
			if err := s.kv.Put(ctx, kvByNumberPrefix+account.Number, []byte(account.UUID)); err != nil {
				return err
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

	return nil
}
