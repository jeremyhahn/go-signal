//go:build fido2

package fido2

import (
	"context"
	"encoding/json"
	"errors"
	"path"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

const (
	kvPrefixCredentials    = "signal/fido2/creds/"
	kvPrefixCredsByAccount = "signal/fido2/creds/by-account/"
	kvPrefixSessions       = "signal/fido2/sessions/"
)

// KVFIDO2AccountsStore is a KV-backed implementation of FIDO2AccountsStore.
type KVFIDO2AccountsStore struct {
	kv store.KVClient
}

// NewKVFIDO2AccountsStore returns a new KV-backed FIDO2AccountsStore.
func NewKVFIDO2AccountsStore(kv store.KVClient) *KVFIDO2AccountsStore {
	return &KVFIDO2AccountsStore{kv: kv}
}

// CreateCredential stores a new FIDO2 credential with a secondary index by
// account UUID.
func (s *KVFIDO2AccountsStore) CreateCredential(ctx context.Context, cred *FIDO2Credential) error {
	credKey := credentialKey(cred.CredentialID)

	exists, err := s.kv.Exists(ctx, credKey)
	if err != nil {
		return err
	}
	if exists {
		return &CredentialExistsError{CredentialID: cred.CredentialID}
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}

	if err := s.kv.Put(ctx, credKey, data); err != nil {
		return err
	}

	indexKey := accountCredentialKey(cred.AccountUUID, cred.CredentialID)
	return s.kv.Put(ctx, indexKey, []byte(cred.CredentialID))
}

// GetCredential retrieves a credential by its unique identifier.
func (s *KVFIDO2AccountsStore) GetCredential(ctx context.Context, credentialID string) (*FIDO2Credential, error) {
	data, err := s.kv.Get(ctx, credentialKey(credentialID))
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &CredentialNotFoundError{CredentialID: credentialID}
		}
		return nil, err
	}

	cred := &FIDO2Credential{}
	if err := json.Unmarshal(data, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// GetCredentialsByAccount returns all credentials registered to the given
// account by listing the secondary index and fetching each credential.
func (s *KVFIDO2AccountsStore) GetCredentialsByAccount(ctx context.Context, accountUUID string) ([]*FIDO2Credential, error) {
	prefix := accountCredentialPrefix(accountUUID)
	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return []*FIDO2Credential{}, nil
	}

	result := make([]*FIDO2Credential, 0, len(keys))
	for _, indexKey := range keys {
		credIDBytes, err := s.kv.Get(ctx, indexKey)
		if err != nil {
			return nil, err
		}

		cred, err := s.GetCredential(ctx, string(credIDBytes))
		if err != nil {
			return nil, err
		}
		result = append(result, cred)
	}
	return result, nil
}

// UpdateCredential overwrites an existing credential.
func (s *KVFIDO2AccountsStore) UpdateCredential(ctx context.Context, cred *FIDO2Credential) error {
	credKey := credentialKey(cred.CredentialID)

	exists, err := s.kv.Exists(ctx, credKey)
	if err != nil {
		return err
	}
	if !exists {
		return &CredentialNotFoundError{CredentialID: cred.CredentialID}
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return s.kv.Put(ctx, credKey, data)
}

// DeleteCredential removes a credential and its secondary index entry.
func (s *KVFIDO2AccountsStore) DeleteCredential(ctx context.Context, credentialID string) error {
	// Fetch the credential first to get the account UUID for index cleanup.
	cred, err := s.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}

	if err := s.kv.Delete(ctx, credentialKey(credentialID)); err != nil {
		return err
	}

	indexKey := accountCredentialKey(cred.AccountUUID, credentialID)
	// Best-effort index cleanup; the primary entry is already removed.
	_ = s.kv.Delete(ctx, indexKey)

	return nil
}

// StoreSession persists a WebAuthn ceremony session.
func (s *KVFIDO2AccountsStore) StoreSession(ctx context.Context, session *FIDO2Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return s.kv.Put(ctx, sessionKey(session.ID), data)
}

// GetSession retrieves a session by its unique identifier.
func (s *KVFIDO2AccountsStore) GetSession(ctx context.Context, sessionID string) (*FIDO2Session, error) {
	data, err := s.kv.Get(ctx, sessionKey(sessionID))
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &SessionNotFoundError{SessionID: sessionID}
		}
		return nil, err
	}

	session := &FIDO2Session{}
	if err := json.Unmarshal(data, session); err != nil {
		return nil, err
	}
	return session, nil
}

// DeleteSession removes a session by its unique identifier.
func (s *KVFIDO2AccountsStore) DeleteSession(ctx context.Context, sessionID string) error {
	err := s.kv.Delete(ctx, sessionKey(sessionID))
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return &SessionNotFoundError{SessionID: sessionID}
		}
		return err
	}
	return nil
}

// credentialKey returns the KV key for a credential.
func credentialKey(credentialID string) string {
	return kvPrefixCredentials + credentialID
}

// accountCredentialPrefix returns the KV prefix for all credentials belonging
// to the given account.
func accountCredentialPrefix(accountUUID string) string {
	return kvPrefixCredsByAccount + accountUUID + "/"
}

// accountCredentialKey returns the KV key for a specific credential in the
// account secondary index.
func accountCredentialKey(accountUUID, credentialID string) string {
	return path.Join(kvPrefixCredsByAccount+accountUUID, credentialID)
}

// sessionKey returns the KV key for a session.
func sessionKey(sessionID string) string {
	return kvPrefixSessions + sessionID
}
