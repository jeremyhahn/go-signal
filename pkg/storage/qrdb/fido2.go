//go:build fido2

package qrdb

import (
	"context"
	"encoding/json"
	"errors"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// Key layout:
//
//	fido2:cred:{credentialID}           → JSON FIDO2Credential
//	fido2:cred-by-account:{uuid}:{id}   → "" (presence-only mirror)
//	fido2:session:{sessionID}           → JSON FIDO2Session

const (
	fido2CredPfx          = "fido2:cred:"            //#nosec G101 -- a KV key prefix, not a credential.
	fido2CredByAccountPfx = "fido2:cred-by-account:" //#nosec G101 -- a KV key prefix, not a credential.
	fido2SessionPfx       = "fido2:session:"
)

var _ fido2.FIDO2AccountsStore = (*FIDO2AccountsStore)(nil)

// FIDO2AccountsStore is a qrdb-backed implementation of
// fido2.FIDO2AccountsStore. The type is only compiled under the `fido2`
// build tag so non-FIDO builds don't pull in the dependency.
type FIDO2AccountsStore struct {
	kv KVStore
}

// NewFIDO2AccountsStore returns a store that persists to kv.
func NewFIDO2AccountsStore(kv KVStore) *FIDO2AccountsStore {
	return &FIDO2AccountsStore{kv: kv}
}

func credKey(id string) string { return fido2CredPfx + id }
func credByAccountKey(account, credID string) string {
	return fido2CredByAccountPfx + account + ":" + credID
}
func credByAccountPrefix(account string) string { return fido2CredByAccountPfx + account + ":" }
func sessionKey(id string) string               { return fido2SessionPfx + id }

// CreateCredential persists a new credential, rejecting duplicates.
func (s *FIDO2AccountsStore) CreateCredential(ctx context.Context, cred *fido2.FIDO2Credential) error {
	if cred == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb fido2: nil credential")
	}
	exists, err := s.kv.Exists(ctx, credKey(cred.CredentialID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: exists", err)
	}
	if exists {
		return &fido2.CredentialExistsError{CredentialID: cred.CredentialID}
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: marshal", err)
	}
	if err := s.kv.Put(ctx, credKey(cred.CredentialID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: put cred", err)
	}
	if err := s.kv.Put(ctx, credByAccountKey(cred.AccountUUID, cred.CredentialID), []byte{}); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: put mirror", err)
	}
	return nil
}

// GetCredential retrieves a credential by ID.
func (s *FIDO2AccountsStore) GetCredential(ctx context.Context, credentialID string) (*fido2.FIDO2Credential, error) {
	data, err := getOrNotFound(ctx, s.kv, credKey(credentialID))
	if errors.Is(err, ErrNotFound) {
		return nil, &fido2.CredentialNotFoundError{CredentialID: credentialID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: get cred", err)
	}
	var cred fido2.FIDO2Credential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: unmarshal cred", err)
	}
	return &cred, nil
}

// GetCredentialsByAccount returns every credential for an account.
func (s *FIDO2AccountsStore) GetCredentialsByAccount(ctx context.Context, accountUUID string) ([]*fido2.FIDO2Credential, error) {
	credIDs := make([]string, 0)
	err := s.kv.Scan(ctx, credByAccountPrefix(accountUUID), func(key string, _ []byte) error {
		// key is "fido2:cred-by-account:{uuid}:{credID}"; extract credID.
		prefix := credByAccountPrefix(accountUUID)
		credIDs = append(credIDs, key[len(prefix):])
		return nil
	})
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: scan by account", err)
	}

	out := make([]*fido2.FIDO2Credential, 0, len(credIDs))
	for _, id := range credIDs {
		cred, err := s.GetCredential(ctx, id)
		if err != nil {
			// A missing cred with a stale mirror key is not fatal — skip.
			var nfe *fido2.CredentialNotFoundError
			if errors.As(err, &nfe) {
				continue
			}
			return nil, err
		}
		out = append(out, cred)
	}
	return out, nil
}

// UpdateCredential overwrites an existing credential in place.
func (s *FIDO2AccountsStore) UpdateCredential(ctx context.Context, cred *fido2.FIDO2Credential) error {
	if cred == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb fido2: nil credential")
	}
	exists, err := s.kv.Exists(ctx, credKey(cred.CredentialID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: exists", err)
	}
	if !exists {
		return &fido2.CredentialNotFoundError{CredentialID: cred.CredentialID}
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: marshal", err)
	}
	if err := s.kv.Put(ctx, credKey(cred.CredentialID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: put cred", err)
	}
	return nil
}

// DeleteCredential removes a credential and its per-account mirror.
func (s *FIDO2AccountsStore) DeleteCredential(ctx context.Context, credentialID string) error {
	cred, err := s.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}
	if err := s.kv.Delete(ctx, credKey(credentialID)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: delete cred", err)
	}
	if err := s.kv.Delete(ctx, credByAccountKey(cred.AccountUUID, credentialID)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: delete mirror", err)
	}
	return nil
}

// StoreSession persists a WebAuthn session.
func (s *FIDO2AccountsStore) StoreSession(ctx context.Context, session *fido2.FIDO2Session) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb fido2: nil session")
	}
	data, err := json.Marshal(session)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: marshal session", err)
	}
	if err := s.kv.Put(ctx, sessionKey(session.ID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: put session", err)
	}
	return nil
}

// GetSession retrieves a session by ID.
func (s *FIDO2AccountsStore) GetSession(ctx context.Context, sessionID string) (*fido2.FIDO2Session, error) {
	data, err := getOrNotFound(ctx, s.kv, sessionKey(sessionID))
	if errors.Is(err, ErrNotFound) {
		return nil, &fido2.SessionNotFoundError{SessionID: sessionID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: get session", err)
	}
	var sess fido2.FIDO2Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: unmarshal session", err)
	}
	return &sess, nil
}

// DeleteSession removes a session.
func (s *FIDO2AccountsStore) DeleteSession(ctx context.Context, sessionID string) error {
	exists, err := s.kv.Exists(ctx, sessionKey(sessionID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: exists", err)
	}
	if !exists {
		return &fido2.SessionNotFoundError{SessionID: sessionID}
	}
	if err := s.kv.Delete(ctx, sessionKey(sessionID)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb fido2: delete session", err)
	}
	return nil
}
