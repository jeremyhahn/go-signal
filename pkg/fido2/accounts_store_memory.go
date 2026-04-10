//go:build fido2

package fido2

import (
	"context"
	"sync"
)

// MemoryFIDO2AccountsStore is a thread-safe in-memory implementation of
// FIDO2AccountsStore suitable for tests and standalone operation.
type MemoryFIDO2AccountsStore struct {
	mu             sync.RWMutex
	credentials    map[string]*FIDO2Credential    // credentialID -> credential
	credsByAccount map[string]map[string]struct{} // accountUUID -> set of credentialIDs
	sessions       map[string]*FIDO2Session       // sessionID -> session
}

// NewMemoryFIDO2AccountsStore returns a new in-memory FIDO2AccountsStore.
func NewMemoryFIDO2AccountsStore() *MemoryFIDO2AccountsStore {
	return &MemoryFIDO2AccountsStore{
		credentials:    make(map[string]*FIDO2Credential),
		credsByAccount: make(map[string]map[string]struct{}),
		sessions:       make(map[string]*FIDO2Session),
	}
}

// CreateCredential stores a new FIDO2 credential.
func (m *MemoryFIDO2AccountsStore) CreateCredential(_ context.Context, cred *FIDO2Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.credentials[cred.CredentialID]; exists {
		return &CredentialExistsError{CredentialID: cred.CredentialID}
	}

	m.credentials[cred.CredentialID] = deepCopyCredential(cred)

	if m.credsByAccount[cred.AccountUUID] == nil {
		m.credsByAccount[cred.AccountUUID] = make(map[string]struct{})
	}
	m.credsByAccount[cred.AccountUUID][cred.CredentialID] = struct{}{}

	return nil
}

// GetCredential retrieves a credential by its unique identifier.
func (m *MemoryFIDO2AccountsStore) GetCredential(_ context.Context, credentialID string) (*FIDO2Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cred, ok := m.credentials[credentialID]
	if !ok {
		return nil, &CredentialNotFoundError{CredentialID: credentialID}
	}

	return deepCopyCredential(cred), nil
}

// GetCredentialsByAccount returns all credentials registered to the given account.
func (m *MemoryFIDO2AccountsStore) GetCredentialsByAccount(_ context.Context, accountUUID string) ([]*FIDO2Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids, ok := m.credsByAccount[accountUUID]
	if !ok || len(ids) == 0 {
		return []*FIDO2Credential{}, nil
	}

	result := make([]*FIDO2Credential, 0, len(ids))
	for id := range ids {
		cred, exists := m.credentials[id]
		if !exists {
			continue
		}
		result = append(result, deepCopyCredential(cred))
	}
	return result, nil
}

// UpdateCredential overwrites an existing credential.
func (m *MemoryFIDO2AccountsStore) UpdateCredential(_ context.Context, cred *FIDO2Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.credentials[cred.CredentialID]; !ok {
		return &CredentialNotFoundError{CredentialID: cred.CredentialID}
	}

	m.credentials[cred.CredentialID] = deepCopyCredential(cred)
	return nil
}

// DeleteCredential removes a credential by its unique identifier.
func (m *MemoryFIDO2AccountsStore) DeleteCredential(_ context.Context, credentialID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cred, ok := m.credentials[credentialID]
	if !ok {
		return &CredentialNotFoundError{CredentialID: credentialID}
	}

	// Clean up the secondary index.
	if acctSet, exists := m.credsByAccount[cred.AccountUUID]; exists {
		delete(acctSet, credentialID)
		if len(acctSet) == 0 {
			delete(m.credsByAccount, cred.AccountUUID)
		}
	}

	delete(m.credentials, credentialID)
	return nil
}

// StoreSession persists a WebAuthn ceremony session.
func (m *MemoryFIDO2AccountsStore) StoreSession(_ context.Context, session *FIDO2Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[session.ID] = deepCopySession(session)
	return nil
}

// GetSession retrieves a session by its unique identifier.
func (m *MemoryFIDO2AccountsStore) GetSession(_ context.Context, sessionID string) (*FIDO2Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return nil, &SessionNotFoundError{SessionID: sessionID}
	}

	return deepCopySession(session), nil
}

// DeleteSession removes a session by its unique identifier.
func (m *MemoryFIDO2AccountsStore) DeleteSession(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[sessionID]; !ok {
		return &SessionNotFoundError{SessionID: sessionID}
	}
	delete(m.sessions, sessionID)
	return nil
}

// deepCopyCredential returns a deep copy of the given credential by copying
// all fields and cloning byte slices and string slices.
func deepCopyCredential(src *FIDO2Credential) *FIDO2Credential {
	dst := *src
	dst.PublicKey = cloneBytes(src.PublicKey)
	dst.AAGUID = cloneBytes(src.AAGUID)
	if src.Transport != nil {
		dst.Transport = make([]string, len(src.Transport))
		copy(dst.Transport, src.Transport)
	}
	return &dst
}

// deepCopySession returns a deep copy of the given session by copying all
// fields and cloning byte slices.
func deepCopySession(src *FIDO2Session) *FIDO2Session {
	dst := *src
	dst.Challenge = cloneBytes(src.Challenge)
	dst.SessionData = cloneBytes(src.SessionData)
	return &dst
}

// cloneBytes returns a copy of the given byte slice, or nil if the input is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}
