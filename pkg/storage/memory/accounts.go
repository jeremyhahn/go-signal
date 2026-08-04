// Package memory provides in-memory storage backends for unit testing.
package memory

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// Compile-time interface satisfaction check.
var _ accounts.AccountStore = (*MemoryAccountStore)(nil)

// MemoryAccountStore implements accounts.AccountStore with in-memory maps.
type MemoryAccountStore struct {
	mu       sync.RWMutex
	byUUID   map[string]*accounts.Account
	byNumber map[string]string // number -> UUID (ACI)
	byPNI    map[string]string // PNI -> UUID (ACI)
}

// NewMemoryAccountStore creates a new in-memory account store.
func NewMemoryAccountStore() *MemoryAccountStore {
	return &MemoryAccountStore{
		byUUID:   make(map[string]*accounts.Account),
		byNumber: make(map[string]string),
		byPNI:    make(map[string]string),
	}
}

// Create persists a new account.
func (s *MemoryAccountStore) Create(_ context.Context, account *accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byUUID[account.UUID]; exists {
		return &accounts.AccountAlreadyExistsError{Identifier: account.UUID}
	}

	if account.Number != "" {
		if existingUUID, exists := s.byNumber[account.Number]; exists {
			return &accounts.AccountAlreadyExistsError{Identifier: existingUUID}
		}
	}

	if account.PNI != "" {
		if existingUUID, exists := s.byPNI[account.PNI]; exists {
			return &accounts.AccountAlreadyExistsError{Identifier: existingUUID}
		}
	}

	stored := cloneAccount(account)
	s.byUUID[stored.UUID] = stored
	if stored.Number != "" {
		s.byNumber[stored.Number] = stored.UUID
	}
	if stored.PNI != "" {
		s.byPNI[stored.PNI] = stored.UUID
	}

	return nil
}

// Get retrieves an account by UUID.
func (s *MemoryAccountStore) Get(_ context.Context, uuid string) (*accounts.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	acct, exists := s.byUUID[uuid]
	if !exists {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}

	return cloneAccount(acct), nil
}

// GetByNumber retrieves an account by phone number.
func (s *MemoryAccountStore) GetByNumber(_ context.Context, number string) (*accounts.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uuid, exists := s.byNumber[number]
	if !exists {
		return nil, &accounts.AccountNotFoundError{Identifier: number}
	}

	acct, exists := s.byUUID[uuid]
	if !exists {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}

	return cloneAccount(acct), nil
}

// GetByPNI retrieves an account by its Phone Number Identity UUID.
func (s *MemoryAccountStore) GetByPNI(_ context.Context, pni string) (*accounts.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uuid, exists := s.byPNI[pni]
	if !exists {
		return nil, &accounts.AccountNotFoundError{Identifier: pni}
	}
	acct, exists := s.byUUID[uuid]
	if !exists {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}
	return cloneAccount(acct), nil
}

// Update persists changes to an existing account.
//
// Optimistic locking: the incoming account.Version must be exactly one greater
// than the version currently stored. If not, a *accounts.VersionConflictError
// is returned so callers can retry their read-modify-write cycle.
func (s *MemoryAccountStore) Update(_ context.Context, account *accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.byUUID[account.UUID]
	if !exists {
		return &accounts.AccountNotFoundError{Identifier: account.UUID}
	}

	// Enforce optimistic concurrency: the caller must have read version N and
	// submitted version N+1. Any other value indicates a lost update.
	if account.Version != existing.Version+1 {
		return &accounts.VersionConflictError{
			AccountUUID:     account.UUID,
			ExpectedVersion: existing.Version + 1,
			ActualVersion:   account.Version,
		}
	}

	if existing.Number != account.Number {
		if existing.Number != "" {
			delete(s.byNumber, existing.Number)
		}
		if account.Number != "" {
			if otherUUID, taken := s.byNumber[account.Number]; taken && otherUUID != account.UUID {
				return &accounts.AccountAlreadyExistsError{Identifier: otherUUID}
			}
			s.byNumber[account.Number] = account.UUID
		}
	}

	// Maintain the PNI index. A PNI change (e.g. number-change flow)
	// updates the mirror; an unset-then-set PNI is treated as creation.
	if existing.PNI != account.PNI {
		if existing.PNI != "" {
			delete(s.byPNI, existing.PNI)
		}
		if account.PNI != "" {
			if otherUUID, taken := s.byPNI[account.PNI]; taken && otherUUID != account.UUID {
				return &accounts.AccountAlreadyExistsError{Identifier: otherUUID}
			}
			s.byPNI[account.PNI] = account.UUID
		}
	}

	s.byUUID[account.UUID] = cloneAccount(account)
	return nil
}

// Delete removes an account by UUID.
func (s *MemoryAccountStore) Delete(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acct, exists := s.byUUID[uuid]
	if !exists {
		return &accounts.AccountNotFoundError{Identifier: uuid}
	}

	if acct.Number != "" {
		delete(s.byNumber, acct.Number)
	}
	if acct.PNI != "" {
		delete(s.byPNI, acct.PNI)
	}
	delete(s.byUUID, uuid)

	return nil
}

// ListAll streams every stored account to fn.
func (s *MemoryAccountStore) ListAll(ctx context.Context, fn func(*accounts.Account) error) error {
	s.mu.RLock()
	snapshot := make([]*accounts.Account, 0, len(s.byUUID))
	for _, a := range s.byUUID {
		snapshot = append(snapshot, cloneAccount(a))
	}
	s.mu.RUnlock()
	for _, a := range snapshot {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(a); err != nil {
			return err
		}
	}
	return nil
}

// cloneAccount returns a deep copy of an account.
func cloneAccount(a *accounts.Account) *accounts.Account {
	clone := *a

	clone.IdentityKey = cloneBytes(a.IdentityKey)
	clone.PhoneNumberIdentityKey = cloneBytes(a.PhoneNumberIdentityKey)
	clone.UnidentifiedAccessKey = cloneBytes(a.UnidentifiedAccessKey)
	clone.UsernameHash = cloneBytes(a.UsernameHash)

	if a.Devices != nil {
		clone.Devices = make([]accounts.Device, len(a.Devices))
		for i := range a.Devices {
			clone.Devices[i] = cloneDevice(&a.Devices[i])
		}
	}

	return &clone
}

// cloneDevice returns a deep copy of a device.
func cloneDevice(d *accounts.Device) accounts.Device {
	clone := *d
	if d.AuthTokenHash != nil {
		// SaltedTokenHash contains only string fields, so a value copy is sufficient
		// for full isolation between the original and the clone.
		h := *d.AuthTokenHash
		clone.AuthTokenHash = &h
	}
	if d.SignedPreKey != nil {
		spk := *d.SignedPreKey
		spk.PublicKey = cloneBytes(d.SignedPreKey.PublicKey)
		spk.Signature = cloneBytes(d.SignedPreKey.Signature)
		clone.SignedPreKey = &spk
	}
	if d.KyberPreKey != nil {
		kpk := *d.KyberPreKey
		kpk.PublicKey = cloneBytes(d.KyberPreKey.PublicKey)
		kpk.Signature = cloneBytes(d.KyberPreKey.Signature)
		clone.KyberPreKey = &kpk
	}
	return clone
}

// cloneBytes returns a copy of a byte slice, or nil if the input is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
