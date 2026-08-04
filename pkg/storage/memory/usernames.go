package memory

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// Compile-time interface satisfaction check.
var _ usernames.UsernameStore = (*MemoryUsernameStore)(nil)

// reservationEntry holds a pending username hash reservation.
type reservationEntry struct {
	uuid      string
	hash      []byte
	token     string
	expiresAt time.Time
}

// reservationTTL is the lifetime of a pending username-hash reservation
// before ConfirmHash rejects it as expired. Mirrors the qrdb backend
// (`pkg/storage/qrdb/usernames.go`) and Java Signal-Server.
const reservationTTL = 5 * time.Minute

// MemoryUsernameStore implements usernames.UsernameStore with in-memory maps.
type MemoryUsernameStore struct {
	mu           sync.RWMutex
	hashToUUID   map[string]string                  // hex(hash) -> UUID (confirmed)
	uuidToHash   map[string][]byte                  // UUID -> hash (confirmed)
	reservations map[string]*reservationEntry       // UUID -> pending reservation
	handleToLink map[string]*usernames.UsernameLink // handle -> link
	uuidToHandle map[string]string                  // UUID -> handle

	// now is injectable so tests can advance the clock without sleeping.
	// Defaults to time.Now. Mirrors the qrdb backend's `s.now` field.
	now func() time.Time
}

// NewMemoryUsernameStore creates a new in-memory username store.
func NewMemoryUsernameStore() *MemoryUsernameStore {
	return &MemoryUsernameStore{
		hashToUUID:   make(map[string]string),
		uuidToHash:   make(map[string][]byte),
		reservations: make(map[string]*reservationEntry),
		handleToLink: make(map[string]*usernames.UsernameLink),
		uuidToHandle: make(map[string]string),
		now:          time.Now,
	}
}

// SetClock overrides the clock used for reservation TTL evaluation. Intended
// for tests; production code should leave the default time.Now in place.
func (s *MemoryUsernameStore) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// ReserveHash attempts to reserve one of the provided username hashes for the
// given account UUID. It selects the first hash that is not already taken and
// returns it along with a reservation token.
func (s *MemoryUsernameStore) ReserveHash(_ context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	// Expire any stale reservation for this UUID.
	if existing, ok := s.reservations[uuid]; ok {
		if now.After(existing.expiresAt) {
			delete(s.reservations, uuid)
		}
	}

	for _, h := range hashes {
		hashKey := hex.EncodeToString(h)

		// Check if hash is already confirmed by another account.
		if ownerUUID, taken := s.hashToUUID[hashKey]; taken && ownerUUID != uuid {
			continue
		}

		// Check if hash is reserved by another account.
		conflict := false
		for resUUID, entry := range s.reservations {
			if resUUID != uuid && hex.EncodeToString(entry.hash) == hashKey && now.Before(entry.expiresAt) {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}

		// Generate reservation token.
		tokenBytes := make([]byte, 16)
		if _, err := rand.Read(tokenBytes); err != nil {
			return nil, "", err
		}
		token := hex.EncodeToString(tokenBytes)

		selectedHash := make([]byte, len(h))
		copy(selectedHash, h)

		s.reservations[uuid] = &reservationEntry{
			uuid:      uuid,
			hash:      selectedHash,
			token:     token,
			expiresAt: now.Add(reservationTTL),
		}

		return selectedHash, token, nil
	}

	return nil, "", &usernames.UsernameHashConflictError{Hash: hashes[0]}
}

// ConfirmHash confirms a previously reserved username hash.
func (s *MemoryUsernameStore) ConfirmHash(_ context.Context, uuid string, hash []byte, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reservation, ok := s.reservations[uuid]
	if !ok {
		return &usernames.InvalidReservationTokenError{UUID: uuid}
	}

	if s.now().After(reservation.expiresAt) {
		delete(s.reservations, uuid)
		return &usernames.InvalidReservationTokenError{UUID: uuid}
	}

	if reservation.token != token {
		return &usernames.InvalidReservationTokenError{UUID: uuid}
	}

	if !bytes.Equal(reservation.hash, hash) {
		return &usernames.InvalidReservationTokenError{UUID: uuid}
	}

	// Remove any previously confirmed hash for this UUID.
	if oldHash, exists := s.uuidToHash[uuid]; exists {
		delete(s.hashToUUID, hex.EncodeToString(oldHash))
	}

	hashKey := hex.EncodeToString(hash)
	confirmedHash := make([]byte, len(hash))
	copy(confirmedHash, hash)

	s.hashToUUID[hashKey] = uuid
	s.uuidToHash[uuid] = confirmedHash
	delete(s.reservations, uuid)

	return nil
}

// LookupByHash returns the account UUID associated with a confirmed username
// hash.
func (s *MemoryUsernameStore) LookupByHash(_ context.Context, hash []byte) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hashKey := hex.EncodeToString(hash)
	uuid, ok := s.hashToUUID[hashKey]
	if !ok {
		return "", &usernames.UsernameNotFoundError{Hash: hash}
	}

	return uuid, nil
}

// DeleteHash removes the confirmed username hash for the given account UUID.
// It is idempotent: deleting a UUID that has no confirmed hash returns nil,
// matching qrdb/postgres semantics.
func (s *MemoryUsernameStore) DeleteHash(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash, ok := s.uuidToHash[uuid]
	if !ok {
		return nil
	}

	delete(s.hashToUUID, hex.EncodeToString(hash))
	delete(s.uuidToHash, uuid)
	delete(s.reservations, uuid)

	return nil
}

// HashForUUID returns the confirmed username hash for an account UUID, or
// *usernames.UsernameNotFoundError when no hash is confirmed. Mirrors the
// Java AccountController#setUsernameLink precondition.
func (s *MemoryUsernameStore) HashForUUID(_ context.Context, uuid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hash, ok := s.uuidToHash[uuid]
	if !ok {
		return nil, &usernames.UsernameNotFoundError{Hash: []byte(uuid)}
	}
	return cloneBytes(hash), nil
}

// LinkForUUID returns the currently published link for an account UUID, or
// *usernames.UsernameLinkNotFoundError when none exists.
func (s *MemoryUsernameStore) LinkForUUID(_ context.Context, uuid string) (*usernames.UsernameLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	handle, ok := s.uuidToHandle[uuid]
	if !ok {
		return nil, &usernames.UsernameLinkNotFoundError{Handle: uuid}
	}
	link := s.handleToLink[handle]
	return &usernames.UsernameLink{
		UUID:               link.UUID,
		UsernameLinkHandle: link.UsernameLinkHandle,
		EncryptedUsername:  cloneBytes(link.EncryptedUsername),
	}, nil
}

// SetLink stores or replaces the username link for the given account.
func (s *MemoryUsernameStore) SetLink(_ context.Context, link *usernames.UsernameLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove any existing link for this UUID.
	if oldHandle, exists := s.uuidToHandle[link.UUID]; exists {
		delete(s.handleToLink, oldHandle)
	}

	stored := &usernames.UsernameLink{
		UUID:               link.UUID,
		UsernameLinkHandle: link.UsernameLinkHandle,
		EncryptedUsername:  cloneBytes(link.EncryptedUsername),
	}

	s.handleToLink[link.UsernameLinkHandle] = stored
	s.uuidToHandle[link.UUID] = link.UsernameLinkHandle

	return nil
}

// GetLink retrieves a username link by its handle UUID.
func (s *MemoryUsernameStore) GetLink(_ context.Context, handle string) (*usernames.UsernameLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	link, ok := s.handleToLink[handle]
	if !ok {
		return nil, &usernames.UsernameLinkNotFoundError{Handle: handle}
	}

	return &usernames.UsernameLink{
		UUID:               link.UUID,
		UsernameLinkHandle: link.UsernameLinkHandle,
		EncryptedUsername:  cloneBytes(link.EncryptedUsername),
	}, nil
}

// DeleteLink removes the username link for the given account UUID. It is
// idempotent: deleting a UUID that has no link returns nil, matching
// qrdb/postgres semantics.
func (s *MemoryUsernameStore) DeleteLink(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	handle, ok := s.uuidToHandle[uuid]
	if !ok {
		return nil
	}

	delete(s.handleToLink, handle)
	delete(s.uuidToHandle, uuid)

	return nil
}

// DeleteExpiredReservations removes every reservation whose TTL has
// elapsed. Returns the number of rows removed.
func (s *MemoryUsernameStore) DeleteExpiredReservations(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for uuid, entry := range s.reservations {
		if now.After(entry.expiresAt) {
			delete(s.reservations, uuid)
			removed++
		}
	}
	return removed, nil
}
