package qrdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// Key layout:
//
//	username:confirmed:{hex(hash)} → UUID (who owns this hash)
//	username:byuuid:{uuid}         → hex(hash) (reverse)
//	username:reservation:{uuid}    → JSON reservationEntry
//	username-link:{handle}         → JSON UsernameLink
//	username-link:byuuid:{uuid}    → handle (reverse)
//
// Reservation TTL (5 minutes) matches the memory-backed implementation.
// Expired reservations are not proactively deleted; they are overwritten
// on the next ReserveHash for the same UUID, or (in future work) cleaned
// up by a background worker.

const (
	usernameConfirmedPfx  = "username:confirmed:"
	usernameByUUIDPfx     = "username:byuuid:"
	usernameReservePfx    = "username:reservation:"
	usernameLinkPfx       = "username-link:"
	usernameLinkByUUIDPfx = "username-link:byuuid:"

	reservationTTL = 5 * time.Minute
)

var _ usernames.UsernameStore = (*UsernameStore)(nil)

// reservationEntry is the value stored under a reservation key.
type reservationEntry struct {
	UUID      string    `json:"uuid"`
	Hash      []byte    `json:"hash"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// UsernameStore is a qrdb-backed implementation of usernames.UsernameStore.
type UsernameStore struct {
	kv     KVStore
	now    func() time.Time
	random func([]byte) (int, error)
}

// NewUsernameStore returns a UsernameStore that persists to kv.
func NewUsernameStore(kv KVStore) *UsernameStore {
	return &UsernameStore{kv: kv, now: time.Now, random: rand.Read}
}

// ReserveHash attempts to reserve one of the provided hashes for the account
// UUID. Semantics match MemoryUsernameStore: the first unclaimed candidate
// wins, a reservation token is generated, and the entry expires after
// reservationTTL.
func (s *UsernameStore) ReserveHash(ctx context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	if uuid == "" {
		return nil, "", &usernames.InvalidArgumentError{Field: "uuid", Message: "empty UUID"}
	}
	if len(hashes) == 0 {
		return nil, "", &usernames.InvalidArgumentError{Field: "hashes", Message: "no candidates provided"}
	}

	for _, h := range hashes {
		available, err := s.hashAvailable(ctx, uuid, h)
		if err != nil {
			return nil, "", err
		}
		if !available {
			continue
		}

		token, err := s.newToken()
		if err != nil {
			return nil, "", signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: token", err)
		}
		entry := &reservationEntry{
			UUID:      uuid,
			Hash:      h,
			Token:     token,
			ExpiresAt: s.now().Add(reservationTTL),
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return nil, "", signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: marshal reservation", err)
		}
		if err := s.kv.Put(ctx, usernameReservePfx+uuid, data); err != nil {
			return nil, "", signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: put reservation", err)
		}
		return h, token, nil
	}

	return nil, "", &usernames.UsernameHashConflictError{Hash: hashes[0]}
}

// hashAvailable reports whether a candidate hash is free for this UUID. A
// hash is unavailable when confirmed by a different UUID or actively
// reserved by a different UUID.
func (s *UsernameStore) hashAvailable(ctx context.Context, uuid string, hash []byte) (bool, error) {
	confirmed, err := getOrNotFound(ctx, s.kv, usernameConfirmedPfx+hex.EncodeToString(hash))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get confirmed", err)
	}
	if err == nil && string(confirmed) != uuid {
		return false, nil
	}

	// Reservation conflict check requires a full scan — fine at the volumes
	// reservations see.
	now := s.now()
	conflict := false
	err = s.kv.Scan(ctx, usernameReservePfx, func(key string, value []byte) error {
		var entry reservationEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "unmarshal reservation "+key, err)
		}
		if entry.UUID == uuid {
			return nil
		}
		if now.After(entry.ExpiresAt) {
			return nil
		}
		if hex.EncodeToString(entry.Hash) == hex.EncodeToString(hash) {
			conflict = true
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return !conflict, nil
}

// ConfirmHash promotes a reservation to a confirmed username hash.
func (s *UsernameStore) ConfirmHash(ctx context.Context, uuid string, hash []byte, token string) error {
	data, err := getOrNotFound(ctx, s.kv, usernameReservePfx+uuid)
	if errors.Is(err, ErrNotFound) {
		return &usernames.InvalidReservationTokenError{}
	}
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get reservation", err)
	}

	var entry reservationEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: unmarshal", err)
	}
	if entry.Token != token {
		return &usernames.InvalidReservationTokenError{}
	}
	if hex.EncodeToString(entry.Hash) != hex.EncodeToString(hash) {
		return &usernames.InvalidReservationTokenError{}
	}
	if s.now().After(entry.ExpiresAt) {
		return &usernames.InvalidReservationTokenError{}
	}

	// Replace any prior confirmed hash for this UUID.
	if old, err := getOrNotFound(ctx, s.kv, usernameByUUIDPfx+uuid); err == nil {
		if err := s.kv.Delete(ctx, usernameConfirmedPfx+string(old)); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete old confirmed", err)
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	hexHash := hex.EncodeToString(hash)
	if err := s.kv.Put(ctx, usernameConfirmedPfx+hexHash, []byte(uuid)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: put confirmed", err)
	}
	if err := s.kv.Put(ctx, usernameByUUIDPfx+uuid, []byte(hexHash)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: put byuuid", err)
	}
	if err := s.kv.Delete(ctx, usernameReservePfx+uuid); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete reservation", err)
	}
	return nil
}

// LookupByHash returns the account UUID that owns the given confirmed hash.
func (s *UsernameStore) LookupByHash(ctx context.Context, hash []byte) (string, error) {
	data, err := getOrNotFound(ctx, s.kv, usernameConfirmedPfx+hex.EncodeToString(hash))
	if errors.Is(err, ErrNotFound) {
		return "", &usernames.UsernameNotFoundError{Hash: hash}
	}
	if err != nil {
		return "", signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get confirmed", err)
	}
	return string(data), nil
}

// DeleteHash removes the confirmed hash for an account UUID.
func (s *UsernameStore) DeleteHash(ctx context.Context, uuid string) error {
	data, err := getOrNotFound(ctx, s.kv, usernameByUUIDPfx+uuid)
	if errors.Is(err, ErrNotFound) {
		return nil // idempotent
	}
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get byuuid", err)
	}
	if err := s.kv.Delete(ctx, usernameConfirmedPfx+string(data)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete confirmed", err)
	}
	if err := s.kv.Delete(ctx, usernameByUUIDPfx+uuid); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete byuuid", err)
	}
	return nil
}

// HashForUUID returns the confirmed username hash for an account UUID.
// Returns *usernames.UsernameNotFoundError when none is confirmed.
func (s *UsernameStore) HashForUUID(ctx context.Context, uuid string) ([]byte, error) {
	data, err := getOrNotFound(ctx, s.kv, usernameByUUIDPfx+uuid)
	if errors.Is(err, ErrNotFound) {
		return nil, &usernames.UsernameNotFoundError{Hash: []byte(uuid)}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get byuuid", err)
	}
	// The byuuid value stores hex(hash); decode back to raw bytes.
	hash, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: decode byuuid", err)
	}
	return hash, nil
}

// LinkForUUID returns the currently-published link for an account UUID, or
// *usernames.UsernameLinkNotFoundError when none is stored.
func (s *UsernameStore) LinkForUUID(ctx context.Context, uuid string) (*usernames.UsernameLink, error) {
	handleBytes, err := getOrNotFound(ctx, s.kv, usernameLinkByUUIDPfx+uuid)
	if errors.Is(err, ErrNotFound) {
		return nil, &usernames.UsernameLinkNotFoundError{Handle: uuid}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get link byuuid", err)
	}
	return s.GetLink(ctx, string(handleBytes))
}

// SetLink stores a username link, replacing any previous link for the same
// account UUID.
func (s *UsernameStore) SetLink(ctx context.Context, link *usernames.UsernameLink) error {
	if link == nil {
		return &usernames.InvalidArgumentError{Field: "link", Message: "nil link"}
	}
	if link.UUID == "" || link.UsernameLinkHandle == "" {
		return &usernames.InvalidArgumentError{Field: "link", Message: "missing UUID or handle"}
	}

	// Remove any prior handle for this UUID.
	if old, err := getOrNotFound(ctx, s.kv, usernameLinkByUUIDPfx+link.UUID); err == nil {
		if err := s.kv.Delete(ctx, usernameLinkPfx+string(old)); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete old link", err)
		}
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}

	data, err := json.Marshal(link)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: marshal link", err)
	}
	if err := s.kv.Put(ctx, usernameLinkPfx+link.UsernameLinkHandle, data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: put link", err)
	}
	if err := s.kv.Put(ctx, usernameLinkByUUIDPfx+link.UUID, []byte(link.UsernameLinkHandle)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: put link byuuid", err)
	}
	return nil
}

// GetLink retrieves a link by its handle.
func (s *UsernameStore) GetLink(ctx context.Context, handle string) (*usernames.UsernameLink, error) {
	data, err := getOrNotFound(ctx, s.kv, usernameLinkPfx+handle)
	if errors.Is(err, ErrNotFound) {
		return nil, &usernames.UsernameLinkNotFoundError{Handle: handle}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get link", err)
	}
	var link usernames.UsernameLink
	if err := json.Unmarshal(data, &link); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: unmarshal link", err)
	}
	return &link, nil
}

// DeleteLink removes the link for an account UUID.
func (s *UsernameStore) DeleteLink(ctx context.Context, uuid string) error {
	data, err := getOrNotFound(ctx, s.kv, usernameLinkByUUIDPfx+uuid)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: get link byuuid", err)
	}
	if err := s.kv.Delete(ctx, usernameLinkPfx+string(data)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete link", err)
	}
	if err := s.kv.Delete(ctx, usernameLinkByUUIDPfx+uuid); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete link byuuid", err)
	}
	return nil
}

func (s *UsernameStore) newToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := s.random(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// DeleteExpiredReservations removes every reservation whose TTL has
// elapsed. Returns the number of rows removed.
func (s *UsernameStore) DeleteExpiredReservations(ctx context.Context) (int, error) {
	now := s.now()
	var doomed []string
	if err := s.kv.Scan(ctx, usernameReservePfx, func(key string, value []byte) error {
		var entry reservationEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "unmarshal reservation "+key, err)
		}
		if now.After(entry.ExpiresAt) {
			doomed = append(doomed, key)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	removed := 0
	for _, key := range doomed {
		if err := s.kv.Delete(ctx, key); err != nil {
			return removed, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb usernames: delete expired "+key, err)
		}
		removed++
	}
	return removed, nil
}
