package qrdb

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Key layout: account:{uuid} -> JSON Account; account:by-number:{e164} -> UUID (a mirror key, not a qrdb secondary index).

// Key prefixes: the "_primary" segment keeps a primary scan clear of the by-number and by-PNI mirror keys.
const (
	accountByNumberPfx = "account:by-number:"
	accountByPNIPfx    = "account:by-pni:"
	accountPrimaryScan = "account:_primary:"
)

// Compile-time interface satisfaction check.
var _ accounts.AccountStore = (*AccountStore)(nil)

// AccountStore is a qrdb-backed implementation of accounts.AccountStore.
type AccountStore struct {
	kv KVStore
}

// NewAccountStore returns an AccountStore that persists to kv.
func NewAccountStore(kv KVStore) *AccountStore {
	return &AccountStore{kv: kv}
}

func accountKey(uuid string) string         { return accountPrimaryScan + uuid }
func accountNumberKey(number string) string { return accountByNumberPfx + number }
func accountPNIKey(pni string) string       { return accountByPNIPfx + pni }

// Create stores a new account with unique UUID and number, writing the primary key before the mirror so a retry repairs a partial write.
func (s *AccountStore) Create(ctx context.Context, account *accounts.Account) error {
	if account == nil {
		return &accounts.InvalidArgumentError{Field: "account", Message: "nil account"}
	}
	if account.UUID == "" {
		return &accounts.InvalidArgumentError{Field: "uuid", Message: "empty UUID"}
	}

	exists, err := s.kv.Exists(ctx, accountKey(account.UUID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: exists", err)
	}
	if exists {
		return &accounts.AccountAlreadyExistsError{Identifier: account.UUID}
	}

	if account.Number != "" {
		existingUUID, err := s.lookupUUIDByNumber(ctx, account.Number)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil {
			return &accounts.AccountAlreadyExistsError{Identifier: existingUUID}
		}
	}
	if account.PNI != "" {
		existingUUID, err := s.lookupUUIDByPNI(ctx, account.PNI)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil {
			return &accounts.AccountAlreadyExistsError{Identifier: existingUUID}
		}
	}

	data, err := json.Marshal(account)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: marshal", err)
	}

	if err := s.kv.Put(ctx, accountKey(account.UUID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: put primary", err)
	}

	if account.Number != "" {
		if err := s.kv.Put(ctx, accountNumberKey(account.Number), []byte(account.UUID)); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: put mirror", err)
		}
	}
	if account.PNI != "" {
		if err := s.kv.Put(ctx, accountPNIKey(account.PNI), []byte(account.UUID)); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: put pni mirror", err)
		}
	}

	return nil
}

// Get retrieves an account by UUID.
func (s *AccountStore) Get(ctx context.Context, uuid string) (*accounts.Account, error) {
	data, err := getOrNotFound(ctx, s.kv, accountKey(uuid))
	if errors.Is(err, ErrNotFound) {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: get", err)
	}

	var acct accounts.Account
	if err := json.Unmarshal(data, &acct); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: unmarshal", err)
	}
	return &acct, nil
}

// GetByNumber retrieves an account by phone number via the mirror index.
func (s *AccountStore) GetByNumber(ctx context.Context, number string) (*accounts.Account, error) {
	uuid, err := s.lookupUUIDByNumber(ctx, number)
	if errors.Is(err, ErrNotFound) {
		return nil, &accounts.AccountNotFoundError{Identifier: number}
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, uuid)
}

// GetByPNI retrieves an account by its Phone Number Identity UUID via the
// PNI mirror index.
func (s *AccountStore) GetByPNI(ctx context.Context, pni string) (*accounts.Account, error) {
	uuid, err := s.lookupUUIDByPNI(ctx, pni)
	if errors.Is(err, ErrNotFound) {
		return nil, &accounts.AccountNotFoundError{Identifier: pni}
	}
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, uuid)
}

// Update stores account when its Version is exactly one above the stored one, maintaining the number mirror.
func (s *AccountStore) Update(ctx context.Context, account *accounts.Account) error {
	if account == nil {
		return &accounts.InvalidArgumentError{Field: "account", Message: "nil account"}
	}

	existing, err := s.Get(ctx, account.UUID)
	if err != nil {
		return err
	}

	if account.Version != existing.Version+1 {
		return &accounts.VersionConflictError{
			AccountUUID:     account.UUID,
			ExpectedVersion: existing.Version + 1,
			ActualVersion:   account.Version,
		}
	}

	// Phone-number change requires mirror maintenance.
	if existing.Number != account.Number {
		if account.Number != "" {
			otherUUID, err := s.lookupUUIDByNumber(ctx, account.Number)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil && otherUUID != account.UUID {
				return &accounts.AccountAlreadyExistsError{Identifier: otherUUID}
			}
		}
		if existing.Number != "" {
			if err := s.kv.Delete(ctx, accountNumberKey(existing.Number)); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: delete old mirror", err)
			}
		}
		if account.Number != "" {
			if err := s.kv.Put(ctx, accountNumberKey(account.Number), []byte(account.UUID)); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: put mirror", err)
			}
		}
	}

	// PNI change requires the same mirror maintenance as phone number
	// changes. Number-change flows regenerate the PNI so this path fires
	// alongside the number branch above.
	if existing.PNI != account.PNI {
		if account.PNI != "" {
			otherUUID, err := s.lookupUUIDByPNI(ctx, account.PNI)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil && otherUUID != account.UUID {
				return &accounts.AccountAlreadyExistsError{Identifier: otherUUID}
			}
		}
		if existing.PNI != "" {
			if err := s.kv.Delete(ctx, accountPNIKey(existing.PNI)); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: delete old pni mirror", err)
			}
		}
		if account.PNI != "" {
			if err := s.kv.Put(ctx, accountPNIKey(account.PNI), []byte(account.UUID)); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: put pni mirror", err)
			}
		}
	}

	data, err := json.Marshal(account)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: marshal", err)
	}
	if err := s.kv.Put(ctx, accountKey(account.UUID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: put primary", err)
	}
	return nil
}

// Delete removes an account and its phone-number mirror (if any).
func (s *AccountStore) Delete(ctx context.Context, uuid string) error {
	existing, err := s.Get(ctx, uuid)
	if err != nil {
		return err
	}

	if existing.Number != "" {
		if err := s.kv.Delete(ctx, accountNumberKey(existing.Number)); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: delete mirror", err)
		}
	}
	if existing.PNI != "" {
		if err := s.kv.Delete(ctx, accountPNIKey(existing.PNI)); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: delete pni mirror", err)
		}
	}

	if err := s.kv.Delete(ctx, accountKey(uuid)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: delete primary", err)
	}
	return nil
}

// ListAll iterates every primary account record and yields a decoded
// *accounts.Account to fn.
func (s *AccountStore) ListAll(ctx context.Context, fn func(*accounts.Account) error) error {
	return s.kv.Scan(ctx, accountPrimaryScan, func(_ string, value []byte) error {
		var acct accounts.Account
		if err := json.Unmarshal(value, &acct); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb accounts: unmarshal", err)
		}
		return fn(&acct)
	})
}

// lookupUUIDByNumber returns the UUID indexed by a phone-number mirror key,
// or ErrNotFound when no mirror exists.
func (s *AccountStore) lookupUUIDByNumber(ctx context.Context, number string) (string, error) {
	data, err := getOrNotFound(ctx, s.kv, accountNumberKey(number))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// lookupUUIDByPNI returns the UUID indexed by a PNI mirror key, or
// ErrNotFound when no mirror exists.
func (s *AccountStore) lookupUUIDByPNI(ctx context.Context, pni string) (string, error) {
	data, err := getOrNotFound(ctx, s.kv, accountPNIKey(pni))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
