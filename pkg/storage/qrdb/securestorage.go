package qrdb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
)

// Key layout:
//
//	ss:{accountUUID}:manifest      → JSON StorageManifest
//	ss:{accountUUID}:item:{b64key} → JSON StorageItem
//
// Item keys are client-supplied bytes; we base64-encode them to keep them
// safe to use inside key strings (they may contain binary / non-printable
// bytes). DeleteAll scans "ss:{accountUUID}:" to clear everything.

const (
	secureStoragePrefix = "ss:"
	manifestSuffix      = ":manifest"
	itemInfix           = ":item:"
)

var _ securestorage.ManifestStore = (*SecureStorageStore)(nil)

// SecureStorageStore is a qrdb-backed implementation of
// securestorage.ManifestStore.
type SecureStorageStore struct {
	kv KVStore
}

// NewSecureStorageStore returns a store that persists to kv.
func NewSecureStorageStore(kv KVStore) *SecureStorageStore {
	return &SecureStorageStore{kv: kv}
}

func manifestKey(accountUUID string) string {
	return secureStoragePrefix + accountUUID + manifestSuffix
}
func itemKey(accountUUID string, key []byte) string {
	return secureStoragePrefix + accountUUID + itemInfix + base64.RawURLEncoding.EncodeToString(key)
}
func accountPrefix(accountUUID string) string {
	return secureStoragePrefix + accountUUID + ":"
}

// GetManifest retrieves the current manifest.
func (s *SecureStorageStore) GetManifest(ctx context.Context, accountUUID string) (*securestorage.StorageManifest, error) {
	data, err := getOrNotFound(ctx, s.kv, manifestKey(accountUUID))
	if errors.Is(err, ErrNotFound) {
		return nil, &securestorage.ManifestNotFoundError{AccountUUID: accountUUID}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: get manifest", err)
	}
	var m securestorage.StorageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: unmarshal manifest", err)
	}
	return &m, nil
}

// PutManifest stores a new manifest. Rejects writes whose version is not
// strictly greater than the stored version.
func (s *SecureStorageStore) PutManifest(ctx context.Context, accountUUID string, m *securestorage.StorageManifest) error {
	if m == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb ss: nil manifest")
	}

	existing, err := s.GetManifest(ctx, accountUUID)
	var notFound *securestorage.ManifestNotFoundError
	if err != nil && !errors.As(err, &notFound) {
		return err
	}
	if existing != nil && m.Version <= existing.Version {
		return &securestorage.ManifestVersionConflictError{
			AccountUUID:      accountUUID,
			StoredVersion:    existing.Version,
			SubmittedVersion: m.Version,
		}
	}

	data, err := json.Marshal(m)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: marshal manifest", err)
	}
	if err := s.kv.Put(ctx, manifestKey(accountUUID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: put manifest", err)
	}
	return nil
}

// GetItem retrieves an item by key.
func (s *SecureStorageStore) GetItem(ctx context.Context, accountUUID string, key []byte) (*securestorage.StorageItem, error) {
	data, err := getOrNotFound(ctx, s.kv, itemKey(accountUUID, key))
	if errors.Is(err, ErrNotFound) {
		return nil, &securestorage.StorageItemNotFoundError{AccountUUID: accountUUID, Key: key}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: get item", err)
	}
	var item securestorage.StorageItem
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: unmarshal item", err)
	}
	return &item, nil
}

// PutItem stores an item, overwriting any previously stored value.
func (s *SecureStorageStore) PutItem(ctx context.Context, accountUUID string, item *securestorage.StorageItem) error {
	if item == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb ss: nil item")
	}
	data, err := json.Marshal(item)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: marshal item", err)
	}
	if err := s.kv.Put(ctx, itemKey(accountUUID, item.Key), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: put item", err)
	}
	return nil
}

// DeleteItem removes an item. Returns NotFound when the key is absent.
func (s *SecureStorageStore) DeleteItem(ctx context.Context, accountUUID string, key []byte) error {
	exists, err := s.kv.Exists(ctx, itemKey(accountUUID, key))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: exists item", err)
	}
	if !exists {
		return &securestorage.StorageItemNotFoundError{AccountUUID: accountUUID, Key: key}
	}
	if err := s.kv.Delete(ctx, itemKey(accountUUID, key)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: delete item", err)
	}
	return nil
}

// DeleteAll removes manifest and all items for the account.
func (s *SecureStorageStore) DeleteAll(ctx context.Context, accountUUID string) error {
	keys, err := s.kv.List(ctx, accountPrefix(accountUUID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: list", err)
	}
	for _, key := range keys {
		if err := s.kv.Delete(ctx, key); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb ss: delete "+key, err)
		}
	}
	return nil
}
