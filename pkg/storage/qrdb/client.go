package qrdb

import (
	"context"
	"errors"

	qrdbkv "github.com/jeremyhahn/go-qrdb/pkg/kvstore"
)

// KVStore is the subset of qrdb's kvstore.KVStore that go-signal's domain
// stores rely on. Narrowing the dependency to these methods keeps the API
// surface testable and avoids coupling to qrdb's index-registration APIs that
// are not needed for current lookup patterns.
type KVStore interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error
	List(ctx context.Context, prefix string) ([]string, error)
	Exists(ctx context.Context, key string) (bool, error)
}

// Compile-time check: qrdb's kvstore.KVStore satisfies our narrower KVStore
// interface. If this ever breaks, the qrdb dep has changed shape and the
// domain stores need attention.
var _ KVStore = (qrdbkv.KVStore)(nil)

// ErrNotFound is returned when a key is absent from the underlying store.
// Domain stores map this to their own not-found error types before returning
// to callers.
var ErrNotFound = errors.New("qrdb: key not found")

// getOrNotFound is a small helper used by the domain stores: qrdb's Get
// returns (nil, nil) for missing keys, which is inconvenient. This wrapper
// converts a missing key into ErrNotFound so callers can branch cleanly.
func getOrNotFound(ctx context.Context, kv KVStore, key string) ([]byte, error) {
	v, err := kv.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, ErrNotFound
	}
	return v, nil
}
