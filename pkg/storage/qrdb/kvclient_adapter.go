package qrdb

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

// KVClientAdapter adapts a store.KVClient to satisfy the qrdb KVStore
// interface. The two interfaces share an identical method set; the only
// behavioural gap is Get's missing-key semantics — KVClient returns a
// *store.KeyNotFoundError, KVStore returns (nil, nil). This adapter
// translates the former into the latter so the qrdb-prefixed domain
// stores (e.g. UsernameStore) can run unchanged on any KVClient backend
// — currently the file-system KV in cmd/signald's "file" storage mode.
type KVClientAdapter struct {
	client store.KVClient
}

// NewKVClientAdapter wraps c so it can be passed where a KVStore is
// expected.
func NewKVClientAdapter(c store.KVClient) *KVClientAdapter {
	return &KVClientAdapter{client: c}
}

// Put delegates to the wrapped client.
func (a *KVClientAdapter) Put(ctx context.Context, key string, value []byte) error {
	return a.client.Put(ctx, key, value)
}

// Get returns the value at key, or (nil, nil) when the key is absent —
// matching qrdb KVStore semantics. Other errors propagate unchanged.
func (a *KVClientAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := a.client.Get(ctx, key)
	if err != nil {
		var nf *store.KeyNotFoundError
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

// Delete removes key. Missing keys are not an error (KVStore semantic).
func (a *KVClientAdapter) Delete(ctx context.Context, key string) error {
	err := a.client.Delete(ctx, key)
	if err != nil {
		var nf *store.KeyNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	return nil
}

// Scan delegates to the wrapped client.
func (a *KVClientAdapter) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	return a.client.Scan(ctx, prefix, fn)
}

// List delegates to the wrapped client.
func (a *KVClientAdapter) List(ctx context.Context, prefix string) ([]string, error) {
	return a.client.List(ctx, prefix)
}

// Exists delegates to the wrapped client.
func (a *KVClientAdapter) Exists(ctx context.Context, key string) (bool, error) {
	return a.client.Exists(ctx, key)
}

// Compile-time check.
var _ KVStore = (*KVClientAdapter)(nil)
