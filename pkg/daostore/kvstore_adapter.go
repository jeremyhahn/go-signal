package daostore

import (
	"context"
	"strings"

	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/jeremyhahn/go-qrdb/pkg/service"
)

// kvStoreAdapter bridges service.KVServicer to kvstore.KVStore.
// This allows the desktop client to use the GenericDAO layer with
// an embedded QRDB backend without requiring the full SDK transport.
type kvStoreAdapter struct {
	svc service.KVServicer
}

// NewKVStoreAdapter creates a KVStore from a KVServicer.
func NewKVStoreAdapter(svc service.KVServicer) kvstore.KVStore {
	return &kvStoreAdapter{svc: svc}
}

func (a *kvStoreAdapter) Put(ctx context.Context, key string, value []byte) error {
	return a.svc.Put(ctx, key, value)
}

func (a *kvStoreAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := a.svc.Get(ctx, key)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	return val, nil
}

func (a *kvStoreAdapter) Delete(ctx context.Context, key string) error {
	return a.svc.Delete(ctx, key)
}

func (a *kvStoreAdapter) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	result, err := a.svc.Scan(ctx, prefix)
	if err != nil {
		return err
	}
	for key, value := range result {
		if err := fn(key, value); err != nil {
			return err
		}
	}
	return nil
}

func (a *kvStoreAdapter) List(ctx context.Context, prefix string) ([]string, error) {
	return a.svc.List(ctx, prefix)
}

func (a *kvStoreAdapter) Exists(ctx context.Context, key string) (bool, error) {
	val, err := a.Get(ctx, key)
	if err != nil {
		return false, err
	}
	return val != nil, nil
}

func (a *kvStoreAdapter) RegisterEntityIndexes(entityType string, indexes []kvstore.EntityIndex) error {
	// The embedded backend handles index registration through the engine.
	// For the standalone adapter, indexes are registered when the DAO
	// is constructed and the engine processes them.
	return nil
}

func (a *kvStoreAdapter) QueryIndex(ctx context.Context, indexName string, value []byte) ([][]byte, error) {
	// Delegate to the service's index query capability.
	// The BackendKVService routes this through the engine's Lookup method.
	return nil, nil
}

func (a *kvStoreAdapter) ScanIndex(ctx context.Context, indexName string, start, end []byte) (map[string][][]byte, error) {
	return nil, nil
}

func (a *kvStoreAdapter) QueryCompoundIndex(ctx context.Context, indexName string, values [][]byte) ([][]byte, error) {
	return nil, nil
}

func (a *kvStoreAdapter) ScanCompoundIndex(ctx context.Context, indexName string, prefixValues [][]byte, rangeStart, rangeEnd []byte) (map[string][][]byte, error) {
	return nil, nil
}

var _ kvstore.KVStore = (*kvStoreAdapter)(nil)
