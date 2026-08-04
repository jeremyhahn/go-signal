package daostore

import (
	"context"
	"path/filepath"
	"strings"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-qrdb/pkg/engine"
	"github.com/jeremyhahn/go-qrdb/pkg/index"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/jeremyhahn/go-qrdb/pkg/storage"
	pebble "github.com/jeremyhahn/go-qrdb/pkg/storage/pebble"
)

// NewEmbeddedKVStore creates an in-process QRDB KVStore backed by PebbleDB.
// This uses PebbleDB storage directly with KVEngine for index management.
func NewEmbeddedKVStore(dataDir string) (kvstore.KVStore, error) {
	pebbleCfg := pebble.DefaultConfig(filepath.Join(dataDir, "pebble"))
	stg, err := pebble.New(pebbleCfg)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "create pebble storage", err)
	}

	eng := engine.NewKVEngine(stg)

	return &engineKVStoreAdapter{
		stg:    stg,
		engine: eng,
	}, nil
}

type engineKVStoreAdapter struct {
	stg    storage.Storage
	engine *engine.KVEngine
}

func (a *engineKVStoreAdapter) Put(_ context.Context, key string, value []byte) error {
	return a.engine.PutWithIndexes([]byte(key), value)
}

func (a *engineKVStoreAdapter) Get(_ context.Context, key string) ([]byte, error) {
	val, err := a.stg.Get([]byte(key))
	if err != nil {
		return nil, nil
	}
	return val, nil
}

func (a *engineKVStoreAdapter) Delete(_ context.Context, key string) error {
	return a.engine.DeleteWithIndexes([]byte(key))
}

func (a *engineKVStoreAdapter) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	prefixBytes := []byte(prefix)
	opts := &storage.IteratorOptions{}
	if len(prefixBytes) > 0 {
		opts.LowerBound = prefixBytes
		opts.UpperBound = incrementPrefixBytes(prefixBytes)
	}
	iter := a.stg.NewIterator(opts)
	defer func() { _ = iter.Close() }()

	for iter.SeekToFirst(); iter.Valid(); iter.Next() {
		key := iter.Key()
		if !hasBytePrefix(key, prefixBytes) {
			break
		}
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		valCopy := make([]byte, len(iter.Value()))
		copy(valCopy, iter.Value())
		if err := fn(string(keyCopy), valCopy); err != nil {
			return err
		}
	}
	return iter.Error()
}

func (a *engineKVStoreAdapter) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	err := a.Scan(ctx, prefix, func(key string, _ []byte) error {
		keys = append(keys, key)
		return nil
	})
	return keys, err
}

func (a *engineKVStoreAdapter) Exists(_ context.Context, key string) (bool, error) {
	return a.stg.Exists([]byte(key))
}

func (a *engineKVStoreAdapter) RegisterEntityIndexes(entityType string, indexes []kvstore.EntityIndex) error {
	engineIndexes := make([]engine.EntityIndex, len(indexes))
	for i, idx := range indexes {
		engineIndexes[i] = engine.EntityIndex{
			FieldName:      idx.FieldName,
			JSONFieldName:  idx.JSONFieldName,
			FieldNames:     idx.FieldNames,
			JSONFieldNames: idx.JSONFieldNames,
			Unique:         idx.Unique,
			Sparse:         idx.Sparse,
			CaseSensitive:  idx.CaseSensitive,
		}
	}
	return a.engine.RegisterEntityType(entityType, engineIndexes)
}

func (a *engineKVStoreAdapter) QueryIndex(ctx context.Context, indexName string, value []byte) ([][]byte, error) {
	result, err := a.engine.Lookup(ctx, index.IndexQueryRequest{IndexName: indexName, Value: value})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, nil
		}
		return nil, err
	}
	keys, ok := result.([][]byte)
	if !ok {
		return nil, nil
	}
	return keys, nil
}

func (a *engineKVStoreAdapter) ScanIndex(ctx context.Context, indexName string, start, end []byte) (map[string][][]byte, error) {
	result, err := a.engine.Lookup(ctx, index.IndexScanRequest{IndexName: indexName, Start: start, End: end})
	if err != nil {
		return nil, err
	}
	m, ok := result.(map[string][][]byte)
	if !ok {
		return nil, nil
	}
	return m, nil
}

func (a *engineKVStoreAdapter) QueryCompoundIndex(ctx context.Context, indexName string, values [][]byte) ([][]byte, error) {
	result, err := a.engine.Lookup(ctx, index.CompoundIndexQueryRequest{IndexName: indexName, Values: values})
	if err != nil {
		return nil, err
	}
	keys, ok := result.([][]byte)
	if !ok {
		return nil, nil
	}
	return keys, nil
}

func (a *engineKVStoreAdapter) ScanCompoundIndex(ctx context.Context, indexName string, prefixValues [][]byte, rangeStart, rangeEnd []byte) (map[string][][]byte, error) {
	result, err := a.engine.Lookup(ctx, index.CompoundIndexScanRequest{IndexName: indexName, PrefixValues: prefixValues, RangeStart: rangeStart, RangeEnd: rangeEnd})
	if err != nil {
		return nil, err
	}
	m, ok := result.(map[string][][]byte)
	if !ok {
		return nil, nil
	}
	return m, nil
}

func hasBytePrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

func incrementPrefixBytes(b []byte) []byte {
	result := make([]byte, len(b))
	copy(result, b)
	for i := len(result) - 1; i >= 0; i-- {
		if result[i] < 0xff {
			result[i]++
			return result
		}
		result[i] = 0
	}
	return append(result, 0)
}

var _ kvstore.KVStore = (*engineKVStoreAdapter)(nil)
