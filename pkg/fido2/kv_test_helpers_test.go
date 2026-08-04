//go:build fido2

package fido2

import (
	"context"
	"errors"
)

// errFailing is a sentinel error used by the failing KV client.
var errFailing = errors.New("kv client failure")

// failingKVClient is a KV client that fails on specific operations to test
// error handling paths.
type failingKVClient struct {
	failPut             bool
	failGet             bool
	failDelete          bool
	failDeleteIfPresent bool
	failList            bool
	failExists          bool

	// data allows selective success for setup operations.
	data map[string][]byte
}

func newFailingKVClient() *failingKVClient {
	return &failingKVClient{
		data: make(map[string][]byte),
	}
}

func (f *failingKVClient) Put(_ context.Context, key string, value []byte) error {
	if f.failPut {
		return errFailing
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	f.data[key] = cp
	return nil
}

func (f *failingKVClient) Get(_ context.Context, key string) ([]byte, error) {
	if f.failGet {
		return nil, errFailing
	}
	v, ok := f.data[key]
	if !ok {
		return nil, errFailing
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (f *failingKVClient) Delete(_ context.Context, key string) error {
	if f.failDelete {
		return errFailing
	}
	delete(f.data, key)
	return nil
}

func (f *failingKVClient) DeleteIfPresent(_ context.Context, key string) (bool, error) {
	if f.failDeleteIfPresent {
		return false, errFailing
	}
	if _, ok := f.data[key]; !ok {
		return false, nil
	}
	delete(f.data, key)
	return true, nil
}

func (f *failingKVClient) List(_ context.Context, _ string) ([]string, error) {
	if f.failList {
		return nil, errFailing
	}
	return nil, nil
}

func (f *failingKVClient) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return errFailing
}

func (f *failingKVClient) Exists(_ context.Context, key string) (bool, error) {
	if f.failExists {
		return false, errFailing
	}
	_, ok := f.data[key]
	return ok, nil
}
