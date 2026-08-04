package store

import "context"

// FailingKVClient wraps a KVClient and injects configurable errors for
// testing error-handling paths. Set the corresponding error field to a
// non-nil value to make that operation fail before delegating.
type FailingKVClient struct {
	Delegate  KVClient
	PutErr    error
	GetErr    error
	DeleteErr error
	ListErr   error
	ScanErr   error
	ExistsErr error
}

// NewFailingKVClient returns a FailingKVClient wrapping a MemoryKVClient.
func NewFailingKVClient() *FailingKVClient {
	return &FailingKVClient{
		Delegate: NewMemoryKVClient(),
	}
}

// Put delegates to the underlying KVClient unless PutErr is set.
func (f *FailingKVClient) Put(ctx context.Context, key string, value []byte) error {
	if f.PutErr != nil {
		return f.PutErr
	}
	return f.Delegate.Put(ctx, key, value)
}

// Get delegates to the underlying KVClient unless GetErr is set.
func (f *FailingKVClient) Get(ctx context.Context, key string) ([]byte, error) {
	if f.GetErr != nil {
		return nil, f.GetErr
	}
	return f.Delegate.Get(ctx, key)
}

// Delete delegates to the underlying KVClient unless DeleteErr is set.
func (f *FailingKVClient) Delete(ctx context.Context, key string) error {
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	return f.Delegate.Delete(ctx, key)
}

// DeleteIfPresent delegates to the underlying KVClient unless DeleteErr is set.
func (f *FailingKVClient) DeleteIfPresent(ctx context.Context, key string) (bool, error) {
	if f.DeleteErr != nil {
		return false, f.DeleteErr
	}
	return f.Delegate.DeleteIfPresent(ctx, key)
}

// List delegates to the underlying KVClient unless ListErr is set.
func (f *FailingKVClient) List(ctx context.Context, prefix string) ([]string, error) {
	if f.ListErr != nil {
		return nil, f.ListErr
	}
	return f.Delegate.List(ctx, prefix)
}

// Scan delegates to the underlying KVClient unless ScanErr is set.
func (f *FailingKVClient) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.ScanErr != nil {
		return f.ScanErr
	}
	return f.Delegate.Scan(ctx, prefix, fn)
}

// Exists delegates to the underlying KVClient unless ExistsErr is set.
func (f *FailingKVClient) Exists(ctx context.Context, key string) (bool, error) {
	if f.ExistsErr != nil {
		return false, f.ExistsErr
	}
	return f.Delegate.Exists(ctx, key)
}
