// Package store provides storage abstractions for the Signal server.
package store

import "context"

// KVClient defines a key-value storage interface used by all Signal server
// store implementations.
type KVClient interface {
	// Put stores a value at the given key, overwriting any existing value.
	Put(ctx context.Context, key string, value []byte) error

	// Get retrieves the value stored at the given key.
	Get(ctx context.Context, key string) ([]byte, error)

	// Delete removes the value stored at the given key.
	Delete(ctx context.Context, key string) error

	// List returns all keys that share the given prefix.
	List(ctx context.Context, prefix string) ([]string, error)

	// Scan iterates over all key-value pairs whose keys share the given prefix,
	// invoking fn for each pair. Iteration stops early if fn returns an error.
	Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error

	// Exists reports whether a value is stored at the given key.
	Exists(ctx context.Context, key string) (bool, error)
}

// KeyNotFoundError indicates that the requested key does not exist.
type KeyNotFoundError struct {
	Key string
}

func (e *KeyNotFoundError) Error() string {
	return "key not found: " + e.Key
}

// KeyExistsError indicates that the key already exists.
type KeyExistsError struct {
	Key string
}

func (e *KeyExistsError) Error() string {
	return "key already exists: " + e.Key
}
