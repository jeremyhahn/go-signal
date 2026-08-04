// Package qrdb provides domain store implementations backed by
// github.com/jeremyhahn/go-qrdb.
//
// Each domain store (AccountStore, ProvisioningStore, KeyStore, etc.)
// implements the same interface as its memory counterpart in
// github.com/jeremyhahn/go-signal/pkg/storage/memory, so callers can swap
// backends at startup without touching business logic.
//
// Values are serialized as JSON for portability. Primary keys follow the
// convention "<domain>:<primary-id>". Secondary lookups are implemented
// with mirror keys "<domain>:<index>:<value>" that map to primary IDs.
//
// Optimistic concurrency is provided by per-entity Version fields; the
// store performs read-compare-write on Update paths and returns a
// domain-level VersionConflictError when the caller's version is not
// exactly one greater than the stored version.
package qrdb
