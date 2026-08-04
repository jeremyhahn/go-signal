// Package cdsi is the server-side state engine for Contact Discovery
// v2. cmd/cdsi wires it behind a Noise-NKhfs-attested WebSocket and
// pulls its (E.164 → ACI/PNI/access_key) snapshot from signald over
// internal gRPC at startup.
//
// Per Java's architecture (and the Phase 4.3 plan), mobile clients
// connect DIRECTLY to cdsi for batch lookups; signald is not on the
// call path. signald issues HMAC credentials at /v2/directory/auth
// that mobile clients present as HTTP Basic on the WebSocket upgrade.
package cdsi

import (
	"context"
	"sync"
	"sync/atomic"
)

// Entry is one row of the contact-discovery directory: the
// (E.164 phone number, ACI, PNI, access_key) tuple. Zero-value UUID
// bytes mean "absent" — common for PNI-only accounts that have not
// opted in to contact-discovery.
type Entry struct {
	// E164 is the canonical phone number as a uint64 (no + prefix).
	E164 uint64
	// ACI is the 16-byte Account Contact Identifier or zero.
	ACI [16]byte
	// PNI is the 16-byte Phone Number Identifier or zero.
	PNI [16]byte
	// AccessKey is the 16-byte profile access key or zero.
	AccessKey [16]byte
}

// Directory is the read surface cdsi's request dispatcher consumes.
// Implementations must be safe for concurrent reads (writes happen on
// startup snapshot + later via change events).
type Directory interface {
	// Lookup returns the entry for e164, or (Entry{}, false) when no
	// account is registered against that number.
	Lookup(e164 uint64) (Entry, bool)
	// Count returns the current entry count. Used by metrics +
	// integration assertions.
	Count() int
}

// MemoryDirectory is an in-memory Directory used by the Phase 4.3
// MVP. cmd/cdsi populates it once at startup by streaming from
// signald's DirectoryService.ListEntries.
type MemoryDirectory struct {
	mu      sync.RWMutex
	entries map[uint64]Entry
	// version increments on every mutation so observers (metrics,
	// tests) can detect change without consulting the map.
	version atomic.Uint64
}

// NewMemoryDirectory constructs an empty MemoryDirectory.
func NewMemoryDirectory() *MemoryDirectory {
	return &MemoryDirectory{entries: make(map[uint64]Entry)}
}

// Lookup implements Directory.
func (d *MemoryDirectory) Lookup(e164 uint64) (Entry, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	entry, ok := d.entries[e164]
	return entry, ok
}

// Count implements Directory.
func (d *MemoryDirectory) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries)
}

// Upsert inserts or replaces an entry. Called by the chat-server-sync
// loop on snapshot stream messages.
func (d *MemoryDirectory) Upsert(entry Entry) {
	d.mu.Lock()
	d.entries[entry.E164] = entry
	d.mu.Unlock()
	d.version.Add(1)
}

// Delete removes the entry for e164. Idempotent: missing keys are
// not an error.
func (d *MemoryDirectory) Delete(e164 uint64) {
	d.mu.Lock()
	delete(d.entries, e164)
	d.mu.Unlock()
	d.version.Add(1)
}

// Replace atomically swaps the directory contents with newEntries.
// Used by the snapshot path so partial inflight loads aren't visible.
func (d *MemoryDirectory) Replace(ctx context.Context, newEntries []Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m := make(map[uint64]Entry, len(newEntries))
	for _, e := range newEntries {
		m[e.E164] = e
	}
	d.mu.Lock()
	d.entries = m
	d.mu.Unlock()
	d.version.Add(1)
	return nil
}

// Version returns a monotonic counter that advances on every mutation.
func (d *MemoryDirectory) Version() uint64 { return d.version.Load() }
