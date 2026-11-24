// Package server hosts the cmd/key-transparency-side state engine
// for the KeyTransparencyQueryService gRPC contract: an append-only
// log of (search key, value) pairs that the server signs and serves
// via Search / Monitor / Distinguished RPCs.
//
// The Phase 4.5 MVP ships the wire surface end-to-end with an
// in-memory log + ed25519-signed TreeHead. Real Merkle/VRF proof
// generation matching go-libsignal/pkg/keytrans's verification path
// is the focused follow-up.
package server

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Entry is one log record: a search key (ACI, username hash, or
// E.164) mapped to its current public value, plus the index at which
// it was appended.
type Entry struct {
	// Key is the opaque search key the client looks up by.
	Key []byte
	// Value is the public material the log commits to (identity key,
	// PNI link, etc.). Server treats this as opaque bytes.
	Value []byte
	// Index is the monotonically increasing log position.
	Index uint64
	// AppendedAt is when the entry was written.
	AppendedAt time.Time
}

// Log is the append-only KT log surface.
type Log interface {
	// Append writes (key, value) at the next log index and returns
	// the appended Entry. Implementations replace any previous value
	// under key with the new one — the previous-value record stays
	// in the log so Monitor can return its proof.
	Append(key, value []byte) (*Entry, error)

	// Latest returns the most recent Entry for key (the value
	// currently bound to it). Returns (nil, false) when key has
	// never been appended.
	Latest(key []byte) (*Entry, bool)

	// Size returns the current log size (count of appends).
	Size() uint64

	// RootHash returns a deterministic 32-byte commitment over the
	// log contents. The Phase 4.5 MVP uses sha256 of a serialized
	// snapshot; the focused proof-generation follow-up replaces
	// this with the proper left-balanced Merkle tree root.
	RootHash() [32]byte
}

// MemoryLog is an in-memory append-only log. All operations are safe
// for concurrent use.
type MemoryLog struct {
	mu      sync.RWMutex
	entries []*Entry
	// latest maps key (hex) → most-recent index in entries.
	latest map[string]int
}

// NewMemoryLog constructs an empty MemoryLog.
func NewMemoryLog() *MemoryLog {
	return &MemoryLog{
		latest: make(map[string]int),
	}
}

// Append implements Log.
func (l *MemoryLog) Append(key, value []byte) (*Entry, error) {
	if len(key) == 0 {
		return nil, errors.New("kt: key required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	idx := uint64(len(l.entries))
	entry := &Entry{
		Key:        append([]byte(nil), key...),
		Value:      append([]byte(nil), value...),
		Index:      idx,
		AppendedAt: time.Now().UTC(),
	}
	l.entries = append(l.entries, entry)
	l.latest[string(key)] = int(idx)
	return entry, nil
}

// Latest implements Log.
func (l *MemoryLog) Latest(key []byte) (*Entry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	idx, ok := l.latest[string(key)]
	if !ok {
		return nil, false
	}
	return l.entries[idx], true
}

// Size implements Log.
func (l *MemoryLog) Size() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return uint64(len(l.entries))
}

// RootHash implements Log. Hashes the entries as RFC-6962-style
// Merkle-tree leaves (domain-separated by a 0x00 prefix) and returns
// the left-balanced root. Inclusion proofs land via
// MerkleInclusionProof so Search/Monitor responses can carry real
// audit paths against this root.
//
// Each leaf's pre-image is:
//
//	uint64(index) BE || uint32(len(Key)) BE || Key || uint32(len(Value)) BE || Value
func (l *MemoryLog) RootHash() [32]byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	leaves := make([][32]byte, len(l.entries))
	for i, e := range l.entries {
		leaves[i] = merkleLeafForEntry(e)
	}
	return MerkleRoot(leaves)
}

// merkleLeafForEntry serialises one entry into its leaf pre-image and
// returns the leaf hash.
func merkleLeafForEntry(e *Entry) [32]byte {
	buf := make([]byte, 0, 8+4+len(e.Key)+4+len(e.Value))
	var w [8]byte
	binary.BigEndian.PutUint64(w[:], e.Index)
	buf = append(buf, w[:]...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(e.Key)))
	buf = append(buf, l[:]...)
	buf = append(buf, e.Key...)
	binary.BigEndian.PutUint32(l[:], uint32(len(e.Value)))
	buf = append(buf, l[:]...)
	buf = append(buf, e.Value...)
	return merkleLeaf(buf)
}

// LeafHashes returns the per-entry leaf hashes in append order. The
// dispatcher pairs this with MerkleInclusionProof to attach real
// audit paths to Search/Monitor responses.
func (l *MemoryLog) LeafHashes() [][32]byte {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([][32]byte, len(l.entries))
	for i, e := range l.entries {
		out[i] = merkleLeafForEntry(e)
	}
	return out
}

// LatestIndex returns the most-recent log index for key plus its leaf
// hash, suitable for MerkleInclusionProof. Returns -1 + zero hash
// when the key isn't present.
func (l *MemoryLog) LatestIndex(key []byte) (int, [32]byte) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	idx, ok := l.latest[string(key)]
	if !ok {
		return -1, [32]byte{}
	}
	return idx, merkleLeafForEntry(l.entries[idx])
}

// SignTreeHead returns an ed25519 signature over the serialized tree
// head bytes (size || rootHash || timestampMillis). The verification
// path in go-libsignal expects this layout; the dedicated
// proof-generation follow-up extends the signed payload with the
// auditor signatures + consistency-proof material.
func SignTreeHead(signer ed25519.PrivateKey, size uint64, rootHash [32]byte, ts time.Time) []byte {
	payload := make([]byte, 0, 8+32+8)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], size)
	payload = append(payload, buf[:]...)
	payload = append(payload, rootHash[:]...)
	binary.BigEndian.PutUint64(buf[:], uint64(ts.UnixMilli()))
	payload = append(payload, buf[:]...)
	return ed25519.Sign(signer, payload)
}

// VerifyTreeHead checks the signature produced by SignTreeHead.
func VerifyTreeHead(verifier ed25519.PublicKey, size uint64, rootHash [32]byte, ts time.Time, sig []byte) bool {
	payload := make([]byte, 0, 8+32+8)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], size)
	payload = append(payload, buf[:]...)
	payload = append(payload, rootHash[:]...)
	binary.BigEndian.PutUint64(buf[:], uint64(ts.UnixMilli()))
	payload = append(payload, buf[:]...)
	return ed25519.Verify(verifier, payload, sig)
}
