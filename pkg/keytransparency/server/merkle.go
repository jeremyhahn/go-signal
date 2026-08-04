package server

import (
	"crypto/sha256"
)

// merkleLeaf hashes one log entry into a leaf node. Domain-separated
// from internal nodes (prefix byte 0x00) so a malicious server can't
// reframe an internal hash as a leaf or vice versa — RFC 6962 §2.1
// uses the same construction.
func merkleLeaf(serialized []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(serialized)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleNode hashes two child digests into a parent. Domain-separated
// from leaves (prefix byte 0x01).
func merkleNode(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot computes the RFC-6962-style left-balanced Merkle root
// over leaves. An empty slice produces sha256(nothing) — the same
// convention go-libsignal/pkg/keytrans verification expects for an
// empty log.
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		h := sha256.New()
		var out [32]byte
		copy(out[:], h.Sum(nil))
		return out
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	// Find the largest power of two <= len(leaves) but strictly less
	// than the full count. RFC 6962 §2.1: split the array there.
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	left := MerkleRoot(leaves[:k])
	right := MerkleRoot(leaves[k:])
	return merkleNode(left, right)
}

// MerkleInclusionProof returns the audit path proving that the leaf
// at idx is included in a tree of leaves. The returned slice contains
// the sibling hashes from leaf-to-root order; pair with
// VerifyMerkleInclusion to validate against a known root.
//
// Returns nil + false when idx is out of range.
func MerkleInclusionProof(leaves [][32]byte, idx int) ([][32]byte, bool) {
	if idx < 0 || idx >= len(leaves) {
		return nil, false
	}
	return buildInclusion(leaves, idx), true
}

// buildInclusion implements the RFC-6962 audit path generation.
// Recurses down to the leaf, collecting the sibling subtree hash at
// each level.
func buildInclusion(leaves [][32]byte, idx int) [][32]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	if idx < k {
		path := buildInclusion(leaves[:k], idx)
		path = append(path, MerkleRoot(leaves[k:]))
		return path
	}
	path := buildInclusion(leaves[k:], idx-k)
	path = append(path, MerkleRoot(leaves[:k]))
	return path
}

// VerifyMerkleInclusion reconstructs the root from leafHash + the
// audit path and compares it against expectedRoot. Returns true when
// the proof witnesses leaf inclusion at position idx in a tree of
// treeSize leaves.
//
// The verifier mirrors buildInclusion's recursive descent so
// path[0] is the deepest sibling and path[len-1] is the topmost —
// the prover and verifier round-trip in lockstep.
func VerifyMerkleInclusion(leafHash [32]byte, idx, treeSize int, path [][32]byte, expectedRoot [32]byte) bool {
	if idx < 0 || idx >= treeSize {
		return false
	}
	root, consumed, ok := verifyRec(idx, treeSize, leafHash, path, 0)
	if !ok {
		return false
	}
	return root == expectedRoot && consumed == len(path)
}

// verifyRec recursively combines leafHash with sibling hashes from
// path. Returns (sub-tree root, bytes consumed from path, ok).
func verifyRec(idx, treeSize int, leafHash [32]byte, path [][32]byte, pathIdx int) ([32]byte, int, bool) {
	if treeSize <= 1 {
		if idx != 0 {
			return [32]byte{}, 0, false
		}
		return leafHash, pathIdx, true
	}
	k := 1
	for k*2 < treeSize {
		k *= 2
	}
	if idx < k {
		sub, pIdx, ok := verifyRec(idx, k, leafHash, path, pathIdx)
		if !ok || pIdx >= len(path) {
			return [32]byte{}, 0, false
		}
		return merkleNode(sub, path[pIdx]), pIdx + 1, true
	}
	sub, pIdx, ok := verifyRec(idx-k, treeSize-k, leafHash, path, pathIdx)
	if !ok || pIdx >= len(path) {
		return [32]byte{}, 0, false
	}
	return merkleNode(path[pIdx], sub), pIdx + 1, true
}
