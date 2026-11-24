package server

import (
	"crypto/sha256"
)

// merkleLeaf hashes an entry as a leaf with prefix 0x00, per RFC 6962 §2.1.
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

// MerkleRoot returns the RFC 6962 left-balanced root; an empty slice gives sha256 of nothing.
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

// MerkleInclusionProof returns leaf-to-root sibling hashes for idx, or nil and false when idx is out of range.
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

// VerifyMerkleInclusion recomputes the root from leafHash and path (deepest sibling first) and compares it with expectedRoot.
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
