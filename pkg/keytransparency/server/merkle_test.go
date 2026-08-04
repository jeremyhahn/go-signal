package server

import (
	"crypto/sha256"
	"testing"
)

func leaf(b byte) [32]byte {
	in := []byte{b}
	return merkleLeaf(in)
}

func TestMerkleRoot_EmptyLog(t *testing.T) {
	want := sha256.Sum256(nil)
	if MerkleRoot(nil) != want {
		t.Error("empty MerkleRoot must equal sha256(nil)")
	}
}

func TestMerkleRoot_SingleLeafReturnsLeaf(t *testing.T) {
	l := leaf(1)
	if MerkleRoot([][32]byte{l}) != l {
		t.Error("single-leaf root should equal the leaf")
	}
}

func TestMerkleRoot_DeterministicAcrossSameInputs(t *testing.T) {
	leaves1 := [][32]byte{leaf(1), leaf(2), leaf(3), leaf(4)}
	leaves2 := [][32]byte{leaf(1), leaf(2), leaf(3), leaf(4)}
	if MerkleRoot(leaves1) != MerkleRoot(leaves2) {
		t.Error("identical leaf slices must produce identical roots")
	}
}

func TestMerkleRoot_OrderSensitive(t *testing.T) {
	a := MerkleRoot([][32]byte{leaf(1), leaf(2)})
	b := MerkleRoot([][32]byte{leaf(2), leaf(1)})
	if a == b {
		t.Error("swapping leaves must change the root")
	}
}

func TestMerkleInclusion_ProofVerifiesForEveryLeafInBalancedTree(t *testing.T) {
	leaves := [][32]byte{leaf(1), leaf(2), leaf(3), leaf(4)}
	root := MerkleRoot(leaves)
	for i := range leaves {
		path, ok := MerkleInclusionProof(leaves, i)
		if !ok {
			t.Fatalf("path[%d] not produced", i)
		}
		if !VerifyMerkleInclusion(leaves[i], i, len(leaves), path, root) {
			t.Errorf("verification failed for idx=%d", i)
		}
	}
}

func TestMerkleInclusion_ProofVerifiesInUnbalancedTree(t *testing.T) {
	// 5 leaves — RFC 6962 splits at k=4 (largest 2^n < 5), exercising
	// the unbalanced path.
	leaves := [][32]byte{leaf(1), leaf(2), leaf(3), leaf(4), leaf(5)}
	root := MerkleRoot(leaves)
	for i := range leaves {
		path, ok := MerkleInclusionProof(leaves, i)
		if !ok {
			t.Fatalf("path[%d] not produced", i)
		}
		if !VerifyMerkleInclusion(leaves[i], i, len(leaves), path, root) {
			t.Errorf("verification failed for idx=%d (unbalanced)", i)
		}
	}
}

func TestMerkleInclusion_WrongRootFails(t *testing.T) {
	leaves := [][32]byte{leaf(1), leaf(2), leaf(3)}
	path, _ := MerkleInclusionProof(leaves, 1)
	bogus := leaf(0xFF)
	if VerifyMerkleInclusion(leaves[1], 1, 3, path, bogus) {
		t.Error("verification must fail under a wrong root")
	}
}

func TestMerkleInclusion_TamperedPathFails(t *testing.T) {
	leaves := [][32]byte{leaf(1), leaf(2), leaf(3), leaf(4)}
	root := MerkleRoot(leaves)
	path, _ := MerkleInclusionProof(leaves, 2)
	if len(path) == 0 {
		t.Fatal("empty path")
	}
	// Flip a byte on the first sibling.
	path[0][0] ^= 0xFF
	if VerifyMerkleInclusion(leaves[2], 2, 4, path, root) {
		t.Error("tampered path must not verify")
	}
}

func TestMerkleInclusion_IdxOutOfRange(t *testing.T) {
	leaves := [][32]byte{leaf(1), leaf(2)}
	if _, ok := MerkleInclusionProof(leaves, -1); ok {
		t.Error("negative idx should fail")
	}
	if _, ok := MerkleInclusionProof(leaves, 99); ok {
		t.Error("out-of-range idx should fail")
	}
}

func TestMerkleNode_DomainSeparated(t *testing.T) {
	a, b := leaf(1), leaf(2)
	// Internal-node hashing is distinct from leaf hashing — same
	// bytes through merkleLeaf and merkleNode must produce different
	// outputs.
	if merkleNode(a, b) == merkleLeaf(append(a[:], b[:]...)) {
		t.Error("leaf and internal-node domains must be separated")
	}
}
