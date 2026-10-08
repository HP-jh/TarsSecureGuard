package threatmodel

import (
	"testing"
)

func TestContentVerifierComputeVerify(t *testing.T) {
	v := NewContentVerifier()
	data := []byte("test data")
	cid := v.ComputeCID(data)
	if err := v.Verify(data, cid); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify([]byte("tampered"), cid); err == nil {
		t.Fatal("expected verify failure for tampered data")
	}
}

func TestContentVerifierMulti(t *testing.T) {
	v := NewContentVerifier()
	pairs := []struct{ Data []byte; CID string }{
		{[]byte("a"), v.ComputeCID([]byte("a"))},
		{[]byte("b"), v.ComputeCID([]byte("b"))},
	}
	if err := v.VerifyMulti(pairs); err != nil {
		t.Fatal(err)
	}
	badPairs := []struct{ Data []byte; CID string }{
		{[]byte("a"), v.ComputeCID([]byte("b"))},
	}
	if err := v.VerifyMulti(badPairs); err == nil {
		t.Fatal("expected failure for bad pair")
	}
}

func TestContentVerifierMerkle(t *testing.T) {
	v := NewContentVerifier()
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	root, tree, err := v.BuildMerkleTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if root == "" {
		t.Fatal("expected non-empty root")
	}
	if tree == nil {
		t.Fatal("expected tree")
	}

	path := []string{tree.Left.Left.Hash, tree.Right.Hash}
	isRight := []bool{true, false}
	if err := v.VerifyMerklePath(leaves[1], root, path, isRight); err != nil {
		t.Fatalf("merkle path verify failed: %v", err)
	}
}

func TestContentVerifierMerkleBadPath(t *testing.T) {
	v := NewContentVerifier()
	leaves := [][]byte{[]byte("a"), []byte("b")}
	root, _, _ := v.BuildMerkleTree(leaves)
	if err := v.VerifyMerklePath([]byte("x"), root, []string{}, []bool{}); err == nil {
		t.Fatal("expected failure for wrong leaf")
	}
}
