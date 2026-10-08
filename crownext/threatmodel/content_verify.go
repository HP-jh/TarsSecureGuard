package threatmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ContentVerifier validates content-addressed data integrity.
type ContentVerifier struct{}

// NewContentVerifier creates a verifier.
func NewContentVerifier() *ContentVerifier {
	return &ContentVerifier{}
}

// ComputeCID returns the SHA-256 CID string for data.
func (v *ContentVerifier) ComputeCID(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Verify checks that data matches the claimed CID.
func (v *ContentVerifier) Verify(data []byte, claimedCID string) error {
	actual := v.ComputeCID(data)
	if actual != claimedCID {
		return fmt.Errorf("threatmodel: CID mismatch: expected %s, got %s", claimedCID, actual)
	}
	return nil
}

// VerifyMulti checks multiple (data, CID) pairs and returns the first mismatch.
func (v *ContentVerifier) VerifyMulti(pairs []struct{ Data []byte; CID string }) error {
	for _, p := range pairs {
		if err := v.Verify(p.Data, p.CID); err != nil {
			return err
		}
	}
	return nil
}

// MerkleNode is a single node in a lightweight Merkle tree.
type MerkleNode struct {
	Hash  string `json:"hash"`
	Left  *MerkleNode `json:"left,omitempty"`
	Right *MerkleNode `json:"right,omitempty"`
}

// BuildMerkleTree builds a Merkle tree from leaf data and returns the root hash.
func (v *ContentVerifier) BuildMerkleTree(leaves [][]byte) (string, *MerkleNode, error) {
	if len(leaves) == 0 {
		return "", nil, fmt.Errorf("threatmodel: no leaves")
	}
	var nodes []*MerkleNode
	for _, leaf := range leaves {
		nodes = append(nodes, &MerkleNode{Hash: v.ComputeCID(leaf)})
	}
	for len(nodes) > 1 {
		var next []*MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				combined := nodes[i].Hash + nodes[i+1].Hash
				next = append(next, &MerkleNode{
					Hash:  v.ComputeCID([]byte(combined)),
					Left:  nodes[i],
					Right: nodes[i+1],
				})
			} else {
				next = append(next, nodes[i])
			}
		}
		nodes = next
	}
	return nodes[0].Hash, nodes[0], nil
}

// VerifyMerklePath verifies a leaf is part of a Merkle tree with given root.
func (v *ContentVerifier) VerifyMerklePath(leaf []byte, root string, path []string, isRight []bool) error {
	hash := v.ComputeCID(leaf)
	for i, sibling := range path {
		var combined string
		if isRight[i] {
			combined = sibling + hash
		} else {
			combined = hash + sibling
		}
		hash = v.ComputeCID([]byte(combined))
	}
	if hash != root {
		return fmt.Errorf("threatmodel: Merkle root mismatch")
	}
	return nil
}
