// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package transport

// Transparency log operations: the read verbs over the CA's transparency log
// (docs/transparency-log). Hashes are RFC 9162 §2.1 Merkle tree hashes.

// GetTransparencyLogHeadRequest requests the log's current signed tree head.
type GetTransparencyLogHeadRequest struct{}

// GetTransparencyLogHeadResponse is the log's signed tree head.
type GetTransparencyLogHeadResponse struct {
	// Checkpoint is the tree head as a C2SP signed note (tlog-checkpoint),
	// signed with the CA key.
	Checkpoint []byte `json:"checkpoint"`

	// Origin is the checkpoint's origin line.
	Origin string `json:"origin"`

	// Size is the number of entries the tree head covers.
	Size uint64 `json:"size"`

	// RootHash is the Merkle tree root hash at Size.
	RootHash []byte `json:"root_hash"`
}

// GetTransparencyLogEntryRequest requests one log entry.
type GetTransparencyLogEntryRequest struct {
	// Index is the entry's zero-based index in the log.
	Index uint64 `json:"index"`
}

// GetTransparencyLogEntryResponse is one log entry.
type GetTransparencyLogEntryResponse struct {
	// Index is the entry's zero-based index in the log.
	Index uint64 `json:"index"`

	// Entry is the encoded entry: the leaf data whose RFC 9162 leaf hash
	// the inclusion proof proves.
	Entry []byte `json:"entry"`
}

// GetTransparencyLogInclusionProofRequest requests the proof that an entry
// is in the tree of a given size.
type GetTransparencyLogInclusionProofRequest struct {
	// Index is the entry's zero-based index; it must be below TreeSize.
	Index uint64 `json:"index"`

	// TreeSize is the size of the tree to prove against; it must be at
	// least one and at most the current tree head's size.
	TreeSize uint64 `json:"tree_size"`
}

// GetTransparencyLogInclusionProofResponse is an RFC 9162 §2.1.3 inclusion
// proof.
type GetTransparencyLogInclusionProofResponse struct {
	// Index is the proven entry's index.
	Index uint64 `json:"index"`

	// TreeSize is the size of the tree the proof is against.
	TreeSize uint64 `json:"tree_size"`

	// Hashes is the inclusion path, leaf to root.
	Hashes [][]byte `json:"hashes"`
}

// GetTransparencyLogConsistencyProofRequest requests the proof that the tree
// of FirstSize is a prefix of the tree of SecondSize.
type GetTransparencyLogConsistencyProofRequest struct {
	// FirstSize is the older tree's size; it must be at least one and at
	// most SecondSize.
	FirstSize uint64 `json:"first_size"`

	// SecondSize is the newer tree's size; it must be at most the current
	// tree head's size.
	SecondSize uint64 `json:"second_size"`
}

// GetTransparencyLogConsistencyProofResponse is an RFC 9162 §2.1.4
// consistency proof.
type GetTransparencyLogConsistencyProofResponse struct {
	// FirstSize is the older tree's size.
	FirstSize uint64 `json:"first_size"`

	// SecondSize is the newer tree's size.
	SecondSize uint64 `json:"second_size"`

	// Hashes is the consistency path.
	Hashes [][]byte `json:"hashes"`
}

// AppendTransparencyLogExternalRequest appends an external entry. It carries
// only the payload: the entry's SPIFFE ID is the authenticated caller's,
// never a request field.
type AppendTransparencyLogExternalRequest struct {
	// Payload is the caller's opaque payload, 1 to 65535 bytes.
	Payload []byte `json:"payload"`
}

// AppendTransparencyLogExternalResponse names the appended entry.
type AppendTransparencyLogExternalResponse struct {
	// Index is the appended entry's leaf index.
	Index uint64 `json:"index"`
}
