// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build frost

package frost

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// NonceTracker provides O(1) nonce reuse prevention using storage-based tracking.
// Nonce reuse in FROST is catastrophic - it allows full private key recovery.
//
// The tracker uses commitment hashes as storage keys for constant-time lookups.
// Commitments are already public (broadcast to other participants during signing),
// so storing their hashes does not leak any secret information.
type NonceTracker struct {
	storage storage.Backend
}

// NewNonceTracker creates a new NonceTracker with the given storage backend.
func NewNonceTracker(storage storage.Backend) *NonceTracker {
	return &NonceTracker{
		storage: storage,
	}
}

// noncePath returns the storage path for a nonce marker.
func noncePath(keyID string, commitmentHash []byte) string {
	return path.Join(noncesPrefix, keyID, hex.EncodeToString(commitmentHash))
}

// hashCommitment computes a SHA-256 hash of the commitment for storage key.
func hashCommitment(commitment []byte) []byte {
	h := sha256.Sum256(commitment)
	return h[:]
}

// MarkUsed marks a commitment's nonce as used.
// Returns ErrNonceAlreadyUsed if the nonce was already used.
func (t *NonceTracker) MarkUsed(keyID string, commitment []byte) error {
	commitmentHash := hashCommitment(commitment)
	key := noncePath(keyID, commitmentHash)

	// Check if already used (O(1) existence check)
	exists, err := t.storage.Exists(key)
	if err != nil {
		return fmt.Errorf("failed to check nonce status: %w", err)
	}
	if exists {
		return ErrNonceAlreadyUsed
	}

	// Mark as used (value is just a marker)
	if err := t.storage.Put(key, []byte{1}, nil); err != nil {
		return fmt.Errorf("failed to mark nonce as used: %w", err)
	}

	return nil
}

// IsUsed checks if a commitment's nonce has already been used.
func (t *NonceTracker) IsUsed(keyID string, commitment []byte) (bool, error) {
	commitmentHash := hashCommitment(commitment)
	key := noncePath(keyID, commitmentHash)
	return t.storage.Exists(key)
}

// MarkUsedWithDetails marks a nonce as used with detailed error information.
func (t *NonceTracker) MarkUsedWithDetails(keyID string, participantID uint32, sessionID string, commitment []byte) error {
	commitmentHash := hashCommitment(commitment)
	key := noncePath(keyID, commitmentHash)

	// Check if already used
	exists, err := t.storage.Exists(key)
	if err != nil {
		return fmt.Errorf("failed to check nonce status: %w", err)
	}
	if exists {
		return &NonceReuseError{
			KeyID:         keyID,
			ParticipantID: participantID,
			SessionID:     sessionID,
		}
	}

	// Mark as used
	if err := t.storage.Put(key, []byte{1}, nil); err != nil {
		return fmt.Errorf("failed to mark nonce as used: %w", err)
	}

	return nil
}

// DeleteKeyNonces removes all nonce markers for a key.
// This should be called when a key is deleted.
func (t *NonceTracker) DeleteKeyNonces(keyID string) error {
	prefix := path.Join(noncesPrefix, keyID) + "/"
	keys, err := t.storage.List(prefix)
	if err != nil {
		return fmt.Errorf("failed to list nonces: %w", err)
	}

	for _, key := range keys {
		_ = t.storage.Delete(key)
	}

	return nil
}

// NoncePackage contains nonces and commitments for a signing round.
type NoncePackage struct {
	// ParticipantID identifies which participant generated this
	ParticipantID uint32

	// SessionID groups nonces for a signing session
	SessionID string

	// Nonces are secret and must not be shared
	Nonces *SigningNonces

	// Commitments are public and shared with other participants
	Commitments *SigningCommitments
}

// SigningNonces holds the secret nonces for a participant.
// These must NEVER be shared or reused.
type SigningNonces struct {
	// HidingNonce is the hiding nonce (secret)
	HidingNonce []byte

	// BindingNonce is the binding nonce (secret)
	BindingNonce []byte
}

// Zeroize securely erases the nonce material from memory.
func (n *SigningNonces) Zeroize() {
	if n.HidingNonce != nil {
		for i := range n.HidingNonce {
			n.HidingNonce[i] = 0
		}
	}
	if n.BindingNonce != nil {
		for i := range n.BindingNonce {
			n.BindingNonce[i] = 0
		}
	}
}

// SigningCommitments holds the public commitments for a participant.
// These are shared with other participants during the signing protocol.
type SigningCommitments struct {
	// ParticipantID identifies who created these commitments
	ParticipantID uint32

	// HidingCommitment is the commitment to the hiding nonce (public)
	HidingCommitment []byte

	// BindingCommitment is the commitment to the binding nonce (public)
	BindingCommitment []byte
}

// Serialize returns the commitments in wire format for hashing/tracking.
func (c *SigningCommitments) Serialize() []byte {
	result := make([]byte, 0, len(c.HidingCommitment)+len(c.BindingCommitment)+4)
	result = append(result, byte(c.ParticipantID>>24), byte(c.ParticipantID>>16), byte(c.ParticipantID>>8), byte(c.ParticipantID))
	result = append(result, c.HidingCommitment...)
	result = append(result, c.BindingCommitment...)
	return result
}

// Commitment wraps commitments with participant information for protocol use.
type Commitment struct {
	// ParticipantID identifies who created these commitments
	ParticipantID uint32

	// Commitments contains the actual commitment values
	Commitments *SigningCommitments
}

// Serialize returns the commitment in wire format.
func (c *Commitment) Serialize() []byte {
	return c.Commitments.Serialize()
}
