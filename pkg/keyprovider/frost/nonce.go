// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build frost

package frost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-enclave"
)

// NonceTracker prevents FROST nonce reuse. Reuse is catastrophic: two
// signature shares over one nonce reveal the signer's secret share.
//
// Each used nonce is one FrostNonce entity in the DatabaseName database,
// created with the DAO's SaveIfAbsent: the one write with a defined outcome
// under concurrency, so a nonce is claimed once across every goroutine,
// process and node sharing the datastore, never twice. Commitments are
// public (broadcast to the other participants), so the records leak nothing
// secret.
type NonceTracker struct {
	nonces qrdbsdk.GenericDAO[*FrostNonce]
}

// NewNonceTracker returns a NonceTracker whose DAO daos builds over
// DatabaseName.
func NewNonceTracker(daos *qrdbsdk.DAOFactory) (*NonceTracker, error) {
	nonces, err := newDAO(daos, nonceEntityType, newFrostNonce)
	if err != nil {
		return nil, err
	}
	return &NonceTracker{nonces: nonces}, nil
}

// nonceName is the natural key of the nonce behind commitment under keyID.
func nonceName(keyID string, commitment []byte) string {
	hash := sha256.Sum256(commitment)
	return keyID + "/" + hex.EncodeToString(hash[:])
}

// Claim atomically records the nonce behind commitment as used for keyID.
// It returns *NonceReuseError when the nonce was already claimed, by this or
// any other process sharing the datastore, and *StoreError when the claim
// could not be made, whose outcome is then unknown. The claim is the DAO's
// SaveIfAbsent, so there is no read-then-write here for two signers to race
// through.
func (t *NonceTracker) Claim(ctx context.Context, keyID string, participantID uint32, sessionID string, commitment []byte) error {
	nonce := &FrostNonce{
		Name:          nonceName(keyID, commitment),
		KeyID:         keyID,
		ParticipantID: participantID,
		SessionID:     sessionID,
	}
	claimed, err := t.nonces.SaveIfAbsent(ctx, nonce)
	if err != nil {
		return &StoreError{Op: "claim nonce", Key: nonce.Name, Err: err}
	}
	if !claimed {
		return &NonceReuseError{KeyID: keyID, ParticipantID: participantID, SessionID: sessionID}
	}
	return nil
}

// DeleteKeyNonces removes every nonce record of keyID. It is called when the
// key is deleted. Every failed delete is reported, joined.
func (t *NonceTracker) DeleteKeyNonces(ctx context.Context, keyID string) error {
	var used []*FrostNonce
	err := t.nonces.ForEachPage(ctx, listQuery(), func(page qrdbsdk.PageResult[*FrostNonce]) error {
		for _, nonce := range page.Entities {
			if nonce.KeyID == keyID {
				used = append(used, nonce)
			}
		}
		return nil
	})
	if err != nil {
		return &StoreError{Op: "list nonces", Key: keyID, Err: err}
	}

	var deleteErr error
	for _, nonce := range used {
		if err := t.nonces.Delete(ctx, nonce); err != nil {
			deleteErr = errors.Join(deleteErr, &StoreError{Op: "delete nonce", Key: nonce.Name, Err: err})
		}
	}
	return deleteErr
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
	enclave.Wipe(n.HidingNonce)
	enclave.Wipe(n.BindingNonce)
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
