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
	"crypto"
	"io"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// FrostSigner implements crypto.Signer for a single-participant
// (threshold 1) FROST key. FrostBackend.Signer refuses to construct a
// FrostSigner for any key whose threshold requires coordinating more than
// one participant; use the GenerateNonces, SignRound, and Aggregate
// methods directly for distributed signing.
type FrostSigner struct {
	backend    *FrostBackend
	keyID      string
	keyPackage *KeyPackage
}

// Public returns the threshold group public key.
func (s *FrostSigner) Public() crypto.PublicKey {
	return s.keyPackage.GroupPublicKey
}

// Sign signs digest with the FROST key.
//
// FrostSigner always wraps a single-participant (threshold 1) key, so
// Sign runs the FROST round internally: generate a nonce, produce this
// participant's signature share, and aggregate that lone share into the
// final signature.
//
// The rand parameter is used for generating signing nonces.
// The opts parameter is currently unused but may support hash functions in the future.
func (s *FrostSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Generate nonces
	noncePackage, err := s.backend.GenerateNonces(s.keyID)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate nonces", Err: err}
	}

	// Create commitment from our nonce package
	commitment := &Commitment{
		ParticipantID: noncePackage.ParticipantID,
		Commitments:   noncePackage.Commitments,
	}
	commitments := []*Commitment{commitment}

	// Generate signature share
	share, err := s.backend.SignRound(s.keyID, digest, noncePackage, commitments)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate signature share", Err: err}
	}

	// Aggregate (with single share)
	signature, err := s.backend.Aggregate(s.keyID, digest, commitments, []*SignatureShare{share})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to aggregate signature", Err: err}
	}

	return signature, nil
}

// Algorithm returns the public key algorithm type.
func (s *FrostSigner) Algorithm() types.FrostAlgorithm {
	return s.keyPackage.Algorithm
}

// KeyID returns the key identifier.
func (s *FrostSigner) KeyID() string {
	return s.keyID
}

// ParticipantID returns this signer's participant identifier.
func (s *FrostSigner) ParticipantID() uint32 {
	return s.keyPackage.ParticipantID
}

// Threshold returns the minimum number of signers required.
func (s *FrostSigner) Threshold() uint32 {
	return s.keyPackage.MinSigners
}

// Total returns the total number of participants.
func (s *FrostSigner) Total() uint32 {
	return s.keyPackage.MaxSigners
}

// GroupPublicKey returns the threshold group public key bytes.
func (s *FrostSigner) GroupPublicKey() []byte {
	return s.keyPackage.GroupPublicKey
}

// VerificationShare returns the verification share for a participant.
func (s *FrostSigner) VerificationShare(participantID uint32) []byte {
	if share, ok := s.keyPackage.VerificationShares[participantID]; ok {
		return share
	}
	return nil
}
