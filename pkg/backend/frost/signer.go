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
	"crypto"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// FrostSigner implements crypto.Signer for FROST threshold signatures.
// This provides orchestrated signing that internally coordinates the
// FROST protocol rounds.
//
// Note: For distributed scenarios where participants communicate externally,
// use the GenerateNonces, SignRound, and Aggregate methods directly.
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
// For orchestrated mode, this method performs a single-participant signing
// operation. In a real distributed scenario, you would:
//  1. Use GenerateNonces to create nonces
//  2. Exchange commitments with other participants
//  3. Use SignRound to create signature shares
//  4. Use Aggregate to combine shares
//
// The rand parameter is used for generating signing nonces.
// The opts parameter is currently unused but may support hash functions in the future.
func (s *FrostSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// For orchestrated mode, we need to coordinate with other participants
	// This is a simplified single-participant signing for demo purposes
	// In production, use the explicit round API for distributed signing

	// Generate nonces
	noncePackage, err := s.backend.GenerateNonces(s.keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonces: %w", err)
	}

	// Create commitment from our nonce package
	commitment := &Commitment{
		ParticipantID: noncePackage.ParticipantID,
		Commitments:   noncePackage.Commitments,
	}

	// For single-participant mode (threshold=1), we can sign alone
	// Otherwise, this would need coordination with other participants
	if s.keyPackage.MinSigners == 1 {
		// Single participant can sign alone
		commitments := []*Commitment{commitment}

		// Generate signature share
		share, err := s.backend.SignRound(s.keyID, digest, noncePackage, commitments)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signature share: %w", err)
		}

		// Aggregate (with single share)
		signature, err := s.backend.Aggregate(s.keyID, digest, commitments, []*SignatureShare{share})
		if err != nil {
			return nil, fmt.Errorf("failed to aggregate signature: %w", err)
		}

		return signature, nil
	}

	// For threshold > 1, orchestrated signing is not yet implemented
	// Applications should use the explicit round API for distributed scenarios
	return nil, fmt.Errorf("orchestrated multi-participant signing not implemented; use GenerateNonces, SignRound, and Aggregate for distributed signing")
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
