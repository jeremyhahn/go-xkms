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
	"fmt"

	gofrost "github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/keygen"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// FrostConfig contains configuration for FROST key generation.
type FrostConfig struct {
	// Threshold is the minimum number of signers required (M)
	Threshold int

	// Total is the total number of participants (N)
	Total int

	// Algorithm specifies the FROST ciphersuite to use
	Algorithm types.FrostAlgorithm

	// Participants are the identifiers for each participant
	Participants []string

	// ParticipantID is this participant's identifier (1 to Total)
	ParticipantID uint32
}

// Validate checks if the FROST config is valid.
func (c *FrostConfig) Validate() error {
	if c.Threshold < 2 {
		return fmt.Errorf("threshold must be at least 2, got %d", c.Threshold)
	}
	if c.Total < c.Threshold {
		return fmt.Errorf("total (%d) must be >= threshold (%d)", c.Total, c.Threshold)
	}
	if c.Threshold > 255 {
		return fmt.Errorf("threshold cannot exceed 255, got %d", c.Threshold)
	}
	if c.Total > 255 {
		return fmt.Errorf("total cannot exceed 255, got %d", c.Total)
	}
	if len(c.Participants) > 0 && len(c.Participants) != c.Total {
		return fmt.Errorf("participants length (%d) must match total (%d)", len(c.Participants), c.Total)
	}
	if !c.Algorithm.IsValid() {
		return fmt.Errorf("invalid algorithm: %s", c.Algorithm)
	}
	return nil
}

// KeyPackage contains FROST key material for a single participant.
type KeyPackage struct {
	// ParticipantID identifies this participant
	ParticipantID uint32

	// SecretShare is this participant's secret key share
	SecretShare *SecretKeyShare

	// GroupPublicKey is the threshold public key
	GroupPublicKey []byte

	// VerificationShares are public key shares for all participants
	// Keyed by participant ID
	VerificationShares map[uint32][]byte

	// MinSigners is the threshold value (M)
	MinSigners uint32

	// MaxSigners is the total number of participants (N)
	MaxSigners uint32

	// Algorithm is the FROST ciphersuite used
	Algorithm types.FrostAlgorithm
}

// SecretKeyShare holds the secret scalar for a participant.
type SecretKeyShare struct {
	// Value is the secret scalar bytes
	Value []byte
}

// Zeroize securely erases the secret key share from memory.
func (s *SecretKeyShare) Zeroize() {
	if s.Value != nil {
		for i := range s.Value {
			s.Value[i] = 0
		}
	}
}

// PublicKeyPackage contains the public components of a FROST key.
type PublicKeyPackage struct {
	// GroupPublicKey is the threshold public key
	GroupPublicKey []byte

	// VerificationShares maps participant IDs to their public key shares
	VerificationShares map[uint32][]byte

	// MinSigners is the threshold value (M)
	MinSigners uint32

	// MaxSigners is the total number of participants (N)
	MaxSigners uint32

	// Algorithm is the FROST ciphersuite used
	Algorithm types.FrostAlgorithm
}

// KeyGenerator is the interface for FROST key generation.
// This abstraction allows plugging in custom DKG implementations.
type KeyGenerator interface {
	// Generate creates key packages for a threshold signing group.
	//
	// Returns:
	//   - []*KeyPackage: Key packages for all participants
	//   - *PublicKeyPackage: Public keys for all participants
	//   - error: Any error during generation
	Generate(config FrostConfig) ([]*KeyPackage, *PublicKeyPackage, error)
}

// TrustedDealer implements RFC 9591 Appendix C trusted dealer key generation.
// In this model, a single trusted party generates all key shares.
type TrustedDealer struct{}

// NewTrustedDealer creates a new TrustedDealer key generator.
func NewTrustedDealer() *TrustedDealer {
	return &TrustedDealer{}
}

// Generate creates FROST key packages using the trusted dealer model.
// This implements RFC 9591 Appendix C.
func (td *TrustedDealer) Generate(config FrostConfig) ([]*KeyPackage, *PublicKeyPackage, error) {
	if err := config.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid config: %w", err)
	}

	// Get the ciphersuite
	cs, err := GetCiphersuite(config.Algorithm)
	if err != nil {
		return nil, nil, err
	}

	// Generate participant identifiers
	identifiers := make([]gofrost.Identifier, config.Total)
	for i := 0; i < config.Total; i++ {
		identifiers[i] = gofrost.Identifier(uint32(i + 1))
	}

	// Create dealer and generate key shares
	dealer := keygen.NewDealer(cs)
	keyPackages, groupPublicKey, err := dealer.GenerateShares(
		nil, // Let dealer generate the secret
		uint32(config.Threshold),
		uint32(config.Total),
		identifiers,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("trusted dealer keygen failed: %w", err)
	}

	// Convert to our KeyPackage format
	packages := make([]*KeyPackage, config.Total)
	verificationShares := make(map[uint32][]byte)

	for i, kp := range keyPackages {
		participantID := uint32(kp.Identifier)

		// Extract secret share bytes
		secretBytes := kp.SecretShare.Bytes()

		// Extract verification shares for all participants
		// Note: go-frost returns VerificationShares with 0-indexed identifiers
		// even when we pass 1-indexed participant identifiers. We need to map
		// from the 0-indexed vs.Identifier to the actual participant identifier.
		for _, vs := range kp.VerificationShares {
			// Map 0-indexed verification share position to actual participant identifier
			actualID := identifiers[uint32(vs.Identifier)]
			verificationShares[uint32(actualID)] = vs.VerificationKey.Bytes()
		}

		packages[i] = &KeyPackage{
			ParticipantID: participantID,
			SecretShare: &SecretKeyShare{
				Value: secretBytes,
			},
			MinSigners: uint32(config.Threshold),
			MaxSigners: uint32(config.Total),
			Algorithm:  config.Algorithm,
		}
	}

	// Serialize group public key
	groupPubBytes := groupPublicKey.Bytes()

	// Set group public key and verification shares on all packages
	for _, pkg := range packages {
		pkg.GroupPublicKey = groupPubBytes
		pkg.VerificationShares = verificationShares
	}

	// Create public key package
	publicPackage := &PublicKeyPackage{
		GroupPublicKey:     groupPubBytes,
		VerificationShares: verificationShares,
		MinSigners:         uint32(config.Threshold),
		MaxSigners:         uint32(config.Total),
		Algorithm:          config.Algorithm,
	}

	return packages, publicPackage, nil
}

// GenerateSinglePackage generates a key package for a specific participant.
// This is a convenience method that generates all packages and returns just one.
func (td *TrustedDealer) GenerateSinglePackage(config FrostConfig, participantID uint32) (*KeyPackage, *PublicKeyPackage, error) {
	packages, publicPackage, err := td.Generate(config)
	if err != nil {
		return nil, nil, err
	}

	if participantID < 1 || participantID > uint32(len(packages)) {
		return nil, nil, fmt.Errorf("invalid participant ID: %d (must be 1-%d)", participantID, len(packages))
	}

	return packages[participantID-1], publicPackage, nil
}
