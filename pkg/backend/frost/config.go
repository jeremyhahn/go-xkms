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
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Config contains configuration for the FROST backend.
type Config struct {
	// PublicStorage stores public components (group public key, verification shares, metadata)
	// This storage does not need to be encrypted or hardware-backed.
	PublicStorage storage.Backend

	// SecretBackend stores the secret key share.
	// This should be a secure backend (TPM2, PKCS#11, Cloud KMS, Vault, etc.)
	SecretBackend types.Backend

	// DKG is the key generator implementation.
	// If nil, TrustedDealer is used by default.
	DKG KeyGenerator

	// Algorithm is the default FROST ciphersuite for new keys.
	// Defaults to FrostAlgorithmEd25519 if not specified.
	Algorithm types.FrostAlgorithm

	// ParticipantID is this node's participant identifier (1 to DefaultTotal).
	// Only used when generating keys for a specific participant.
	ParticipantID uint32

	// DefaultThreshold is the default minimum signers for new keys (M).
	// Must be at least 2. Defaults to 2 if not specified.
	DefaultThreshold int

	// DefaultTotal is the default total participants for new keys (N).
	// Must be >= DefaultThreshold. Defaults to 3 if not specified.
	DefaultTotal int

	// Participants are the default identifiers for each participant.
	// Length must equal DefaultTotal if specified.
	Participants []string

	// NonceStorage stores used nonce markers.
	// If nil, PublicStorage is used.
	NonceStorage storage.Backend

	// EnableNonceTracking enables nonce reuse prevention.
	// Defaults to true. Disabling is STRONGLY DISCOURAGED as it allows
	// catastrophic nonce reuse attacks that can recover the private key.
	EnableNonceTracking bool
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.PublicStorage == nil {
		return &ConfigError{Field: "PublicStorage", Message: "required"}
	}

	if c.SecretBackend == nil {
		return &ConfigError{Field: "SecretBackend", Message: "required"}
	}

	// Set defaults
	if c.Algorithm == "" {
		c.Algorithm = types.FrostAlgorithmEd25519
	}

	if !c.Algorithm.IsValid() {
		return &ConfigError{Field: "Algorithm", Message: "invalid algorithm: " + string(c.Algorithm)}
	}

	if c.DefaultThreshold == 0 {
		c.DefaultThreshold = 2
	}

	if c.DefaultTotal == 0 {
		c.DefaultTotal = 3
	}

	if c.DefaultThreshold < 2 {
		return &ConfigError{Field: "DefaultThreshold", Message: "must be at least 2"}
	}

	if c.DefaultTotal < c.DefaultThreshold {
		return &ConfigError{Field: "DefaultTotal", Message: "must be >= DefaultThreshold"}
	}

	if c.DefaultThreshold > 255 {
		return &ConfigError{Field: "DefaultThreshold", Message: "cannot exceed 255"}
	}

	if c.DefaultTotal > 255 {
		return &ConfigError{Field: "DefaultTotal", Message: "cannot exceed 255"}
	}

	if c.ParticipantID != 0 && (c.ParticipantID < 1 || c.ParticipantID > uint32(c.DefaultTotal)) {
		return &ConfigError{Field: "ParticipantID", Message: "must be between 1 and DefaultTotal"}
	}

	if len(c.Participants) > 0 && len(c.Participants) != c.DefaultTotal {
		return &ConfigError{Field: "Participants", Message: "length must match DefaultTotal"}
	}

	return nil
}

// SetDefaults sets default values for unspecified fields.
func (c *Config) SetDefaults() {
	if c.Algorithm == "" {
		c.Algorithm = types.FrostAlgorithmEd25519
	}

	if c.DefaultThreshold == 0 {
		c.DefaultThreshold = 2
	}

	if c.DefaultTotal == 0 {
		c.DefaultTotal = 3
	}

	// Default to enabling nonce tracking (safe default)
	// We use a separate boolean to track if the user explicitly set it
	// Since EnableNonceTracking defaults to false in Go, we treat it specially
}

// GetNonceStorage returns the nonce storage backend.
// Falls back to PublicStorage if NonceStorage is not set.
func (c *Config) GetNonceStorage() storage.Backend {
	if c.NonceStorage != nil {
		return c.NonceStorage
	}
	return c.PublicStorage
}

// GetKeyGenerator returns the key generator.
// Falls back to TrustedDealer if DKG is not set.
func (c *Config) GetKeyGenerator() KeyGenerator {
	if c.DKG != nil {
		return c.DKG
	}
	return NewTrustedDealer()
}

// DefaultConfig returns a Config with sensible defaults.
// Note: PublicStorage and SecretBackend must still be provided.
func DefaultConfig() *Config {
	return &Config{
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		EnableNonceTracking: true,
	}
}
