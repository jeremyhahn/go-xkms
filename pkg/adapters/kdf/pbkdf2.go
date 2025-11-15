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

package kdf

import (
	"golang.org/x/crypto/pbkdf2"
)

const (
	// MinPBKDF2Iterations is the minimum recommended iteration count
	MinPBKDF2Iterations = 100000

	// MinPBKDF2SaltLength is the minimum recommended salt length in bytes
	MinPBKDF2SaltLength = 16
)

// PBKDF2Adapter implements the KDFAdapter interface using PBKDF2 (RFC 2898)
// PBKDF2 is suitable for deriving keys from passwords
type PBKDF2Adapter struct{}

// NewPBKDF2Adapter creates a new PBKDF2 adapter
func NewPBKDF2Adapter() *PBKDF2Adapter {
	return &PBKDF2Adapter{}
}

// DeriveKey derives a key using PBKDF2
func (p *PBKDF2Adapter) DeriveKey(ikm []byte, params *KDFParams) ([]byte, error) {
	if err := p.ValidateParams(params); err != nil {
		return nil, err
	}

	if len(ikm) == 0 {
		return nil, ErrInvalidIKM
	}

	// Derive key using PBKDF2
	key := pbkdf2.Key(ikm, params.Salt, params.Iterations, params.KeyLength, params.Hash.New)

	return key, nil
}

// Algorithm returns the KDF algorithm
func (p *PBKDF2Adapter) Algorithm() KDFAlgorithm {
	return AlgorithmPBKDF2
}

// ValidateParams validates PBKDF2 parameters
func (p *PBKDF2Adapter) ValidateParams(params *KDFParams) error {
	if params == nil {
		return ErrInvalidKeyLength
	}

	if params.Algorithm != AlgorithmPBKDF2 {
		return ErrUnsupportedAlgorithm
	}

	if params.KeyLength <= 0 {
		return ErrInvalidKeyLength
	}

	if len(params.Salt) < MinPBKDF2SaltLength {
		return ErrInvalidSalt
	}

	if params.Iterations < MinPBKDF2Iterations {
		return ErrInvalidIterations
	}

	// Validate hash function
	if params.Hash == 0 {
		return ErrInvalidHash
	}

	// Check if hash size is valid (must be linked)
	if params.Hash.Size() == 0 {
		return ErrInvalidHash
	}

	return nil
}
