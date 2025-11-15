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
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDFAdapter implements the KDFAdapter interface using HKDF (RFC 5869)
// HKDF is suitable for deriving keys from high-entropy sources like
// shared secrets from key exchange protocols (ECDH, etc.)
type HKDFAdapter struct{}

// NewHKDFAdapter creates a new HKDF adapter
func NewHKDFAdapter() *HKDFAdapter {
	return &HKDFAdapter{}
}

// DeriveKey derives a key using HKDF
func (h *HKDFAdapter) DeriveKey(ikm []byte, params *KDFParams) ([]byte, error) {
	if err := h.ValidateParams(params); err != nil {
		return nil, err
	}

	if len(ikm) == 0 {
		return nil, ErrInvalidIKM
	}

	// Create HKDF reader
	hash := params.Hash.New
	kdf := hkdf.New(hash, ikm, params.Salt, params.Info)

	// Derive key
	key := make([]byte, params.KeyLength)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}

	return key, nil
}

// Algorithm returns the KDF algorithm
func (h *HKDFAdapter) Algorithm() KDFAlgorithm {
	return AlgorithmHKDF
}

// ValidateParams validates HKDF parameters
func (h *HKDFAdapter) ValidateParams(params *KDFParams) error {
	if params == nil {
		return ErrInvalidKeyLength
	}

	if params.Algorithm != AlgorithmHKDF {
		return ErrUnsupportedAlgorithm
	}

	if params.KeyLength <= 0 {
		return ErrInvalidKeyLength
	}

	// Validate hash function
	if params.Hash == 0 {
		return ErrInvalidHash
	}

	// Check if hash size is valid (must be linked)
	if params.Hash.Size() == 0 {
		return ErrInvalidHash
	}

	// Validate key length against hash size
	if params.KeyLength > 255*params.Hash.Size() {
		return ErrInvalidKeyLength
	}

	// Salt is optional in HKDF but recommended
	// Info is optional and can be nil

	return nil
}
