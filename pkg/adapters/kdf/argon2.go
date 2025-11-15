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
	"golang.org/x/crypto/argon2"
)

const (
	// MinArgon2SaltLength is the minimum recommended salt length in bytes
	MinArgon2SaltLength = 16

	// MinArgon2Memory is the minimum memory cost in KiB
	MinArgon2Memory = 8 * 1024 // 8 MiB

	// MinArgon2Time is the minimum time cost
	MinArgon2Time = 1

	// MinArgon2Threads is the minimum number of threads
	MinArgon2Threads = 1
)

// Argon2Adapter implements the KDFAdapter interface using Argon2
// Argon2 is the winner of the Password Hashing Competition and provides
// excellent resistance against GPU-based attacks
type Argon2Adapter struct {
	variant KDFAlgorithm
}

// NewArgon2Adapter creates a new Argon2 adapter with the specified variant
// Supported variants: AlgorithmArgon2i, AlgorithmArgon2id
// AlgorithmArgon2id is recommended for most use cases (hybrid approach)
func NewArgon2Adapter(variant KDFAlgorithm) *Argon2Adapter {
	if variant != AlgorithmArgon2i && variant != AlgorithmArgon2id {
		// Default to Argon2id which is the recommended variant
		variant = AlgorithmArgon2id
	}
	return &Argon2Adapter{
		variant: variant,
	}
}

// NewArgon2iAdapter creates a new Argon2i adapter
// Argon2i is optimized to resist side-channel attacks
func NewArgon2iAdapter() *Argon2Adapter {
	return &Argon2Adapter{
		variant: AlgorithmArgon2i,
	}
}

// NewArgon2idAdapter creates a new Argon2id adapter
// Argon2id is a hybrid of Argon2i and Argon2d, recommended for most use cases
func NewArgon2idAdapter() *Argon2Adapter {
	return &Argon2Adapter{
		variant: AlgorithmArgon2id,
	}
}

// DeriveKey derives a key using Argon2
func (a *Argon2Adapter) DeriveKey(ikm []byte, params *KDFParams) ([]byte, error) {
	if err := a.ValidateParams(params); err != nil {
		return nil, err
	}

	if len(ikm) == 0 {
		return nil, ErrInvalidIKM
	}

	var key []byte

	switch a.variant {
	case AlgorithmArgon2i:
		key = argon2.Key(
			ikm,
			params.Salt,
			params.Time,
			params.Memory,
			params.Threads,
			uint32(params.KeyLength),
		)
	case AlgorithmArgon2id:
		key = argon2.IDKey(
			ikm,
			params.Salt,
			params.Time,
			params.Memory,
			params.Threads,
			uint32(params.KeyLength),
		)
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	return key, nil
}

// Algorithm returns the KDF algorithm
func (a *Argon2Adapter) Algorithm() KDFAlgorithm {
	return a.variant
}

// ValidateParams validates Argon2 parameters
func (a *Argon2Adapter) ValidateParams(params *KDFParams) error {
	if params == nil {
		return ErrInvalidKeyLength
	}

	// Check if algorithm matches this adapter's variant
	if params.Algorithm != a.variant {
		// Also accept generic Argon2 algorithm and use the adapter's variant
		if params.Algorithm != AlgorithmArgon2 {
			return ErrUnsupportedAlgorithm
		}
	}

	if params.KeyLength <= 0 {
		return ErrInvalidKeyLength
	}

	if len(params.Salt) < MinArgon2SaltLength {
		return ErrInvalidSalt
	}

	if params.Memory < MinArgon2Memory {
		return ErrInvalidMemory
	}

	if params.Time < MinArgon2Time {
		return ErrInvalidTime
	}

	if params.Threads < MinArgon2Threads {
		return ErrInvalidThreads
	}

	return nil
}
