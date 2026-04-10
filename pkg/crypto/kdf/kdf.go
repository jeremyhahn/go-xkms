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

package kdf

import (
	"crypto"
	"errors"
)

// KDFAlgorithm represents the key derivation function algorithm type
type KDFAlgorithm string

const (
	// AlgorithmHKDF represents HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)
	AlgorithmHKDF KDFAlgorithm = "HKDF"

	// AlgorithmPBKDF2 represents Password-Based Key Derivation Function 2 (RFC 2898)
	AlgorithmPBKDF2 KDFAlgorithm = "PBKDF2"

	// AlgorithmArgon2 represents Argon2 (winner of the Password Hashing Competition)
	AlgorithmArgon2 KDFAlgorithm = "Argon2"

	// AlgorithmArgon2i represents Argon2i variant (optimized against side-channel attacks)
	AlgorithmArgon2i KDFAlgorithm = "Argon2i"

	// AlgorithmArgon2id represents Argon2id variant (hybrid of Argon2i and Argon2d)
	AlgorithmArgon2id KDFAlgorithm = "Argon2id"

	// AlgorithmSP800108Counter represents NIST SP 800-108 Counter Mode KDF
	AlgorithmSP800108Counter KDFAlgorithm = "SP800-108-COUNTER"

	// AlgorithmSP800108Feedback represents NIST SP 800-108 Feedback Mode KDF
	AlgorithmSP800108Feedback KDFAlgorithm = "SP800-108-FEEDBACK"

	// AlgorithmSP800108DoublePipeline represents NIST SP 800-108 Double-Pipeline Mode KDF
	AlgorithmSP800108DoublePipeline KDFAlgorithm = "SP800-108-DOUBLE-PIPELINE"
)

// String returns the string representation of the KDF algorithm
func (a KDFAlgorithm) String() string {
	return string(a)
}

// KDFParams contains parameters for key derivation
type KDFParams struct {
	// Algorithm specifies which KDF algorithm to use
	Algorithm KDFAlgorithm

	// Salt is the cryptographic salt (should be random and unique per key)
	Salt []byte

	// Info is additional context and application-specific information (HKDF only)
	Info []byte

	// Iterations specifies the number of iterations (PBKDF2 only)
	Iterations int

	// Memory is the memory cost in KiB (Argon2 only)
	Memory uint32

	// Threads is the number of parallel threads (Argon2 only)
	Threads uint8

	// Time is the time cost/iterations (Argon2 only)
	Time uint32

	// KeyLength is the desired output key length in bytes
	KeyLength int

	// Hash is the hash function to use (HKDF, PBKDF2, SP800-108)
	Hash crypto.Hash

	// Label is the label/purpose string (SP800-108 only)
	Label []byte

	// Context is the context/application-specific info (SP800-108 only)
	Context []byte

	// CounterLength is the length of counter in bits: 8, 16, 24, or 32 (SP800-108 only)
	// Default is 32 bits
	CounterLength int

	// CounterLocation specifies where the counter appears in the PRF input (SP800-108 only)
	// "before" = counter before fixed data, "after" = counter after fixed data
	// Default is "before"
	CounterLocation string

	// IV is the initial value for feedback mode (SP800-108 Feedback only)
	IV []byte
}

// KDFAdapter is the interface for key derivation function adapters
// Applications implement this interface to integrate their KDF implementation
type KDFAdapter interface {
	// DeriveKey derives a key from the input key material using the specified parameters
	// Returns the derived key or an error if derivation fails
	DeriveKey(ikm []byte, params *KDFParams) ([]byte, error)

	// Algorithm returns the KDF algorithm this adapter implements
	Algorithm() KDFAlgorithm

	// ValidateParams validates the KDF parameters for this algorithm
	// Returns an error if parameters are invalid or incompatible
	ValidateParams(params *KDFParams) error
}

// Common errors
var (
	// ErrInvalidSalt indicates the salt is invalid (nil, empty, or too short)
	ErrInvalidSalt = errors.New("kdf: invalid salt")

	// ErrInvalidKeyLength indicates the requested key length is invalid
	ErrInvalidKeyLength = errors.New("kdf: invalid key length")

	// ErrInvalidIterations indicates the iteration count is invalid
	ErrInvalidIterations = errors.New("kdf: invalid iterations")

	// ErrInvalidMemory indicates the memory cost is invalid
	ErrInvalidMemory = errors.New("kdf: invalid memory cost")

	// ErrInvalidThreads indicates the thread count is invalid
	ErrInvalidThreads = errors.New("kdf: invalid threads")

	// ErrInvalidTime indicates the time cost is invalid
	ErrInvalidTime = errors.New("kdf: invalid time cost")

	// ErrInvalidHash indicates the hash function is invalid or not supported
	ErrInvalidHash = errors.New("kdf: invalid or unsupported hash function")

	// ErrInvalidIKM indicates the input key material is invalid
	ErrInvalidIKM = errors.New("kdf: invalid input key material")

	// ErrUnsupportedAlgorithm indicates the algorithm is not supported by this adapter
	ErrUnsupportedAlgorithm = errors.New("kdf: unsupported algorithm")

	// ErrInvalidLabel indicates the label is invalid (SP800-108)
	ErrInvalidLabel = errors.New("kdf: invalid label")

	// ErrInvalidContext indicates the context is invalid (SP800-108)
	ErrInvalidContext = errors.New("kdf: invalid context")

	// ErrInvalidCounterLength indicates the counter length is invalid (SP800-108)
	ErrInvalidCounterLength = errors.New("kdf: invalid counter length (must be 8, 16, 24, or 32)")

	// ErrOutputTooLong indicates the requested output exceeds maximum allowed
	ErrOutputTooLong = errors.New("kdf: requested output length exceeds maximum")
)

// DefaultParams returns recommended default parameters for each KDF algorithm
func DefaultParams(algorithm KDFAlgorithm) *KDFParams {
	switch algorithm {
	case AlgorithmHKDF:
		return &KDFParams{
			Algorithm: AlgorithmHKDF,
			KeyLength: 32,
			Hash:      crypto.SHA256,
		}
	case AlgorithmPBKDF2:
		return &KDFParams{
			Algorithm:  AlgorithmPBKDF2,
			Iterations: 600000, // OWASP recommendation for PBKDF2-SHA256 (2023)
			KeyLength:  32,
			Hash:       crypto.SHA256,
		}
	case AlgorithmArgon2, AlgorithmArgon2id:
		return &KDFParams{
			Algorithm: AlgorithmArgon2id,
			Memory:    64 * 1024, // 64 MiB
			Time:      3,
			Threads:   4,
			KeyLength: 32,
		}
	case AlgorithmArgon2i:
		return &KDFParams{
			Algorithm: AlgorithmArgon2i,
			Memory:    64 * 1024, // 64 MiB
			Time:      3,
			Threads:   4,
			KeyLength: 32,
		}
	case AlgorithmSP800108Counter, AlgorithmSP800108Feedback, AlgorithmSP800108DoublePipeline:
		return &KDFParams{
			Algorithm:       algorithm,
			KeyLength:       32,
			Hash:            crypto.SHA256,
			CounterLength:   32,
			CounterLocation: "before",
		}
	default:
		return nil
	}
}
