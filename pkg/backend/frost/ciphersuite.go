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
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed25519_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ed448_shake256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/p256_sha256"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/ristretto255_sha512"
	"github.com/jeremyhahn/go-frost/pkg/frost/ciphersuite/secp256k1_sha256"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// GetCiphersuite returns the go-frost Ciphersuite for a given FrostAlgorithm.
// Returns an error if the algorithm is not supported.
func GetCiphersuite(algorithm types.FrostAlgorithm) (ciphersuite.Ciphersuite, error) {
	switch algorithm {
	case types.FrostAlgorithmEd25519:
		return ed25519_sha512.New(), nil
	case types.FrostAlgorithmRistretto255:
		return ristretto255_sha512.New(), nil
	case types.FrostAlgorithmEd448:
		return ed448_shake256.New(), nil
	case types.FrostAlgorithmP256:
		return p256_sha256.New(), nil
	case types.FrostAlgorithmSecp256k1:
		return secp256k1_sha256.New(), nil
	default:
		return nil, &AlgorithmError{Algorithm: string(algorithm)}
	}
}

// GetCiphersuiteID returns the RFC 9591 ciphersuite identifier.
func GetCiphersuiteID(algorithm types.FrostAlgorithm) string {
	switch algorithm {
	case types.FrostAlgorithmEd25519:
		return "FROST-ED25519-SHA512-v1"
	case types.FrostAlgorithmRistretto255:
		return "FROST-RISTRETTO255-SHA512-v1"
	case types.FrostAlgorithmEd448:
		return "FROST-ED448-SHAKE256-v1"
	case types.FrostAlgorithmP256:
		return "FROST-P256-SHA256-v1"
	case types.FrostAlgorithmSecp256k1:
		return "FROST-secp256k1-SHA256-v1"
	default:
		return ""
	}
}

// GetSignatureSize returns the signature size in bytes for the given algorithm.
func GetSignatureSize(algorithm types.FrostAlgorithm) int {
	switch algorithm {
	case types.FrostAlgorithmEd25519:
		return 64 // 32 bytes R + 32 bytes s
	case types.FrostAlgorithmRistretto255:
		return 64 // 32 bytes R + 32 bytes s
	case types.FrostAlgorithmEd448:
		return 114 // 57 bytes R + 57 bytes s
	case types.FrostAlgorithmP256:
		return 64 // 32 bytes R + 32 bytes s
	case types.FrostAlgorithmSecp256k1:
		return 64 // 32 bytes R + 32 bytes s
	default:
		return 0
	}
}

// GetPublicKeySize returns the public key size in bytes for the given algorithm.
func GetPublicKeySize(algorithm types.FrostAlgorithm) int {
	switch algorithm {
	case types.FrostAlgorithmEd25519:
		return 32
	case types.FrostAlgorithmRistretto255:
		return 32
	case types.FrostAlgorithmEd448:
		return 57
	case types.FrostAlgorithmP256:
		return 33 // compressed point
	case types.FrostAlgorithmSecp256k1:
		return 33 // compressed point
	default:
		return 0
	}
}

// GetScalarSize returns the scalar size in bytes for the given algorithm.
func GetScalarSize(algorithm types.FrostAlgorithm) int {
	switch algorithm {
	case types.FrostAlgorithmEd25519:
		return 32
	case types.FrostAlgorithmRistretto255:
		return 32
	case types.FrostAlgorithmEd448:
		return 57
	case types.FrostAlgorithmP256:
		return 32
	case types.FrostAlgorithmSecp256k1:
		return 32
	default:
		return 0
	}
}

// AlgorithmInfo contains metadata about a FROST algorithm.
type AlgorithmInfo struct {
	Algorithm     types.FrostAlgorithm
	CiphersuiteID string
	ScalarSize    int
	PublicKeySize int
	SignatureSize int
	Description   string
}

// GetAlgorithmInfo returns detailed information about a FROST algorithm.
func GetAlgorithmInfo(algorithm types.FrostAlgorithm) *AlgorithmInfo {
	switch algorithm {
	case types.FrostAlgorithmEd25519:
		return &AlgorithmInfo{
			Algorithm:     algorithm,
			CiphersuiteID: "FROST-ED25519-SHA512-v1",
			ScalarSize:    32,
			PublicKeySize: 32,
			SignatureSize: 64,
			Description:   "Ed25519 with SHA-512 - General purpose, high performance",
		}
	case types.FrostAlgorithmRistretto255:
		return &AlgorithmInfo{
			Algorithm:     algorithm,
			CiphersuiteID: "FROST-RISTRETTO255-SHA512-v1",
			ScalarSize:    32,
			PublicKeySize: 32,
			SignatureSize: 64,
			Description:   "ristretto255 with SHA-512 - Enhanced security properties",
		}
	case types.FrostAlgorithmEd448:
		return &AlgorithmInfo{
			Algorithm:     algorithm,
			CiphersuiteID: "FROST-ED448-SHAKE256-v1",
			ScalarSize:    57,
			PublicKeySize: 57,
			SignatureSize: 114,
			Description:   "Ed448 with SHAKE256 - Higher security level (224-bit)",
		}
	case types.FrostAlgorithmP256:
		return &AlgorithmInfo{
			Algorithm:     algorithm,
			CiphersuiteID: "FROST-P256-SHA256-v1",
			ScalarSize:    32,
			PublicKeySize: 33,
			SignatureSize: 64,
			Description:   "NIST P-256 with SHA-256 - FIPS compliance",
		}
	case types.FrostAlgorithmSecp256k1:
		return &AlgorithmInfo{
			Algorithm:     algorithm,
			CiphersuiteID: "FROST-secp256k1-SHA256-v1",
			ScalarSize:    32,
			PublicKeySize: 33,
			SignatureSize: 64,
			Description:   "secp256k1 with SHA-256 - Bitcoin/Ethereum compatibility",
		}
	default:
		return nil
	}
}

// ListSupportedAlgorithms returns all supported FROST algorithms.
func ListSupportedAlgorithms() []types.FrostAlgorithm {
	return []types.FrostAlgorithm{
		types.FrostAlgorithmEd25519,
		types.FrostAlgorithmRistretto255,
		types.FrostAlgorithmEd448,
		types.FrostAlgorithmP256,
		types.FrostAlgorithmSecp256k1,
	}
}

// DefaultAlgorithm returns the default FROST algorithm (Ed25519).
func DefaultAlgorithm() types.FrostAlgorithm {
	return types.FrostAlgorithmEd25519
}
