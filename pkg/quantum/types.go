//go:build quantum

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

// Package quantum provides quantum-safe cryptography support using
// post-quantum algorithms like Dilithium (signatures) and Kyber (KEM).
package quantum

// Algorithm represents a quantum-safe cryptographic algorithm
type Algorithm int

const (
	// ALGORITHM_DILITHIUM2 is the Dilithium2 signature algorithm
	ALGORITHM_DILITHIUM2 Algorithm = 1 + iota
	// ALGORITHM_KYBER768 is the Kyber768 key encapsulation algorithm
	ALGORITHM_KYBER768
)

// String returns the string representation of the algorithm
func (algo Algorithm) String() string {
	switch algo {
	case ALGORITHM_DILITHIUM2:
		return "Dilithium2"
	case ALGORITHM_KYBER768:
		return "Kyber768"
	default:
		return "Unknown"
	}
}

// Type returns the type of the quantum algorithm
func (algo Algorithm) Type() string {
	switch algo {
	case ALGORITHM_DILITHIUM2:
		return "signature"
	case ALGORITHM_KYBER768:
		return "kem"
	default:
		return "unknown"
	}
}

// IsSignature returns true if the algorithm is a signature algorithm
func (algo Algorithm) IsSignature() bool {
	return algo == ALGORITHM_DILITHIUM2
}

// IsKEM returns true if the algorithm is a key encapsulation mechanism
func (algo Algorithm) IsKEM() bool {
	return algo == ALGORITHM_KYBER768
}
