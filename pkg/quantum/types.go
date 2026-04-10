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

// Package quantum provides quantum-safe cryptography support using
// post-quantum algorithms: ML-DSA (signatures) and ML-KEM (key encapsulation).
package quantum

// Algorithm represents a quantum-safe cryptographic algorithm
type Algorithm int

const (
	// ALGORITHM_DILITHIUM2 is the ML-DSA-44 signature algorithm (Dilithium2)
	ALGORITHM_DILITHIUM2 Algorithm = 1 + iota
	// ALGORITHM_KYBER768 is the ML-KEM-768 key encapsulation algorithm (Kyber768)
	ALGORITHM_KYBER768
	// ALGORITHM_MLDSA65 is the ML-DSA-65 signature algorithm
	ALGORITHM_MLDSA65
	// ALGORITHM_MLDSA87 is the ML-DSA-87 signature algorithm
	ALGORITHM_MLDSA87
	// ALGORITHM_MLKEM1024 is the ML-KEM-1024 key encapsulation algorithm
	ALGORITHM_MLKEM1024
)

var algorithmNames = map[Algorithm]string{
	ALGORITHM_DILITHIUM2: "Dilithium2",
	ALGORITHM_KYBER768:   "Kyber768",
	ALGORITHM_MLDSA65:    "MLDSA65",
	ALGORITHM_MLDSA87:    "MLDSA87",
	ALGORITHM_MLKEM1024:  "MLKEM1024",
}

var algorithmTypes = map[Algorithm]string{
	ALGORITHM_DILITHIUM2: "signature",
	ALGORITHM_KYBER768:   "kem",
	ALGORITHM_MLDSA65:    "signature",
	ALGORITHM_MLDSA87:    "signature",
	ALGORITHM_MLKEM1024:  "kem",
}

// String returns the string representation of the algorithm
func (algo Algorithm) String() string {
	if name, ok := algorithmNames[algo]; ok {
		return name
	}
	return "Unknown"
}

// Type returns the type of the quantum algorithm
func (algo Algorithm) Type() string {
	if t, ok := algorithmTypes[algo]; ok {
		return t
	}
	return "unknown"
}

// IsSignature returns true if the algorithm is a signature algorithm
func (algo Algorithm) IsSignature() bool {
	return algorithmTypes[algo] == "signature"
}

// IsKEM returns true if the algorithm is a key encapsulation mechanism
func (algo Algorithm) IsKEM() bool {
	return algorithmTypes[algo] == "kem"
}
