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

package types

// AlgorithmInfo describes a cryptographic algorithm and the backends that
// support it. It is used by the algorithm discovery endpoint to report
// available capabilities at runtime.
type AlgorithmInfo struct {
	// Algorithm is the canonical algorithm name (e.g., "ECDSA", "RSA", "ML-DSA-65").
	Algorithm string `json:"algorithm"`

	// Curves lists the supported elliptic curves, if applicable (e.g., ["P-256", "P-384"]).
	Curves []string `json:"curves,omitempty"`

	// KeySizes lists the supported key sizes in bits, if applicable (e.g., [2048, 3072, 4096]).
	KeySizes []int `json:"key_sizes,omitempty"`

	// Backends lists the backend identifiers that support this algorithm.
	Backends []string `json:"backends"`

	// PostQuantum indicates whether this algorithm is a post-quantum algorithm.
	PostQuantum bool `json:"post_quantum,omitempty"`
}

// AlgorithmsResponse is the top-level response for the algorithm discovery
// endpoint. It groups algorithms by their primary purpose.
type AlgorithmsResponse struct {
	// Signing lists algorithms available for digital signature operations.
	Signing []AlgorithmInfo `json:"signing"`

	// KeyEncapsulation lists algorithms available for key encapsulation mechanisms.
	KeyEncapsulation []AlgorithmInfo `json:"key_encapsulation"`
}
