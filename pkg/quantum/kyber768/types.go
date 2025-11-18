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

//go:build quantum

package kyber768

import "crypto/x509"

// Kyber768KeyAlgorithm represents the Kyber768 key algorithm type
type Kyber768KeyAlgorithm x509.PublicKeyAlgorithm

// String returns the string representation of the algorithm
func (pka Kyber768KeyAlgorithm) String() string {
	return "Kyber768"
}

// Kyber768KEMAlgorithm represents the Kyber768 KEM algorithm type
type Kyber768KEMAlgorithm int

// String returns the string representation of the KEM algorithm
func (pka Kyber768KEMAlgorithm) String() string {
	return "Kyber768"
}
