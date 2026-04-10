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

package mldsa87

import "crypto/x509"

// MLDSA87KeyAlgorithm represents the ML-DSA-87 key algorithm type
type MLDSA87KeyAlgorithm x509.PublicKeyAlgorithm

// String returns the string representation of the algorithm
func (pka MLDSA87KeyAlgorithm) String() string {
	return "ML-DSA-87"
}

// MLDSA87SignatureAlgorithm represents the ML-DSA-87 signature algorithm type
type MLDSA87SignatureAlgorithm int

// String returns the string representation of the signature algorithm
func (pka MLDSA87SignatureAlgorithm) String() string {
	return "ML-DSA-87"
}
