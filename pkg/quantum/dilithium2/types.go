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

package dilithium2

import "crypto/x509"

// Dilithium2KeyAlgorithm represents the Dilithium2 key algorithm type
type Dilithium2KeyAlgorithm x509.PublicKeyAlgorithm

// String returns the string representation of the algorithm
func (pka Dilithium2KeyAlgorithm) String() string {
	return "Dilithium2"
}

// Dilithium2SignatureAlgorithm represents the Dilithium2 signature algorithm type
type Dilithium2SignatureAlgorithm int

// String returns the string representation of the signature algorithm
func (pka Dilithium2SignatureAlgorithm) String() string {
	return "Dilithium2"
}
