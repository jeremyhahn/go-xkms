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

package mlkem1024

import "crypto/x509"

// MLKEM1024KeyAlgorithm represents the ML-KEM-1024 key algorithm type
type MLKEM1024KeyAlgorithm x509.PublicKeyAlgorithm

// String returns the string representation of the algorithm
func (pka MLKEM1024KeyAlgorithm) String() string {
	return "MLKEM1024"
}

// MLKEM1024KEMAlgorithm represents the ML-KEM-1024 KEM algorithm type
type MLKEM1024KEMAlgorithm int

// String returns the string representation of the KEM algorithm
func (pka MLKEM1024KEMAlgorithm) String() string {
	return "MLKEM1024"
}
