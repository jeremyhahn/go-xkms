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

// Package module provides post-quantum cryptography backend registration for PKCS#11.
//
// The quantum backend provides post-quantum cryptographic algorithms including:
//   - ML-DSA (formerly Dilithium) for digital signatures (FIPS 204)
//   - ML-KEM (formerly Kyber) for key encapsulation (FIPS 203)
//
// This backend uses pure-Go implementations: crypto/mldsa for ML-DSA-44/65/87,
// cloudflare/circl for ML-KEM-512 (crypto/mlkem has no 512 parameter set), and
// crypto/mlkem for ML-KEM-768/1024. No CGO or external libraries required.
package module

func init() {
	RegisterBackend(BackendQuantum)
}
