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

// Package keyprovider provides partial key provider implementations that are
// composed into full-service backends. Key providers support key generation
// and limited cryptographic operations but do not implement the full backend
// interface. They handle cryptographic operations without certificate
// management, seal/unseal, or key metadata storage capabilities.
//
// Key providers are designed to be composed with other components to build
// complete backend solutions. Each provider focuses on a specific key storage
// or cryptographic operation domain.
//
// Sub-packages:
//
//   - pkcs8: PKCS#8 encoded key storage (file or memory)
//   - symmetric: AES-GCM and ChaCha20-Poly1305 symmetric encryption
//   - quantum: Post-quantum cryptography (ML-DSA, ML-KEM)
//   - frost: FROST threshold signatures (RFC 9591)
//   - threshold: Threshold cryptography (Shamir secret sharing, threshold ECDSA)
package keyprovider
