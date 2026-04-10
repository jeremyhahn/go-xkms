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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
)

// ---------------------------------------------------------------------------
// Quantum backend (from pkg/backend/quantum/)
//
// Post-quantum cryptographic backend supporting ML-DSA for digital signatures
// and ML-KEM for key encapsulation. Uses pure-Go implementations (circl, crypto/mlkem).
// ---------------------------------------------------------------------------

// QuantumBackend implements the Backend interface for post-quantum
// cryptography using ML-DSA (signing) and ML-KEM (key encapsulation).
type QuantumBackend = quantum.QuantumBackend

// QuantumBackendConfig holds configuration for the quantum backend.
type QuantumBackendConfig = quantum.Config

// NewQuantumBackend creates a new QuantumBackend with the given storage
// backend and default configuration.
var NewQuantumBackend = quantum.New

// NewQuantumBackendWithConfig creates a new QuantumBackend with the given
// storage backend and explicit configuration.
var NewQuantumBackendWithConfig = quantum.NewWithConfig

// MLDSAPrivateKey represents a post-quantum ML-DSA private key that
// implements crypto.Signer for signing operations.
type MLDSAPrivateKey = quantum.MLDSAPrivateKey

// MLDSAPublicKey represents a post-quantum ML-DSA public key.
type MLDSAPublicKey = quantum.MLDSAPublicKey

// MLKEMPrivateKey represents a post-quantum ML-KEM private key for key
// encapsulation and hybrid encryption (ML-KEM + AES-256-GCM).
type MLKEMPrivateKey = quantum.MLKEMPrivateKey

// MLKEMPublicKey represents a post-quantum ML-KEM public key.
type MLKEMPublicKey = quantum.MLKEMPublicKey
