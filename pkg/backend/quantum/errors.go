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

package quantum

import "errors"

var (
	// ErrStorageClosed indicates the backend storage has been closed
	ErrStorageClosed = errors.New("quantum: storage is closed")

	// ErrKeyNotSigner indicates the key does not implement crypto.Signer
	ErrKeyNotSigner = errors.New("quantum: key is not a signer (only ML-DSA keys support signing)")

	// ErrKeyNotDecrypter indicates the key does not support decryption
	ErrKeyNotDecrypter = errors.New("quantum: key is not a decrypter (ML-KEM keys use encapsulation, not direct decryption)")

	// ErrUnsupportedAlgorithm indicates an unsupported quantum algorithm
	ErrUnsupportedAlgorithm = errors.New("quantum: unsupported quantum algorithm")

	// ErrInvalidQuantumAttributes indicates missing or invalid quantum attributes
	ErrInvalidQuantumAttributes = errors.New("quantum: QuantumAttributes required for quantum-safe operations")

	// ErrSigningFailed indicates a signature operation failed
	ErrSigningFailed = errors.New("quantum: signing operation failed")

	// ErrVerificationFailed indicates signature verification failed
	ErrVerificationFailed = errors.New("quantum: verification failed")

	// ErrEncapsulationFailed indicates key encapsulation failed
	ErrEncapsulationFailed = errors.New("quantum: encapsulation failed")

	// ErrDecapsulationFailed indicates key decapsulation failed
	ErrDecapsulationFailed = errors.New("quantum: decapsulation failed")

	// ErrNotInitialized indicates the cryptographic primitive is not initialized
	ErrNotInitialized = errors.New("quantum: not initialized")
)
