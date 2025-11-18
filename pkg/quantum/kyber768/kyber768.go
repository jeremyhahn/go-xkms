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

// Package kyber768 provides Kyber768 quantum-safe key encapsulation mechanism (KEM)
// using the liboqs library. Kyber is a NIST PQC standard for key encapsulation.
package kyber768

import (
	"errors"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
	// AlgorithmName is the OQS algorithm identifier for Kyber768
	// Using ML-KEM-768 which is the NIST FIPS 203 standard name for Kyber768
	AlgorithmName = "ML-KEM-768"
)

var (
	// ErrNotInitialized indicates the KEM has not been initialized
	ErrNotInitialized = errors.New("kyber768: KEM not initialized")
	// ErrInvalidSecretKey indicates an invalid secret key was provided
	ErrInvalidSecretKey = errors.New("kyber768: invalid secret key")
	// ErrEncapsulationFailed indicates encapsulation operation failed
	ErrEncapsulationFailed = errors.New("kyber768: encapsulation failed")
	// ErrDecapsulationFailed indicates decapsulation operation failed
	ErrDecapsulationFailed = errors.New("kyber768: decapsulation failed")
)

// Kyber768 wraps the liboqs Kyber768 key encapsulation mechanism
type Kyber768 struct {
	kem *oqs.KeyEncapsulation
}

// New creates a new uninitialized Kyber768 instance
func New() (*Kyber768, error) {
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(AlgorithmName, nil); err != nil {
		return nil, err
	}
	return &Kyber768{kem: &kem}, nil
}

// Create initializes Kyber768 with an existing secret key
func Create(secretKey []byte) (*Kyber768, error) {
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(AlgorithmName, secretKey); err != nil {
		return nil, ErrInvalidSecretKey
	}
	return &Kyber768{kem: &kem}, nil
}

// Clean releases resources held by the KEM
// This should always be called when done using the instance
func (k *Kyber768) Clean() {
	if k.kem != nil {
		k.kem.Clean()
	}
}

// GenerateKeyPair generates a new Kyber768 key pair
// Returns the public key; the secret key is stored internally
func (k *Kyber768) GenerateKeyPair() ([]byte, error) {
	if k.kem == nil {
		return nil, ErrNotInitialized
	}
	return k.kem.GenerateKeyPair()
}

// ExportSecretKey returns the current secret key
func (k *Kyber768) ExportSecretKey() []byte {
	if k.kem == nil {
		return nil
	}
	return k.kem.ExportSecretKey()
}

// Encapsulate generates a shared secret and ciphertext using recipient's public key
// Returns (ciphertext, sharedSecret)
func (k *Kyber768) Encapsulate(publicKey []byte) ([]byte, []byte, error) {
	if k.kem == nil {
		return nil, nil, ErrNotInitialized
	}
	ciphertext, sharedSecret, err := k.kem.EncapSecret(publicKey)
	if err != nil {
		return nil, nil, ErrEncapsulationFailed
	}
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using the secret key
func (k *Kyber768) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k.kem == nil {
		return nil, ErrNotInitialized
	}
	sharedSecret, err := k.kem.DecapSecret(ciphertext)
	if err != nil {
		return nil, ErrDecapsulationFailed
	}
	return sharedSecret, nil
}

// Details returns the algorithm details
func (k *Kyber768) Details() oqs.KeyEncapsulationDetails {
	if k.kem == nil {
		return oqs.KeyEncapsulationDetails{}
	}
	return k.kem.Details()
}

// PublicKeyLength returns the public key size in bytes
func (k *Kyber768) PublicKeyLength() int {
	return k.Details().LengthPublicKey
}

// SecretKeyLength returns the secret key size in bytes
func (k *Kyber768) SecretKeyLength() int {
	return k.Details().LengthSecretKey
}

// CiphertextLength returns the ciphertext size in bytes
func (k *Kyber768) CiphertextLength() int {
	return k.Details().LengthCiphertext
}

// SharedSecretLength returns the shared secret size in bytes
func (k *Kyber768) SharedSecretLength() int {
	return k.Details().LengthSharedSecret
}
