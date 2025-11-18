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

// Package dilithium2 provides Dilithium2 quantum-safe digital signatures
// using the liboqs library. Dilithium is a NIST PQC standard finalist for
// digital signatures.
package dilithium2

import (
	"errors"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
	// AlgorithmName is the OQS algorithm identifier
	// Using ML-DSA-44 which is the NIST FIPS 204 standard name for Dilithium2
	AlgorithmName = "ML-DSA-44"
)

var (
	// ErrNotInitialized indicates the signer has not been initialized
	ErrNotInitialized = errors.New("dilithium2: signer not initialized")
	// ErrInvalidSecretKey indicates an invalid secret key was provided
	ErrInvalidSecretKey = errors.New("dilithium2: invalid secret key")
	// ErrSignatureFailed indicates signing operation failed
	ErrSignatureFailed = errors.New("dilithium2: signature operation failed")
	// ErrVerificationFailed indicates signature verification failed
	ErrVerificationFailed = errors.New("dilithium2: verification failed")
)

// Dilithium2 wraps the liboqs Dilithium2 signature scheme
type Dilithium2 struct {
	signer *oqs.Signature
}

// New creates a new uninitialized Dilithium2 instance
func New() (*Dilithium2, error) {
	signer := oqs.Signature{}
	if err := signer.Init(AlgorithmName, nil); err != nil {
		return nil, err
	}
	return &Dilithium2{signer: &signer}, nil
}

// Create initializes Dilithium2 with an existing secret key
func Create(secretKey []byte) (*Dilithium2, error) {
	signer := oqs.Signature{}
	if err := signer.Init(AlgorithmName, secretKey); err != nil {
		return nil, ErrInvalidSecretKey
	}
	return &Dilithium2{signer: &signer}, nil
}

// Clean releases resources held by the signer
// This should always be called when done using the instance
func (d *Dilithium2) Clean() {
	if d.signer != nil {
		d.signer.Clean()
	}
}

// GenerateKeyPair generates a new Dilithium2 key pair
// Returns the public key; the secret key is stored internally
func (d *Dilithium2) GenerateKeyPair() ([]byte, error) {
	if d.signer == nil {
		return nil, ErrNotInitialized
	}
	return d.signer.GenerateKeyPair()
}

// ExportSecretKey returns the current secret key
func (d *Dilithium2) ExportSecretKey() []byte {
	if d.signer == nil {
		return nil
	}
	return d.signer.ExportSecretKey()
}

// Sign creates a Dilithium2 signature for the given message
func (d *Dilithium2) Sign(message []byte) ([]byte, error) {
	if d.signer == nil {
		return nil, ErrNotInitialized
	}
	signature, err := d.signer.Sign(message)
	if err != nil {
		return nil, ErrSignatureFailed
	}
	return signature, nil
}

// Verify verifies a Dilithium2 signature against a message and public key
func (d *Dilithium2) Verify(message, signature, publicKey []byte) (bool, error) {
	if d.signer == nil {
		return false, ErrNotInitialized
	}
	valid, err := d.signer.Verify(message, signature, publicKey)
	if err != nil {
		return false, err
	}
	return valid, nil
}

// Details returns the algorithm details
func (d *Dilithium2) Details() oqs.SignatureDetails {
	if d.signer == nil {
		return oqs.SignatureDetails{}
	}
	return d.signer.Details()
}

// PublicKeyLength returns the public key size in bytes
func (d *Dilithium2) PublicKeyLength() int {
	return d.Details().LengthPublicKey
}

// SecretKeyLength returns the secret key size in bytes
func (d *Dilithium2) SecretKeyLength() int {
	return d.Details().LengthSecretKey
}

// SignatureLength returns the maximum signature size in bytes
func (d *Dilithium2) SignatureLength() int {
	return d.Details().MaxLengthSignature
}
