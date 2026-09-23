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

// Package mldsa87 provides ML-DSA-87 quantum-safe digital signatures using
// the Go standard library's crypto/mldsa package. ML-DSA-87 is the NIST
// FIPS 204 standard for post-quantum digital signatures at security level 5.
//
// crypto/mldsa is the Go Cryptographic Module's own implementation: under a
// FIPS-140 build whose selected module version does not yet certify ML-DSA,
// the stdlib functions this package calls refuse on their own, so no
// allowlist of approved algorithms needs to be kept here (go-xkms #21).
package mldsa87

import (
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"io"

	"github.com/jeremyhahn/go-enclave"
)

const (
	// AlgorithmName is the NIST FIPS 204 standard algorithm identifier
	AlgorithmName = "ML-DSA-87"

	// SeedSize is the size of the deterministic key-derivation seed, in bytes.
	SeedSize = mldsa.PrivateKeySize

	// PublicKeySize is the size of a serialized ML-DSA-87 public key, in bytes.
	PublicKeySize = mldsa.MLDSA87PublicKeySize

	// SignatureSize is the size of an ML-DSA-87 signature, in bytes.
	SignatureSize = mldsa.MLDSA87SignatureSize
)

// params is the FIPS 204 parameter set for ML-DSA-87.
var params = mldsa.MLDSA87()

var (
	// ErrNotInitialized indicates the signer has not been initialized
	ErrNotInitialized = errors.New("mldsa87: signer not initialized")
	// ErrInvalidSecretKey indicates an invalid secret key was provided
	ErrInvalidSecretKey = errors.New("mldsa87: invalid secret key")
	// ErrSignatureFailed indicates signing operation failed
	ErrSignatureFailed = errors.New("mldsa87: signature operation failed")
	// ErrVerificationFailed indicates signature verification failed
	ErrVerificationFailed = errors.New("mldsa87: verification failed")
)

// SignatureDetails holds the constant parameters for the ML-DSA-87 scheme
type SignatureDetails struct {
	Name               string
	LengthPublicKey    int
	LengthSecretKey    int // Seed size (32 bytes), not the expanded private key
	MaxLengthSignature int
}

// MLDSA87 wraps the stdlib ML-DSA-87 signature scheme.
// The 32-byte seed is stored internally for deterministic key reconstruction
// and export. The expanded private key and public key are derived from the
// seed and held in memory for signing and verification operations.
type MLDSA87 struct {
	privateKey *mldsa.PrivateKey
	publicKey  *mldsa.PublicKey
	seed       [SeedSize]byte
	hasSeed    bool
}

// New creates a new uninitialized MLDSA87 instance.
// Call GenerateKeyPair to generate keys before signing.
func New() (*MLDSA87, error) {
	return &MLDSA87{}, nil
}

// Create initializes MLDSA87 from an existing 32-byte seed.
// The seed is used to deterministically reconstruct the key pair.
func Create(seed []byte) (*MLDSA87, error) {
	if len(seed) != SeedSize {
		return nil, ErrInvalidSecretKey
	}

	priv, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		return nil, ErrInvalidSecretKey
	}

	var seedArr [SeedSize]byte
	copy(seedArr[:], seed)

	return &MLDSA87{
		privateKey: priv,
		publicKey:  priv.PublicKey(),
		seed:       seedArr,
		hasSeed:    true,
	}, nil
}

// Clean zeroes the internal seed bytes and releases key references.
// This should always be called when done using the instance.
func (m *MLDSA87) Clean() {
	if m.hasSeed {
		enclave.Wipe(m.seed[:])
		m.hasSeed = false
	}
	m.privateKey = nil
	m.publicKey = nil
}

// GenerateKeyPair generates a new ML-DSA-87 key pair.
// Returns the serialized public key (2592 bytes). The seed and expanded
// private key are stored internally.
func (m *MLDSA87) GenerateKeyPair() ([]byte, error) {
	// Generate a random seed and derive the key pair from it so
	// that we retain the seed for deterministic reconstruction.
	var seed [SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, err
	}

	priv, err := mldsa.NewPrivateKey(params, seed[:])
	if err != nil {
		return nil, err
	}

	m.privateKey = priv
	m.publicKey = priv.PublicKey()
	m.seed = seed
	m.hasSeed = true

	return m.publicKey.Bytes(), nil
}

// ExportSecretKey returns a copy of the 32-byte seed.
// Returns nil if no key has been generated or loaded.
func (m *MLDSA87) ExportSecretKey() []byte {
	if !m.hasSeed {
		return nil
	}
	out := make([]byte, SeedSize)
	copy(out, m.seed[:])
	return out
}

// Sign creates an ML-DSA-87 signature for the given message.
// The private key must have been generated or loaded via Create before calling.
func (m *MLDSA87) Sign(message []byte) ([]byte, error) {
	if m.privateKey == nil {
		return nil, ErrNotInitialized
	}
	sig, err := m.privateKey.Sign(nil, message, nil)
	if err != nil {
		return nil, ErrSignatureFailed
	}
	return sig, nil
}

// Verify verifies an ML-DSA-87 signature against a message and public key.
// The publicKey parameter is the serialized public key (2592 bytes). If nil,
// the internally stored public key is used.
func (m *MLDSA87) Verify(message, signature, publicKey []byte) (bool, error) {
	var pk *mldsa.PublicKey

	switch {
	case publicKey != nil:
		decoded, err := mldsa.NewPublicKey(params, publicKey)
		if err != nil {
			return false, ErrVerificationFailed
		}
		pk = decoded
	case m.publicKey != nil:
		pk = m.publicKey
	default:
		return false, ErrNotInitialized
	}

	return mldsa.Verify(pk, message, signature, nil) == nil, nil
}

// Details returns the algorithm parameters as constant values
func (m *MLDSA87) Details() SignatureDetails {
	return SignatureDetails{
		Name:               AlgorithmName,
		LengthPublicKey:    PublicKeySize,
		LengthSecretKey:    SeedSize,
		MaxLengthSignature: SignatureSize,
	}
}

// PublicKeyLength returns the public key size in bytes (2592)
func (m *MLDSA87) PublicKeyLength() int {
	return PublicKeySize
}

// SecretKeyLength returns the seed size in bytes (32)
func (m *MLDSA87) SecretKeyLength() int {
	return SeedSize
}

// SignatureLength returns the signature size in bytes (4627)
func (m *MLDSA87) SignatureLength() int {
	return SignatureSize
}
