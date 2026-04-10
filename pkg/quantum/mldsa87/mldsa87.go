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
// the cloudflare/circl library. ML-DSA-87 is the NIST FIPS 204 standard for
// post-quantum digital signatures at security level 5.
package mldsa87

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

const (
	// AlgorithmName is the NIST FIPS 204 standard algorithm identifier
	AlgorithmName = "ML-DSA-87"
)

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

// MLDSA87 wraps the circl ML-DSA-87 signature scheme.
// The 32-byte seed is stored internally for deterministic key reconstruction
// and export. The expanded private key and public key are derived from the
// seed and held in memory for signing and verification operations.
type MLDSA87 struct {
	privateKey *mldsa87.PrivateKey
	publicKey  *mldsa87.PublicKey
	seed       [mldsa87.SeedSize]byte
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
	if len(seed) != mldsa87.SeedSize {
		return nil, ErrInvalidSecretKey
	}

	var seedArr [mldsa87.SeedSize]byte
	copy(seedArr[:], seed)

	pub, priv := mldsa87.NewKeyFromSeed(&seedArr)

	return &MLDSA87{
		privateKey: priv,
		publicKey:  pub,
		seed:       seedArr,
		hasSeed:    true,
	}, nil
}

// Clean zeroes the internal seed bytes and releases key references.
// This should always be called when done using the instance.
func (m *MLDSA87) Clean() {
	if m.hasSeed {
		for i := range m.seed {
			m.seed[i] = 0
		}
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
	var seed [mldsa87.SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, err
	}

	pub, priv := mldsa87.NewKeyFromSeed(&seed)

	m.privateKey = priv
	m.publicKey = pub
	m.seed = seed
	m.hasSeed = true

	return pub.Bytes(), nil
}

// ExportSecretKey returns a copy of the 32-byte seed.
// Returns nil if no key has been generated or loaded.
func (m *MLDSA87) ExportSecretKey() []byte {
	if !m.hasSeed {
		return nil
	}
	out := make([]byte, mldsa87.SeedSize)
	copy(out, m.seed[:])
	return out
}

// Sign creates an ML-DSA-87 signature for the given message.
// The private key must have been generated or loaded via Create before calling.
func (m *MLDSA87) Sign(message []byte) ([]byte, error) {
	if m.privateKey == nil {
		return nil, ErrNotInitialized
	}
	sig, err := m.privateKey.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		return nil, ErrSignatureFailed
	}
	return sig, nil
}

// Verify verifies an ML-DSA-87 signature against a message and public key.
// The publicKey parameter is the serialized public key (2592 bytes). If nil,
// the internally stored public key is used.
func (m *MLDSA87) Verify(message, signature, publicKey []byte) (bool, error) {
	var pk mldsa87.PublicKey

	if publicKey != nil {
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, ErrVerificationFailed
		}
	} else if m.publicKey != nil {
		pk = *m.publicKey
	} else {
		return false, ErrNotInitialized
	}

	return mldsa87.Verify(&pk, message, nil, signature), nil
}

// Details returns the algorithm parameters as constant values
func (m *MLDSA87) Details() SignatureDetails {
	return SignatureDetails{
		Name:               AlgorithmName,
		LengthPublicKey:    mldsa87.PublicKeySize,
		LengthSecretKey:    mldsa87.SeedSize,
		MaxLengthSignature: mldsa87.SignatureSize,
	}
}

// PublicKeyLength returns the public key size in bytes (2592)
func (m *MLDSA87) PublicKeyLength() int {
	return mldsa87.PublicKeySize
}

// SecretKeyLength returns the seed size in bytes (32)
func (m *MLDSA87) SecretKeyLength() int {
	return mldsa87.SeedSize
}

// SignatureLength returns the signature size in bytes (4627)
func (m *MLDSA87) SignatureLength() int {
	return mldsa87.SignatureSize
}
