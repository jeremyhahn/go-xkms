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

// Package dilithium2 provides ML-DSA-44 quantum-safe digital signatures using
// the Go standard library's crypto/mldsa package. ML-DSA-44 is the NIST
// FIPS 204 standard for post-quantum digital signatures at security level 2.
//
// crypto/mldsa is the Go Cryptographic Module's own implementation: under a
// FIPS-140 build whose selected module version does not yet certify ML-DSA,
// the stdlib functions this package calls refuse on their own, so no
// allowlist of approved algorithms needs to be kept here (go-xkms #21).
package dilithium2

import (
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// AlgorithmName is the NIST FIPS 204 standard algorithm identifier
	AlgorithmName = "ML-DSA-44"

	// SeedSize is the size of the deterministic key-derivation seed, in bytes.
	SeedSize = mldsa.PrivateKeySize

	// PublicKeySize is the size of a serialized ML-DSA-44 public key, in bytes.
	PublicKeySize = mldsa.MLDSA44PublicKeySize

	// SignatureSize is the size of an ML-DSA-44 signature, in bytes.
	SignatureSize = mldsa.MLDSA44SignatureSize
)

// params is the FIPS 204 parameter set for ML-DSA-44.
var params = mldsa.MLDSA44()

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

// SignatureDetails holds the constant parameters for the ML-DSA-44 scheme
type SignatureDetails struct {
	Name               string
	LengthPublicKey    int
	LengthSecretKey    int // Seed size (32 bytes), not the expanded private key
	MaxLengthSignature int
}

// Dilithium2 wraps the stdlib ML-DSA-44 signature scheme.
// The 32-byte seed is stored internally for deterministic key reconstruction
// and export. The expanded private key and public key are derived from the
// seed and held in memory for signing and verification operations.
type Dilithium2 struct {
	privateKey *mldsa.PrivateKey
	publicKey  *mldsa.PublicKey
	seed       [SeedSize]byte
	hasSeed    bool
}

// New creates a new uninitialized Dilithium2 instance.
// Call GenerateKeyPair to generate keys before signing.
func New() (*Dilithium2, error) {
	return &Dilithium2{}, nil
}

// Create initializes Dilithium2 from an existing 32-byte seed.
// The seed is used to deterministically reconstruct the key pair.
func Create(seed []byte) (*Dilithium2, error) {
	if len(seed) != SeedSize {
		return nil, ErrInvalidSecretKey
	}

	priv, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		return nil, ErrInvalidSecretKey
	}

	var seedArr [SeedSize]byte
	copy(seedArr[:], seed)

	return &Dilithium2{
		privateKey: priv,
		publicKey:  priv.PublicKey(),
		seed:       seedArr,
		hasSeed:    true,
	}, nil
}

// Clean zeroes the internal seed bytes and releases key references.
// This should always be called when done using the instance.
func (d *Dilithium2) Clean() {
	if d.hasSeed {
		for i := range d.seed {
			d.seed[i] = 0
		}
		d.hasSeed = false
	}
	d.privateKey = nil
	d.publicKey = nil
}

// GenerateKeyPair generates a new ML-DSA-44 key pair.
// Returns the serialized public key (1312 bytes). The seed and expanded
// private key are stored internally.
func (d *Dilithium2) GenerateKeyPair() ([]byte, error) {
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

	d.privateKey = priv
	d.publicKey = priv.PublicKey()
	d.seed = seed
	d.hasSeed = true

	return d.publicKey.Bytes(), nil
}

// ExportSecretKey returns a copy of the 32-byte seed.
// Returns nil if no key has been generated or loaded.
func (d *Dilithium2) ExportSecretKey() []byte {
	if !d.hasSeed {
		return nil
	}
	out := make([]byte, SeedSize)
	copy(out, d.seed[:])
	return out
}

// Sign creates an ML-DSA-44 signature for the given message.
// The private key must have been generated or loaded via Create before calling.
func (d *Dilithium2) Sign(message []byte) ([]byte, error) {
	if d.privateKey == nil {
		return nil, ErrNotInitialized
	}
	sig, err := d.privateKey.Sign(nil, message, nil)
	if err != nil {
		return nil, ErrSignatureFailed
	}
	return sig, nil
}

// Verify verifies an ML-DSA-44 signature against a message and public key.
// The publicKey parameter is the serialized public key (1312 bytes). If nil,
// the internally stored public key is used.
func (d *Dilithium2) Verify(message, signature, publicKey []byte) (bool, error) {
	var pk *mldsa.PublicKey

	switch {
	case publicKey != nil:
		decoded, err := mldsa.NewPublicKey(params, publicKey)
		if err != nil {
			return false, ErrVerificationFailed
		}
		pk = decoded
	case d.publicKey != nil:
		pk = d.publicKey
	default:
		return false, ErrNotInitialized
	}

	return mldsa.Verify(pk, message, signature, nil) == nil, nil
}

// Details returns the algorithm parameters as constant values
func (d *Dilithium2) Details() SignatureDetails {
	return SignatureDetails{
		Name:               AlgorithmName,
		LengthPublicKey:    PublicKeySize,
		LengthSecretKey:    SeedSize,
		MaxLengthSignature: SignatureSize,
	}
}

// PublicKeyLength returns the public key size in bytes (1312)
func (d *Dilithium2) PublicKeyLength() int {
	return PublicKeySize
}

// SecretKeyLength returns the seed size in bytes (32)
func (d *Dilithium2) SecretKeyLength() int {
	return SeedSize
}

// SignatureLength returns the signature size in bytes (2420)
func (d *Dilithium2) SignatureLength() int {
	return SignatureSize
}
