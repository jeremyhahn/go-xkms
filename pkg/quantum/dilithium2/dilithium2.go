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

// Package dilithium2 provides ML-DSA-44 (Dilithium2) quantum-safe digital
// signatures using the cloudflare/circl library. ML-DSA-44 is the NIST
// FIPS 204 standard for post-quantum digital signatures at security level 2.
package dilithium2

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const (
	// AlgorithmName is the NIST FIPS 204 standard algorithm identifier
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

// SignatureDetails holds the constant parameters for the ML-DSA-44 scheme
type SignatureDetails struct {
	Name               string
	LengthPublicKey    int
	LengthSecretKey    int // Seed size (32 bytes), not the expanded private key
	MaxLengthSignature int
}

// Dilithium2 wraps the circl ML-DSA-44 signature scheme.
// The 32-byte seed is stored internally for deterministic key reconstruction
// and export. The expanded private key and public key are derived from the
// seed and held in memory for signing and verification operations.
type Dilithium2 struct {
	privateKey *mldsa44.PrivateKey
	publicKey  *mldsa44.PublicKey
	seed       [mldsa44.SeedSize]byte
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
	if len(seed) != mldsa44.SeedSize {
		return nil, ErrInvalidSecretKey
	}

	var seedArr [mldsa44.SeedSize]byte
	copy(seedArr[:], seed)

	pub, priv := mldsa44.NewKeyFromSeed(&seedArr)

	return &Dilithium2{
		privateKey: priv,
		publicKey:  pub,
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
	var seed [mldsa44.SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, err
	}

	pub, priv := mldsa44.NewKeyFromSeed(&seed)

	d.privateKey = priv
	d.publicKey = pub
	d.seed = seed
	d.hasSeed = true

	return pub.Bytes(), nil
}

// ExportSecretKey returns a copy of the 32-byte seed.
// Returns nil if no key has been generated or loaded.
func (d *Dilithium2) ExportSecretKey() []byte {
	if !d.hasSeed {
		return nil
	}
	out := make([]byte, mldsa44.SeedSize)
	copy(out, d.seed[:])
	return out
}

// Sign creates an ML-DSA-44 signature for the given message.
// The private key must have been generated or loaded via Create before calling.
func (d *Dilithium2) Sign(message []byte) ([]byte, error) {
	if d.privateKey == nil {
		return nil, ErrNotInitialized
	}
	sig, err := d.privateKey.Sign(nil, message, crypto.Hash(0))
	if err != nil {
		return nil, ErrSignatureFailed
	}
	return sig, nil
}

// Verify verifies an ML-DSA-44 signature against a message and public key.
// The publicKey parameter is the serialized public key (1312 bytes). If nil,
// the internally stored public key is used.
func (d *Dilithium2) Verify(message, signature, publicKey []byte) (bool, error) {
	var pk mldsa44.PublicKey

	if publicKey != nil {
		if err := pk.UnmarshalBinary(publicKey); err != nil {
			return false, ErrVerificationFailed
		}
	} else if d.publicKey != nil {
		pk = *d.publicKey
	} else {
		return false, ErrNotInitialized
	}

	return mldsa44.Verify(&pk, message, nil, signature), nil
}

// Details returns the algorithm parameters as constant values
func (d *Dilithium2) Details() SignatureDetails {
	return SignatureDetails{
		Name:               AlgorithmName,
		LengthPublicKey:    mldsa44.PublicKeySize,
		LengthSecretKey:    mldsa44.SeedSize,
		MaxLengthSignature: mldsa44.SignatureSize,
	}
}

// PublicKeyLength returns the public key size in bytes (1312)
func (d *Dilithium2) PublicKeyLength() int {
	return mldsa44.PublicKeySize
}

// SecretKeyLength returns the seed size in bytes (32)
func (d *Dilithium2) SecretKeyLength() int {
	return mldsa44.SeedSize
}

// SignatureLength returns the signature size in bytes (2420)
func (d *Dilithium2) SignatureLength() int {
	return mldsa44.SignatureSize
}
