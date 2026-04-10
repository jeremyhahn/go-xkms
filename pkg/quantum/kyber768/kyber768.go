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

// Package kyber768 provides ML-KEM-768 quantum-safe key encapsulation mechanism (KEM)
// using the Go standard library crypto/mlkem package. ML-KEM-768 is the NIST FIPS 203
// standard (formerly known as Kyber768).
package kyber768

import (
	"crypto/mlkem"
	"errors"
)

const (
	// AlgorithmName is the NIST FIPS 203 standard name for Kyber768
	AlgorithmName = "ML-KEM-768"

	// SeedSize is the size of the decapsulation key seed in bytes
	SeedSize = mlkem.SeedSize

	// PublicKeySize is the size of an ML-KEM-768 encapsulation key in bytes
	PublicKeySize = mlkem.EncapsulationKeySize768

	// CiphertextSize is the size of an ML-KEM-768 ciphertext in bytes
	CiphertextSize = mlkem.CiphertextSize768

	// SharedSecretSize is the size of a shared secret in bytes
	SharedSecretSize = mlkem.SharedKeySize
)

var (
	// ErrNotInitialized indicates the KEM has not been initialized
	ErrNotInitialized = errors.New("kyber768: KEM not initialized")
	// ErrInvalidSeed indicates an invalid seed was provided
	ErrInvalidSeed = errors.New("kyber768: invalid seed")
	// ErrInvalidPublicKey indicates an invalid public key was provided
	ErrInvalidPublicKey = errors.New("kyber768: invalid public key")
	// ErrEncapsulationFailed indicates encapsulation operation failed
	ErrEncapsulationFailed = errors.New("kyber768: encapsulation failed")
	// ErrDecapsulationFailed indicates decapsulation operation failed
	ErrDecapsulationFailed = errors.New("kyber768: decapsulation failed")

	// ErrInvalidSecretKey is an alias for ErrInvalidSeed for backward compatibility
	ErrInvalidSecretKey = ErrInvalidSeed
)

// KEMDetails contains the algorithm parameters for the KEM
type KEMDetails struct {
	Name               string
	LengthPublicKey    int
	LengthSecretKey    int
	LengthCiphertext   int
	LengthSharedSecret int
}

// Kyber768 wraps the Go standard library ML-KEM-768 key encapsulation mechanism
type Kyber768 struct {
	dk   *mlkem.DecapsulationKey768
	seed []byte // 64 bytes
}

// New creates a new uninitialized Kyber768 instance with a freshly generated key
func New() (*Kyber768, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	seed := dk.Bytes()
	ownedSeed := make([]byte, len(seed))
	copy(ownedSeed, seed)
	return &Kyber768{
		dk:   dk,
		seed: ownedSeed,
	}, nil
}

// Create initializes Kyber768 with an existing 64-byte seed
func Create(seed []byte) (*Kyber768, error) {
	if len(seed) != SeedSize {
		return nil, ErrInvalidSeed
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, ErrInvalidSeed
	}
	ownedSeed := make([]byte, SeedSize)
	copy(ownedSeed, seed)
	return &Kyber768{
		dk:   dk,
		seed: ownedSeed,
	}, nil
}

// Clean zeroes internal seed bytes and releases resources
// This should always be called when done using the instance
func (k *Kyber768) Clean() {
	if k.seed != nil {
		for i := range k.seed {
			k.seed[i] = 0
		}
		k.seed = nil
	}
	k.dk = nil
}

// GenerateKeyPair generates a new ML-KEM-768 key pair
// Returns the public key (1184 bytes); the seed is stored internally
func (k *Kyber768) GenerateKeyPair() ([]byte, error) {
	if k.dk == nil {
		return nil, ErrNotInitialized
	}
	ek := k.dk.EncapsulationKey()
	pubKeyBytes := ek.Bytes()
	result := make([]byte, len(pubKeyBytes))
	copy(result, pubKeyBytes)
	return result, nil
}

// ExportSecretKey returns the 64-byte seed for the decapsulation key.
// The caller receives a copy of the seed.
func (k *Kyber768) ExportSecretKey() []byte {
	if k.dk == nil || k.seed == nil {
		return nil
	}
	result := make([]byte, len(k.seed))
	copy(result, k.seed)
	return result
}

// Encapsulate generates a shared secret and ciphertext using the recipient's public key.
// Returns (ciphertext, sharedSecret, error).
func (k *Kyber768) Encapsulate(publicKey []byte) ([]byte, []byte, error) {
	if k.dk == nil {
		return nil, nil, ErrNotInitialized
	}
	ek, err := mlkem.NewEncapsulationKey768(publicKey)
	if err != nil {
		return nil, nil, ErrInvalidPublicKey
	}
	sharedSecret, ciphertext := ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using the internal decapsulation key
func (k *Kyber768) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k.dk == nil {
		return nil, ErrNotInitialized
	}
	sharedSecret, err := k.dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, ErrDecapsulationFailed
	}
	return sharedSecret, nil
}

// Details returns the algorithm parameter details
func (k *Kyber768) Details() KEMDetails {
	return KEMDetails{
		Name:               AlgorithmName,
		LengthPublicKey:    PublicKeySize,
		LengthSecretKey:    SeedSize,
		LengthCiphertext:   CiphertextSize,
		LengthSharedSecret: SharedSecretSize,
	}
}

// PublicKeyLength returns the public key size in bytes
func (k *Kyber768) PublicKeyLength() int {
	return PublicKeySize
}

// SecretKeyLength returns the seed size in bytes
func (k *Kyber768) SecretKeyLength() int {
	return SeedSize
}

// CiphertextLength returns the ciphertext size in bytes
func (k *Kyber768) CiphertextLength() int {
	return CiphertextSize
}

// SharedSecretLength returns the shared secret size in bytes
func (k *Kyber768) SharedSecretLength() int {
	return SharedSecretSize
}
