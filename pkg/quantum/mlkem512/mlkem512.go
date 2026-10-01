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

// Package mlkem512 provides the ML-KEM-512 key encapsulation mechanism defined
// by NIST FIPS 203.
//
// The sibling packages for the other two parameter sets wrap the Go standard
// library, but crypto/mlkem implements only ML-KEM-768 and ML-KEM-1024, so this
// one wraps CIRCL's github.com/cloudflare/circl/kem/mlkem/mlkem512 instead.
//
// The distinction that matters when reading that dependency: CIRCL ships both
// kem/kyber/kyber512 and kem/mlkem/mlkem512, and they are different algorithms.
// Kyber512 is the NIST round-3 submission; ML-KEM-512 is the standardised
// version, which changed the key-derivation step and the encoding. Only the
// latter is FIPS 203, and only the latter is used here -- a key produced by one
// cannot be decapsulated by the other.
//
// The API mirrors kyber768 and mlkem1024 deliberately, including the 64-byte
// seed as the private-key representation, because the PKCS#11 module stores that
// seed in a private key object's CKA_VALUE and reconstructs the key through
// Create on every later use.
//
// CIRCL is not part of the Go Cryptographic Module, so crypto/fips140.Enabled
// cannot see it and cannot refuse it on its own the way it refuses a
// non-approved stdlib algorithm under GODEBUG=fips140=only (go-xkms #21).
// New and Create are this package's one shared seam for that refusal: every
// other exported method operates on an already-constructed *MLKEM512, so
// gating construction is sufficient and avoids repeating the check per
// operation.
package mlkem512

import (
	"crypto/fips140"
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem512"

	qrdbsecure "github.com/jeremyhahn/go-qrdb/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	// AlgorithmName is the NIST FIPS 203 name for this parameter set.
	AlgorithmName = "ML-KEM-512"

	// SeedSize is the size of the decapsulation key seed in bytes. FIPS 203
	// generates a key from d || z, 32 bytes each, which is the same
	// representation the 768 and 1024 packages use.
	SeedSize = mlkem512.KeySeedSize

	// PublicKeySize is the size of an ML-KEM-512 encapsulation key in bytes.
	PublicKeySize = 800

	// CiphertextSize is the size of an ML-KEM-512 ciphertext in bytes.
	CiphertextSize = 768

	// SharedSecretSize is the size of a shared secret in bytes.
	SharedSecretSize = 32

	// encapsulationSeedSize is the randomness ML-KEM encapsulation consumes.
	encapsulationSeedSize = 32
)

var (
	// ErrNotInitialized indicates the KEM has not been initialized.
	ErrNotInitialized = errors.New("mlkem512: KEM not initialized")
	// ErrInvalidSeed indicates an invalid seed was provided.
	ErrInvalidSeed = errors.New("mlkem512: invalid seed")
	// ErrInvalidPublicKey indicates an invalid public key was provided.
	ErrInvalidPublicKey = errors.New("mlkem512: invalid public key")
	// ErrInvalidCiphertext indicates a ciphertext of the wrong length.
	ErrInvalidCiphertext = errors.New("mlkem512: invalid ciphertext")
	// ErrEncapsulationFailed indicates the encapsulation operation failed.
	ErrEncapsulationFailed = errors.New("mlkem512: encapsulation failed")
	// ErrDecapsulationFailed indicates the decapsulation operation failed.
	ErrDecapsulationFailed = errors.New("mlkem512: decapsulation failed")

	// ErrInvalidSecretKey is an alias for ErrInvalidSeed, matching the naming
	// the sibling parameter-set packages expose.
	ErrInvalidSecretKey = ErrInvalidSeed

	// ErrFIPSMode indicates the process is running under FIPS 140 mode, in
	// which this package refuses to construct a key. ML-KEM-512 has no Go
	// Cryptographic Module implementation to defer to — crypto/mlkem covers
	// only the 768 and 1024 parameter sets — so refusing here is this
	// package's own responsibility rather than something the stdlib does for
	// it once fips140.Enabled reports the module active.
	ErrFIPSMode = errors.New("mlkem512: ML-KEM-512 uses cloudflare/circl, which is not part of the Go Cryptographic Module, and is refused under FIPS 140 mode")
)

// KEMDetails contains the algorithm parameters for the KEM.
type KEMDetails struct {
	Name               string
	LengthPublicKey    int
	LengthSecretKey    int
	LengthCiphertext   int
	LengthSharedSecret int
}

// MLKEM512 wraps the ML-KEM-512 key encapsulation mechanism.
type MLKEM512 struct {
	sk *mlkem512.PrivateKey
	pk *mlkem512.PublicKey
	// seed is the 64-byte d || z decapsulation-key seed, sealed in an enclave
	// rather than held as a plaintext []byte on the Go heap: it reconstructs
	// the whole private key, so it is the most sensitive value this type owns.
	// Open it only for the moment it is needed and destroy the working Buffer
	// after.
	seed *secure.Secret
}

// New creates an MLKEM512 instance holding a freshly generated key pair.
//
// The seed is drawn here and the key derived from it, rather than taken from
// mlkem512.GenerateKeyPair, because the seed is what ExportSecretKey returns and
// what Create reconstructs from; generating the key by any route that does not
// yield its seed would produce a key this package could not persist.
func New() (*MLKEM512, error) {
	if fips140.Enabled() {
		return nil, ErrFIPSMode
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}

	pk, sk := mlkem512.NewKeyFromSeed(seed)

	// NewSecret wipes seed, so the plaintext copy does not outlive this call.
	sealed, sealErr := secure.NewSecret(seed)
	if sealErr != nil {
		return nil, sealErr
	}
	return &MLKEM512{sk: sk, pk: pk, seed: sealed}, nil
}

// Create initializes MLKEM512 from an existing 64-byte seed.
func Create(seed []byte) (*MLKEM512, error) {
	if fips140.Enabled() {
		return nil, ErrFIPSMode
	}
	if len(seed) != SeedSize {
		return nil, ErrInvalidSeed
	}

	ownedSeed := make([]byte, SeedSize)
	copy(ownedSeed, seed)

	pk, sk := mlkem512.NewKeyFromSeed(ownedSeed)

	// NewSecret wipes ownedSeed; the caller's own slice is untouched.
	sealed, sealErr := secure.NewSecret(ownedSeed)
	if sealErr != nil {
		return nil, sealErr
	}
	return &MLKEM512{sk: sk, pk: pk, seed: sealed}, nil
}

// Clean destroys the enclaved seed and releases the key material. It should
// always be called when the instance is no longer needed. It is safe to call
// more than once, on a zero value, and on a nil receiver.
func (k *MLKEM512) Clean() {
	if k == nil {
		return
	}
	k.seed.Destroy()
	k.seed = nil
	k.sk = nil
	k.pk = nil
}

// GenerateKeyPair returns the encapsulation key of the pair this instance
// holds. The seed stays internal; ExportSecretKey returns it.
func (k *MLKEM512) GenerateKeyPair() ([]byte, error) {
	if k.pk == nil {
		return nil, ErrNotInitialized
	}

	publicKey := make([]byte, PublicKeySize)
	k.pk.Pack(publicKey)
	return publicKey, nil
}

// ExportSecretKey returns a copy of the 64-byte decapsulation key seed.
// The caller receives a plaintext copy on the Go heap and owns wiping it; the
// enclaved original is untouched. Returns nil if the seed cannot be opened,
// which for a live instance means it has already been destroyed.
func (k *MLKEM512) ExportSecretKey() []byte {
	if k.sk == nil || k.seed == nil {
		return nil
	}

	buf, err := k.seed.Open()
	if err != nil {
		return nil
	}
	defer buf.Destroy()

	result, err := qrdbsecure.CopyOut(buf)
	if err != nil {
		return nil
	}
	return result
}

// Encapsulate produces a shared secret and its ciphertext under the recipient's
// public key. It returns (ciphertext, sharedSecret, error).
//
// The recipient's key is the argument, so this does not read the instance's own
// key pair -- encapsulating to somebody else is the normal case. The instance
// must still be initialized, matching the sibling packages, so that a cleaned
// instance cannot be used by accident.
func (k *MLKEM512) Encapsulate(publicKey []byte) ([]byte, []byte, error) {
	if k.sk == nil {
		return nil, nil, ErrNotInitialized
	}
	if len(publicKey) != PublicKeySize {
		return nil, nil, ErrInvalidPublicKey
	}

	var recipient mlkem512.PublicKey
	if err := recipient.Unpack(publicKey); err != nil {
		return nil, nil, ErrInvalidPublicKey
	}

	encapsulationSeed := make([]byte, encapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, encapsulationSeed); err != nil {
		return nil, nil, ErrEncapsulationFailed
	}

	ciphertext := make([]byte, CiphertextSize)
	sharedSecret := make([]byte, SharedSecretSize)
	recipient.EncapsulateTo(ciphertext, sharedSecret, encapsulationSeed)

	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from a ciphertext using this
// instance's decapsulation key.
//
// A ciphertext of the wrong length is rejected before it reaches
// DecapsulateTo, which requires the exact size and would otherwise panic. A
// ciphertext of the right length that is simply wrong is not an error: FIPS 203
// specifies implicit rejection, so decapsulation returns a deterministic
// pseudo-random secret derived from the private key rather than reporting
// failure. That is the designed behaviour and callers must compare the secret
// they derive, not rely on an error here.
func (k *MLKEM512) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k.sk == nil {
		return nil, ErrNotInitialized
	}
	if len(ciphertext) != CiphertextSize {
		return nil, ErrInvalidCiphertext
	}

	sharedSecret := make([]byte, SharedSecretSize)
	k.sk.DecapsulateTo(sharedSecret, ciphertext)
	return sharedSecret, nil
}

// Details returns the algorithm parameter details.
func (k *MLKEM512) Details() KEMDetails {
	return KEMDetails{
		Name:               AlgorithmName,
		LengthPublicKey:    PublicKeySize,
		LengthSecretKey:    SeedSize,
		LengthCiphertext:   CiphertextSize,
		LengthSharedSecret: SharedSecretSize,
	}
}

// PublicKeyLength returns the public key size in bytes.
func (k *MLKEM512) PublicKeyLength() int { return PublicKeySize }

// SecretKeyLength returns the seed size in bytes.
func (k *MLKEM512) SecretKeyLength() int { return SeedSize }

// CiphertextLength returns the ciphertext size in bytes.
func (k *MLKEM512) CiphertextLength() int { return CiphertextSize }

// SharedSecretLength returns the shared secret size in bytes.
func (k *MLKEM512) SharedSecretLength() int { return SharedSecretSize }
