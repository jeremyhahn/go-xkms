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

package quantum

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mldsa"
	"crypto/mlkem"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// MLDSAPublicKey represents a post-quantum ML-DSA public key.
type MLDSAPublicKey struct {
	Algorithm string
	Key       []byte
}

// MLDSAPrivateKey represents a post-quantum ML-DSA private key
// that implements crypto.Signer for compatibility with Go's crypto interfaces.
// The underlying key material is a crypto/mldsa private key reconstructed
// from a 32-byte deterministic seed.
type MLDSAPrivateKey struct {
	Algorithm string
	PublicKey *MLDSAPublicKey
	sk        any // *mldsa.PrivateKey
	pk        any // *mldsa.PublicKey
	// seed is the 32-byte deterministic seed, sealed in an enclave rather than
	// held as a plaintext []byte on the Go heap: it reconstructs the whole
	// private key. Open it only for the moment it is needed and destroy the
	// working Buffer after.
	seed *secure.Secret
}

// Public returns the public key corresponding to the private key.
func (k *MLDSAPrivateKey) Public() crypto.PublicKey {
	return k.PublicKey
}

// Sign signs digest with the private key.
// The signature algorithm is determined by the key's parameter set (ML-DSA-44,
// ML-DSA-65, ML-DSA-87), carried inside the crypto/mldsa private key itself.
// ML-DSA signs the full message (not a pre-hash), so the digest parameter is
// treated as the message. opts and rand are ignored: crypto/mldsa.Sign signs
// directly when opts is nil.
func (k *MLDSAPrivateKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.sk == nil {
		return nil, ErrNotInitialized
	}

	sk, ok := k.sk.(*mldsa.PrivateKey)
	if !ok {
		return nil, ErrSigningFailed
	}
	return sk.Sign(nil, digest, nil)
}

// Verify verifies a ML-DSA signature against the message using the public key.
// The parameter set (ML-DSA-44, ML-DSA-65, ML-DSA-87) is carried inside the
// crypto/mldsa public key itself, so one code path covers all three levels.
func (k *MLDSAPrivateKey) Verify(message, signature []byte) (bool, error) {
	if k.pk == nil {
		return false, ErrNotInitialized
	}

	pk, ok := k.pk.(*mldsa.PublicKey)
	if !ok {
		return false, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: k.Algorithm}
	}

	return mldsa.Verify(pk, message, signature, nil) == nil, nil
}

// Clean destroys the enclaved seed to remove key material from memory.
// It is safe to call more than once, on a zero value, and on a nil receiver, so
// deferred cleanup on an error path never has to test the key first.
func (k *MLDSAPrivateKey) Clean() {
	if k == nil {
		return
	}
	k.seed.Destroy()
	k.seed = nil
	k.sk = nil
	k.pk = nil
}

// ExportSecretKey returns a copy of the 32-byte seed used to derive the key pair.
// The caller receives a plaintext copy on the Go heap and owns wiping it; the
// enclaved original is untouched. Returns nil if the seed cannot be opened,
// which for a live key means Clean has already destroyed it.
func (k *MLDSAPrivateKey) ExportSecretKey() []byte {
	if k.seed == nil {
		return nil
	}
	buf, err := k.seed.Open()
	if err != nil {
		return nil
	}
	defer buf.Destroy()
	out := make([]byte, buf.Size())
	copy(out, buf.Bytes())
	return out
}

// MLKEMPublicKey represents a post-quantum ML-KEM public key (encapsulation key).
type MLKEMPublicKey struct {
	Algorithm string
	Key       []byte
}

// Bytes returns the raw public key bytes.
func (pk *MLKEMPublicKey) Bytes() []byte {
	return pk.Key
}

// MLKEMPrivateKey represents a post-quantum ML-KEM private key (decapsulation key).
// ML-KEM is a Key Encapsulation Mechanism, not a direct encryption scheme.
//
// AEAD Safety: When using Encrypt/Decrypt methods, this key uses AES-256-GCM
// internally and integrates with AEAD safety tracking to prevent nonce reuse
// and enforce byte limits per NIST SP 800-38D recommendations.
type MLKEMPrivateKey struct {
	Algorithm string
	PublicKey *MLKEMPublicKey
	dk        any // *mlkem.DecapsulationKey768 or *mlkem.DecapsulationKey1024
	// seed is the 64-byte reconstruction seed, sealed in an enclave rather than
	// held as a plaintext []byte on the Go heap: it reconstructs the whole
	// private key. Open it only for the moment it is needed and destroy the
	// working Buffer after.
	seed *secure.Secret

	// AEAD tracking (optional - if nil, tracking is disabled)
	tracker types.AEADSafetyTracker
	keyID   string
}

// Public returns the public key.
func (k *MLKEMPrivateKey) Public() crypto.PublicKey {
	return k.PublicKey
}

// encapsulateFunc maps algorithm names to encapsulation using a recipient public key.
type encapsulateFunc func(recipientPubKey []byte) (ciphertext, sharedSecret []byte, err error)

var encapsulateDispatch = map[string]encapsulateFunc{
	"ML-KEM-768": func(recipientPubKey []byte) ([]byte, []byte, error) {
		ek, err := mlkem.NewEncapsulationKey768(recipientPubKey)
		if err != nil {
			return nil, nil, err
		}
		sharedKey, ciphertext := ek.Encapsulate()
		return ciphertext, sharedKey, nil
	},
	"ML-KEM-1024": func(recipientPubKey []byte) ([]byte, []byte, error) {
		ek, err := mlkem.NewEncapsulationKey1024(recipientPubKey)
		if err != nil {
			return nil, nil, err
		}
		sharedKey, ciphertext := ek.Encapsulate()
		return ciphertext, sharedKey, nil
	},
}

// Encapsulate generates a shared secret and ciphertext using a recipient's public key.
func (k *MLKEMPrivateKey) Encapsulate(recipientPublicKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if k.dk == nil {
		return nil, nil, ErrNotInitialized
	}

	encap, ok := encapsulateDispatch[k.Algorithm]
	if !ok {
		return nil, nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: k.Algorithm}
	}

	ciphertext, sharedSecret, err = encap(recipientPublicKey)
	if err != nil {
		return nil, nil, ErrEncapsulationFailed
	}

	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext using the decapsulation key.
func (k *MLKEMPrivateKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if k.dk == nil {
		return nil, ErrNotInitialized
	}

	switch dk := k.dk.(type) {
	case *mlkem.DecapsulationKey768:
		sharedSecret, err = dk.Decapsulate(ciphertext)
	case *mlkem.DecapsulationKey1024:
		sharedSecret, err = dk.Decapsulate(ciphertext)
	default:
		return nil, &errs.Detail{Err: ErrUnsupportedAlgorithm, Detail: k.Algorithm}
	}

	if err != nil {
		return nil, ErrDecapsulationFailed
	}

	return sharedSecret, nil
}

// Clean destroys the enclaved seed to remove key material from memory.
// It is safe to call more than once, on a zero value, and on a nil receiver, so
// deferred cleanup on an error path never has to test the key first.
func (k *MLKEMPrivateKey) Clean() {
	if k == nil {
		return
	}
	k.seed.Destroy()
	k.seed = nil
	k.dk = nil
}

// ExportSecretKey returns a copy of the 64-byte seed used to derive the key pair.
// The caller receives a plaintext copy on the Go heap and owns wiping it; the
// enclaved original is untouched. Returns nil if the seed cannot be opened,
// which for a live key means Clean has already destroyed it.
func (k *MLKEMPrivateKey) ExportSecretKey() []byte {
	if k.seed == nil {
		return nil
	}
	buf, err := k.seed.Open()
	if err != nil {
		return nil
	}
	defer buf.Destroy()
	out := make([]byte, buf.Size())
	copy(out, buf.Bytes())
	return out
}

// Encrypt performs quantum-safe encryption using ML-KEM + AES-256-GCM.
// It encapsulates a shared secret to the recipient's public key, then uses
// that secret to encrypt the plaintext with AES-256-GCM.
//
// Returns:
//   - kemCiphertext: The encapsulated shared secret (send to recipient)
//   - encryptedData: The AES-GCM encrypted plaintext (send to recipient)
//   - error: Any error that occurred
//
// The recipient must receive both kemCiphertext and encryptedData to decrypt.
func (k *MLKEMPrivateKey) Encrypt(plaintext []byte, recipientPublicKey []byte) (kemCiphertext, encryptedData []byte, err error) {
	if k.dk == nil {
		return nil, nil, ErrNotInitialized
	}

	// Step 1: Encapsulate to establish shared secret
	kemCiphertext, sharedSecret, err := k.Encapsulate(recipientPublicKey)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "encapsulation failed", Err: err}
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Encrypt plaintext using shared secret as AES-256 key
	encryptedData, err = encryptWithAESGCM(plaintext, sharedSecret, nil, k.tracker, k.keyID)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "AES-GCM encryption failed", Err: err}
	}

	return kemCiphertext, encryptedData, nil
}

// Decrypt performs quantum-safe decryption using ML-KEM + AES-256-GCM.
// It decapsulates the shared secret from kemCiphertext, then uses that
// secret to decrypt the encryptedData with AES-256-GCM.
//
// Parameters:
//   - kemCiphertext: The encapsulated shared secret
//   - encryptedData: The AES-GCM encrypted plaintext
//
// Returns:
//   - plaintext: The decrypted data
//   - error: Any error that occurred
func (k *MLKEMPrivateKey) Decrypt(kemCiphertext, encryptedData []byte) (plaintext []byte, err error) {
	if k.dk == nil {
		return nil, ErrNotInitialized
	}

	// Step 1: Decapsulate to recover shared secret
	sharedSecret, err := k.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "decapsulation failed", Err: err}
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Decrypt using shared secret as AES-256 key
	plaintext, err = decryptWithAESGCM(encryptedData, sharedSecret, nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "AES-GCM decryption failed", Err: err}
	}

	return plaintext, nil
}

// EncryptWithAAD performs quantum-safe encryption with Additional Authenticated Data (AAD).
// Similar to Encrypt, but includes AAD in the authentication tag.
func (k *MLKEMPrivateKey) EncryptWithAAD(plaintext, aad []byte, recipientPublicKey []byte) (kemCiphertext, encryptedData []byte, err error) {
	if k.dk == nil {
		return nil, nil, ErrNotInitialized
	}

	// Step 1: Encapsulate to establish shared secret
	kemCiphertext, sharedSecret, err := k.Encapsulate(recipientPublicKey)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "encapsulation failed", Err: err}
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Encrypt with AAD
	encryptedData, err = encryptWithAESGCM(plaintext, sharedSecret, aad, k.tracker, k.keyID)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "AES-GCM encryption failed", Err: err}
	}

	return kemCiphertext, encryptedData, nil
}

// DecryptWithAAD performs quantum-safe decryption with Additional Authenticated Data (AAD).
// Similar to Decrypt, but validates AAD in the authentication tag.
func (k *MLKEMPrivateKey) DecryptWithAAD(kemCiphertext, encryptedData, aad []byte) (plaintext []byte, err error) {
	if k.dk == nil {
		return nil, ErrNotInitialized
	}

	// Step 1: Decapsulate to recover shared secret
	sharedSecret, err := k.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "decapsulation failed", Err: err}
	}
	defer func() {
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}
	}()

	// Step 2: Decrypt with AAD validation
	plaintext, err = decryptWithAESGCM(encryptedData, sharedSecret, aad)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "AES-GCM decryption failed", Err: err}
	}

	return plaintext, nil
}

// encryptWithAESGCM encrypts plaintext using AES-256-GCM with the provided key.
// The nonce is randomly generated and prepended to the ciphertext.
//
// If tracker and keyID are provided, performs AEAD safety checks:
//   - Checks that the nonce hasn't been used before (prevents catastrophic nonce reuse)
//   - Records the nonce after successful encryption
//   - Tracks bytes encrypted to enforce NIST SP 800-38D limits
//
// Format: [nonce (12 bytes)][ciphertext][auth tag (16 bytes)]
//
// gcmNonceSize names the 96-bit GCM nonce length. The random-nonce AEAD
// reports a NonceSize of zero because it manages the nonce itself, so the
// length has to be named here to slice the nonce back out for the tracker.
const gcmNonceSize = 12

func encryptWithAESGCM(plaintext, key, aad []byte, tracker types.AEADSafetyTracker, keyID string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create AES cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the same 96-bit nonce this code prepended by hand and Open strips it, so
	// the stored layout is byte-for-byte what it was.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// AEAD Safety: Check bytes limit (if tracker available)
	if tracker != nil && keyID != "" {
		if err := tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, &errs.Affix{Prefix: "bytes limit exceeded: ", Err: err, Suffix: " (key rotation required)"}
		}
	}

	// Encrypt and authenticate. Format is unchanged -- nonce || ciphertext+tag
	// -- but the nonce is now generated inside the module rather than here.
	ciphertext := gcm.Seal(nil, nil, plaintext, aad)

	// AEAD Safety: the nonce is only observable after Seal, so the collision
	// check moved from before encryption to after it. The tracker still sees
	// every nonce this key has used and still refuses a repeat; what changed is
	// that a repeat is detected on the ciphertext that caused it rather than
	// one call earlier. Returning an error here discards that ciphertext, so a
	// reused nonce is still never handed to a caller.
	if tracker != nil && keyID != "" {
		nonce := ciphertext[:gcmNonceSize]
		if err := tracker.CheckNonce(keyID, nonce); err != nil {
			return nil, &errs.Affix{Prefix: "nonce reuse detected: ", Err: err, Suffix: " (CRITICAL SECURITY VIOLATION)"}
		}
		if err := tracker.RecordNonce(keyID, nonce); err != nil {
			fmt.Printf("Warning: failed to record nonce for key %s: %v\n", keyID, err)
		}
	}

	return ciphertext, nil
}

// decryptWithAESGCM decrypts ciphertext using AES-256-GCM with the provided key.
// Expects the nonce to be prepended to the ciphertext (as created by encryptWithAESGCM).
func decryptWithAESGCM(ciphertext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create AES cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the same 96-bit nonce this code prepended by hand and Open strips it, so
	// the stored layout is byte-for-byte what it was.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Overhead covers the prepended nonce and the trailing tag; Open extracts
	// the nonce itself.
	if len(ciphertext) < gcm.Overhead() {
		return nil, &errs.Message{Msg: "ciphertext too short"}
	}

	plaintext, err := gcm.Open(nil, nil, ciphertext, aad)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "decryption failed", Err: err}
	}

	return plaintext, nil
}
