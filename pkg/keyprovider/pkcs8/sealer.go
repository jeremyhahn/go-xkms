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

package pkcs8

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// gcmNonceSize and gcmTagSize name the 96-bit GCM nonce and 128-bit
// authentication tag lengths. cipher.NewGCMWithRandomNonce reports a NonceSize
// of zero and folds both into Overhead because it manages the nonce itself, so
// the lengths have to be named here to split a sealed blob back into the
// SealedData Nonce/Ciphertext/Tag fields.
const (
	gcmNonceSize = 12
	gcmTagSize   = 16
)

// Ensure PKCS8Backend implements types.Sealer interface
var _ types.Sealer = (*PKCS8Backend)(nil)

// sealingKeyInfo is the HKDF info string for deriving sealing keys
const sealingKeyInfo = "pkcs8-sealing-key-v1"

// CanSeal returns true if this backend supports sealing operations and is open.
// PKCS#8 supports software-based sealing when the backend is active.
func (b *PKCS8Backend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return !b.closed
}

// Seal encrypts/protects data using HKDF-derived key and AES-GCM.
//
// The sealing process:
//  1. Load the private key specified in opts.KeyAttributes
//  2. Derive a sealing key using HKDF from the private key material
//  3. Encrypt the data using AES-256-GCM with a random nonce
//
// Security Note: This is a software-only sealing mechanism. The private key
// is loaded into memory during the sealing process. For secrets that should
// never touch system memory, use hardware-backed backends (TPM, HSM).
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - data: The plaintext data to seal
//   - opts: Sealing options (KeyAttributes required to identify the sealing key)
//
// Returns SealedData containing the encrypted payload, or error.
func (b *PKCS8Backend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if opts == nil || opts.KeyAttributes == nil {
		return nil, &errs.Message{Msg: "seal options with KeyAttributes required"}
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyAttrs := opts.KeyAttributes

	// Load the private key
	privateKey, err := b.GetKey(ctx, keyAttrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to load sealing key", Err: err}
	}

	// Derive the sealing key from the private key material
	sealingKey, err := deriveSealingKey(privateKey, keyAttrs.ID())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to derive sealing key", Err: err}
	}
	defer enclave.Wipe(sealingKey)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sealingKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create AES cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the same 96-bit nonce and Open strips it, so once the sealed blob is
	// split back into the Nonce/Ciphertext/Tag fields below the stored shape is
	// unchanged and data sealed by earlier builds still unseals.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Encrypt with AAD if provided
	var aad []byte
	if opts.AAD != nil {
		aad = opts.AAD
	}

	// Seal emits nonce || ciphertext || tag. Split all three apart for the
	// SealedData fields the API has always returned.
	sealed := gcm.Seal(nil, nil, data, aad)
	nonce := sealed[:gcmNonceSize]
	body := sealed[gcmNonceSize:]
	ciphertext := body[:len(body)-gcmTagSize]
	tag := body[len(body)-gcmTagSize:]

	// Build the sealed data result
	result := &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
		KeyID:      keyAttrs.KeyID(),
		Metadata:   make(map[string][]byte),
	}

	// Store AAD in metadata if provided
	if aad != nil {
		result.Metadata["pkcs8:aad_hash"] = hashBytes(aad)
	}

	return result, nil
}

// Unseal decrypts/recovers data using HKDF-derived key and AES-GCM.
//
// The unsealing process:
//  1. Load the private key specified in opts.KeyAttributes
//  2. Derive the same sealing key using HKDF
//  3. Decrypt the data using AES-256-GCM
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sealed: The sealed data from a previous Seal operation
//   - opts: Unsealing options (KeyAttributes required, AAD must match if used during sealing)
//
// Returns the original plaintext data, or error if unsealing fails.
func (b *PKCS8Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, &errs.Message{Msg: "sealed data is required"}
	}

	// Verify this is a software backend sealed data
	if sealed.Backend != types.BackendTypeSoftware {
		return nil, &errs.Message{Msg: fmt.Sprintf("sealed data was not created by software backend (got %s)", sealed.Backend)}
	}

	if opts == nil || opts.KeyAttributes == nil {
		return nil, &errs.Message{Msg: "unseal options with KeyAttributes required"}
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyAttrs := opts.KeyAttributes

	// Verify key ID matches (check both KeyID() and legacy ID() formats)
	if sealed.KeyID != "" && sealed.KeyID != keyAttrs.KeyID() && sealed.KeyID != keyAttrs.ID() {
		return nil, &errs.Message{Msg: fmt.Sprintf("key ID mismatch: sealed with %s, attempting unseal with %s", sealed.KeyID, keyAttrs.KeyID())}
	}

	// Load the private key
	privateKey, err := b.GetKey(ctx, keyAttrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to load sealing key", Err: err}
	}

	// Derive the sealing key from the private key material
	sealingKey, err := deriveSealingKey(privateKey, keyAttrs.ID())
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to derive sealing key", Err: err}
	}
	defer enclave.Wipe(sealingKey)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sealingKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create AES cipher", Err: err}
	}

	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. Seal prepends
	// the same 96-bit nonce and Open strips it, so once the sealed blob is
	// split back into the Nonce/Ciphertext/Tag fields below the stored shape is
	// unchanged and data sealed by earlier builds still unseals.
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Verify nonce size. The random-nonce AEAD reports a NonceSize of zero
	// because it manages the nonce itself, so the stored nonce is checked
	// against the constant rather than against the AEAD.
	if len(sealed.Nonce) != gcmNonceSize {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid nonce size: expected %d, got %d", gcmNonceSize, len(sealed.Nonce))}
	}

	// Decrypt with AAD if provided
	var aad []byte
	if opts.AAD != nil {
		aad = opts.AAD
	}

	// gcm.Open expects the nonce prepended and the tag appended, which is the
	// layout Seal produced before it was split into fields.
	blob := make([]byte, 0, len(sealed.Nonce)+len(sealed.Ciphertext)+len(sealed.Tag))
	blob = append(blob, sealed.Nonce...)
	blob = append(blob, sealed.Ciphertext...)
	blob = append(blob, sealed.Tag...)

	plaintext, err := gcm.Open(nil, nil, blob, aad)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decrypt (check password/key and AAD)", Err: err}
	}

	return plaintext, nil
}

// deriveSealingKey derives a 256-bit AES key from the private key material using HKDF.
func deriveSealingKey(privateKey crypto.PrivateKey, keyID string) ([]byte, error) {
	// Extract key material based on key type
	var keyMaterial []byte

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		// Use the private exponent D as key material
		keyMaterial = k.D.Bytes() // crypto/rsa.PrivateKey.D is not deprecated (unlike ecdsa's), no nolint needed
	case *ecdsa.PrivateKey:
		// Use the private scalar D as key material
		keyMaterial = k.D.Bytes() //nolint:staticcheck // raw private scalar needed for key derivation
	case ed25519.PrivateKey:
		// Ed25519 private key is the seed (first 32 bytes)
		keyMaterial = k[:32]
	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type for sealing: %T", privateKey)}
	}

	// Create HKDF with SHA-256
	salt := []byte(keyID) // Use key ID as salt for domain separation

	// crypto/hkdf.Key (the stdlib RFC 5869 implementation, Go 1.24+) is used
	// instead of golang.org/x/crypto/hkdf.New: the x/crypto Reader
	// constructor converts the stdlib's own FIPS 140-only refusals into a
	// panic, which would crash this process instead of returning the error
	// this function promises.
	derivedKey, err := hkdf.Key(sha256.New, keyMaterial, salt, sealingKeyInfo, 32)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "HKDF key derivation failed", Err: err}
	}

	return derivedKey, nil
}

// hashBytes returns SHA-256 hash of the input
func hashBytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// MarshalSealedData serializes SealedData to JSON for storage
func MarshalSealedData(sealed *types.SealedData) ([]byte, error) {
	return json.Marshal(sealed)
}

// UnmarshalSealedData deserializes SealedData from JSON
func UnmarshalSealedData(data []byte) (*types.SealedData, error) {
	var sealed types.SealedData
	if err := json.Unmarshal(data, &sealed); err != nil {
		return nil, err
	}
	return &sealed, nil
}
