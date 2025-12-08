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

package pkcs8

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"golang.org/x/crypto/hkdf"
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
		return nil, fmt.Errorf("seal options with KeyAttributes required")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyAttrs := opts.KeyAttributes

	// Load the private key
	privateKey, err := b.GetKey(keyAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealing key: %w", err)
	}

	// Derive the sealing key from the private key material
	sealingKey, err := deriveSealingKey(privateKey, keyAttrs.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to derive sealing key: %w", err)
	}
	defer clearBytes(sealingKey)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sealingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with AAD if provided
	var aad []byte
	if opts.AAD != nil {
		aad = opts.AAD
	}

	ciphertext := gcm.Seal(nil, nonce, data, aad)

	// Build the sealed data result
	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS8,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		KeyID:      keyAttrs.ID(),
		Metadata:   make(map[string][]byte),
	}

	// Store AAD in metadata if provided
	if aad != nil {
		sealed.Metadata["pkcs8:aad_hash"] = hashBytes(aad)
	}

	return sealed, nil
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
		return nil, fmt.Errorf("sealed data is required")
	}

	// Accept both PKCS#8 and Software backend types since Software delegates to PKCS#8
	if sealed.Backend != types.BackendTypePKCS8 && sealed.Backend != types.BackendTypeSoftware {
		return nil, fmt.Errorf("sealed data was not created by PKCS#8 backend (got %s)", sealed.Backend)
	}

	if opts == nil || opts.KeyAttributes == nil {
		return nil, fmt.Errorf("unseal options with KeyAttributes required")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	keyAttrs := opts.KeyAttributes

	// Verify key ID matches
	if sealed.KeyID != "" && sealed.KeyID != keyAttrs.ID() {
		return nil, fmt.Errorf("key ID mismatch: sealed with %s, attempting unseal with %s",
			sealed.KeyID, keyAttrs.ID())
	}

	// Load the private key
	privateKey, err := b.GetKey(keyAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealing key: %w", err)
	}

	// Derive the sealing key from the private key material
	sealingKey, err := deriveSealingKey(privateKey, keyAttrs.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to derive sealing key: %w", err)
	}
	defer clearBytes(sealingKey)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(sealingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Verify nonce size
	if len(sealed.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d, got %d",
			gcm.NonceSize(), len(sealed.Nonce))
	}

	// Decrypt with AAD if provided
	var aad []byte
	if opts.AAD != nil {
		aad = opts.AAD
	}

	plaintext, err := gcm.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt (check password/key and AAD): %w", err)
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
		keyMaterial = k.D.Bytes()
	case *ecdsa.PrivateKey:
		// Use the private scalar D as key material
		keyMaterial = k.D.Bytes()
	case ed25519.PrivateKey:
		// Ed25519 private key is the seed (first 32 bytes)
		keyMaterial = k[:32]
	default:
		return nil, fmt.Errorf("unsupported key type for sealing: %T", privateKey)
	}

	// Create HKDF with SHA-256
	salt := []byte(keyID) // Use key ID as salt for domain separation
	info := []byte(sealingKeyInfo)

	hkdfReader := hkdf.New(sha256.New, keyMaterial, salt, info)

	// Derive 32 bytes for AES-256
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	return derivedKey, nil
}

// hashBytes returns SHA-256 hash of the input
func hashBytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// clearBytes zeros out a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
