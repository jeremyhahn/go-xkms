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

//go:build pkcs11

package canokey

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Ensure Backend implements types.Sealer interface
var _ types.Sealer = (*Backend)(nil)

// CanSeal returns true if this backend supports sealing operations.
// CanoKey supports sealing via envelope encryption using its PIV RSA keys.
func (b *Backend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.initialized
}

// Seal encrypts/protects data using envelope encryption with CanoKey's RSA key.
//
// The envelope encryption process:
//  1. Generate a random Data Encryption Key (DEK) using CanoKey's hardware RNG
//  2. Encrypt the plaintext data with AES-256-GCM using the DEK
//  3. Encrypt the DEK with the CanoKey's RSA public key (RSA-OAEP)
//  4. Store the encrypted DEK in the sealed data metadata
//
// Security characteristics:
//   - DEK is generated using CanoKey's hardware RNG (or software for QEMU)
//   - DEK is protected by CanoKey's RSA key (cannot be decrypted without CanoKey)
//   - Data encryption happens in software (AES-256-GCM)
//   - CanoKey never sees the plaintext data (only encrypts/decrypts the DEK)
//
// This pattern provides:
//   - Hardware-backed key protection (or software for QEMU virtual mode)
//   - High-performance data encryption (software AES-GCM)
//   - PCR-independent sealing (unlike TPM, no platform state required)
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - data: The plaintext data to seal
//   - opts: Sealing options (KeyAttributes required to identify the RSA key)
//
// Returns SealedData containing the encrypted payload and encrypted DEK, or error.
func (b *Backend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if opts == nil || opts.KeyAttributes == nil {
		return nil, ErrSealOptionsRequired
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.initialized {
		return nil, ErrNotInitialized
	}

	keyAttrs := opts.KeyAttributes

	// Step 1: Generate random DEK using CanoKey's hardware RNG
	dek := make([]byte, 32) // 256-bit key for AES-256
	generatedDEK, err := b.GenerateRandom(32)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to generate DEK: %w", err)
	}
	copy(dek, generatedDEK)
	defer clearBytes(dek)

	// Step 2: Encrypt data with AES-256-GCM using the DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("canokey: failed to generate nonce: %w", err)
	}

	// Encrypt with AAD if provided
	var aad []byte
	if opts.AAD != nil {
		aad = opts.AAD
	}

	ciphertext := gcm.Seal(nil, nonce, data, aad)

	// Step 3: Get the RSA public key and encrypt the DEK
	privateKey, err := b.pkcs11.GetKey(keyAttrs)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to get sealing key: %w", err)
	}

	// Extract public key from private key
	var publicKey crypto.PublicKey
	switch k := privateKey.(type) {
	case crypto.Signer:
		publicKey = k.Public()
	default:
		return nil, ErrNotSigner
	}

	// Verify we have an RSA key
	rsaPub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w, got %T", ErrRSAKeyRequired, publicKey)
	}

	// Encrypt the DEK with RSA-OAEP
	encryptedDEK, err := rsa.EncryptOAEP(
		crypto.SHA256.New(),
		rand.Reader,
		rsaPub,
		dek,
		nil, // no label
	)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to encrypt DEK: %w", err)
	}

	// Step 4: Build the sealed data result
	sealed := &types.SealedData{
		Backend:    "canokey",
		Ciphertext: ciphertext,
		Nonce:      nonce,
		KeyID:      keyAttrs.ID(),
		Metadata:   make(map[string][]byte),
	}

	// Store encrypted DEK in metadata
	sealed.Metadata["encryptedDEK"] = []byte(base64.StdEncoding.EncodeToString(encryptedDEK))

	// Store AAD hash in metadata if provided (for verification)
	if aad != nil {
		sealed.Metadata["canokey:aad_hash"] = hashBytes(aad)
	}

	return sealed, nil
}

// Unseal decrypts/recovers data using envelope encryption with CanoKey's RSA key.
//
// The envelope decryption process:
//  1. Extract the encrypted DEK from the sealed data metadata
//  2. Decrypt the DEK using the CanoKey's RSA private key (RSA-OAEP)
//  3. Decrypt the ciphertext using AES-256-GCM with the recovered DEK
//
// This operation requires:
//   - The CanoKey device with the private key
//   - Correct PIN for CanoKey access
//   - Matching AAD if used during sealing
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sealed: The sealed data from a previous Seal operation
//   - opts: Unsealing options (KeyAttributes required, AAD must match if used)
//
// Returns the original plaintext data, or error if unsealing fails.
func (b *Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrSealedDataRequired
	}

	if sealed.Backend != "canokey" {
		return nil, fmt.Errorf("%w (got %s)", ErrBackendMismatch, sealed.Backend)
	}

	if opts == nil || opts.KeyAttributes == nil {
		return nil, ErrUnsealOptionsRequired
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if !b.initialized {
		return nil, ErrNotInitialized
	}

	keyAttrs := opts.KeyAttributes

	// Verify key ID matches
	if sealed.KeyID != "" && sealed.KeyID != keyAttrs.ID() {
		return nil, fmt.Errorf("%w: sealed with %s, attempting unseal with %s",
			ErrKeyIDMismatch, sealed.KeyID, keyAttrs.ID())
	}

	// Step 1: Extract encrypted DEK from metadata
	encryptedDEKBase64, ok := sealed.Metadata["encryptedDEK"]
	if !ok {
		return nil, ErrMissingEncryptedDEK
	}

	encryptedDEK, err := base64.StdEncoding.DecodeString(string(encryptedDEKBase64))
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to decode encrypted DEK: %w", err)
	}

	// Step 2: Get the CanoKey's crypto.Decrypter to decrypt the DEK
	decrypter, err := b.pkcs11.Decrypter(keyAttrs)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to get decrypter: %w", err)
	}

	// Decrypt the DEK using RSA-OAEP
	dekBytes, err := decrypter.Decrypt(rand.Reader, encryptedDEK, &rsa.OAEPOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to decrypt DEK (check PIN and key): %w", err)
	}
	defer clearBytes(dekBytes)

	// Verify DEK size
	if len(dekBytes) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidDEKSize, len(dekBytes))
	}

	// Step 3: Decrypt the data with AES-256-GCM using the recovered DEK
	block, err := aes.NewCipher(dekBytes)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to create GCM: %w", err)
	}

	// Verify nonce size
	if len(sealed.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: expected %d, got %d",
			ErrInvalidNonceSize, gcm.NonceSize(), len(sealed.Nonce))
	}

	// Decrypt with AAD if provided
	var aad []byte
	if opts.AAD != nil {
		aad = opts.AAD
	}

	plaintext, err := gcm.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("canokey: failed to decrypt (check key and AAD): %w", err)
	}

	return plaintext, nil
}

// hashBytes returns SHA-256 hash of the input
func hashBytes(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}

// clearBytes zeros out a byte slice
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
