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

//go:build awskms

package awskms

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Ensure Backend implements types.Sealer interface
var _ types.Sealer = (*Backend)(nil)

// CanSeal returns true if this backend supports sealing operations and has a client.
// AWS KMS supports cloud-managed sealing using KMS-managed symmetric keys.
func (b *Backend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.client != nil
}

// Seal encrypts/protects data using an AWS KMS-managed symmetric key.
//
// The sealing process:
//  1. Find the symmetric key specified in opts.KeyAttributes
//  2. Encrypt the data using AWS KMS Encrypt API
//  3. Key material never leaves AWS KMS
//
// Security Note: This uses cloud-managed encryption. The symmetric key
// material is sealed within AWS KMS and can only be used through KMS APIs.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - data: The plaintext data to seal
//   - opts: Sealing options (KeyAttributes required to identify the sealing key)
//
// Returns SealedData containing the encrypted payload, or error.
func (b *Backend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if opts == nil || opts.KeyAttributes == nil {
		return nil, fmt.Errorf("seal options with KeyAttributes required")
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	keyAttrs := opts.KeyAttributes

	// Validate that the key is a symmetric key
	if !keyAttrs.IsSymmetric() {
		return nil, fmt.Errorf("AWS KMS sealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)
	}

	// Get the symmetric encrypter for this key
	encrypter, err := b.SymmetricEncrypter(keyAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
	}

	// Set up encryption options
	encOpts := &types.EncryptOptions{
		AdditionalData: opts.AAD,
	}

	// Encrypt the data via AWS KMS
	encrypted, err := encrypter.Encrypt(data, encOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Build the sealed data result
	// Note: AWS KMS returns an opaque ciphertext blob that includes
	// everything (ciphertext, nonce, tag, algorithm info)
	sealed := &types.SealedData{
		Backend:    types.BackendTypeAWSKMS,
		Ciphertext: encrypted.Ciphertext,
		KeyID:      keyAttrs.ID(),
		Metadata:   make(map[string][]byte),
	}

	// Store algorithm in metadata
	sealed.Metadata["awskms:algorithm"] = []byte(encrypted.Algorithm)

	// Store AAD indicator in metadata if provided
	if opts.AAD != nil {
		sealed.Metadata["awskms:has_aad"] = []byte("true")
	}

	return sealed, nil
}

// Unseal decrypts/recovers data using an AWS KMS-managed symmetric key.
//
// The unsealing process:
//  1. Find the symmetric key specified in opts.KeyAttributes
//  2. Decrypt the data using AWS KMS Decrypt API
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sealed: The sealed data from a previous Seal operation
//   - opts: Unsealing options (KeyAttributes required, AAD must match if used during sealing)
//
// Returns the original plaintext data, or error if unsealing fails.
func (b *Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, fmt.Errorf("sealed data is required")
	}

	if sealed.Backend != types.BackendTypeAWSKMS {
		return nil, fmt.Errorf("sealed data was not created by AWS KMS backend (got %s)", sealed.Backend)
	}

	if opts == nil || opts.KeyAttributes == nil {
		return nil, fmt.Errorf("unseal options with KeyAttributes required")
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	keyAttrs := opts.KeyAttributes

	// Verify key ID matches if present
	if sealed.KeyID != "" && sealed.KeyID != keyAttrs.ID() {
		return nil, fmt.Errorf("key ID mismatch: sealed with %s, attempting unseal with %s",
			sealed.KeyID, keyAttrs.ID())
	}

	// Validate that the key is a symmetric key
	if !keyAttrs.IsSymmetric() {
		return nil, fmt.Errorf("AWS KMS unsealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)
	}

	// Get the symmetric encrypter for this key
	encrypter, err := b.SymmetricEncrypter(keyAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
	}

	// Reconstruct encrypted data
	// AWS KMS uses an opaque blob, so ciphertext contains everything
	encrypted := &types.EncryptedData{
		Ciphertext: sealed.Ciphertext,
	}

	// Get algorithm from metadata if available
	if alg, ok := sealed.Metadata["awskms:algorithm"]; ok {
		encrypted.Algorithm = string(alg)
	}

	// Set up decryption options
	decOpts := &types.DecryptOptions{
		AdditionalData: opts.AAD,
	}

	// Decrypt the data via AWS KMS
	plaintext, err := encrypter.Decrypt(encrypted, decOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data (check key and AAD): %w", err)
	}

	return plaintext, nil
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
