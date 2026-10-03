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

//go:build azurekv

package azurekv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Ensure Backend implements types.Sealer interface
var _ types.Sealer = (*Backend)(nil)

// CanSeal returns true if this backend supports sealing operations.
// Azure Key Vault supports sealing via symmetric keys stored as secrets.
func (b *Backend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.config != nil && b.config.VaultURL != ""
}

// Seal encrypts/protects data using an Azure Key Vault-managed symmetric key.
//
// The sealing process:
//  1. Find the symmetric key specified in opts.KeyAttributes
//  2. Encrypt the data using AES-GCM with the key material
//  3. Key material is stored securely as an Azure Key Vault secret
//
// Security Note: Azure Key Vault Standard tier stores symmetric keys as secrets.
// The key material is retrieved and encryption happens locally. Premium tier
// with HSM would provide hardware-backed encryption.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - data: The plaintext data to seal
//   - opts: Sealing options (KeyAttributes required to identify the sealing key)
//
// Returns SealedData containing the encrypted payload, or error.
func (b *Backend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if opts == nil || opts.KeyAttributes == nil {
		return nil, &errs.Message{Msg: "seal options with KeyAttributes required"}
	}

	keyAttrs := opts.KeyAttributes

	// Validate that the key is a symmetric key
	if !keyAttrs.IsSymmetric() {
		return nil, &errs.Message{Msg: fmt.Sprintf("Azure KV sealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)}
	}

	// Get the symmetric encrypter for this key
	encrypter, err := b.SymmetricEncrypter(ctx, keyAttrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get symmetric encrypter", Err: err}
	}

	// Set up encryption options
	encOpts := &types.EncryptOptions{
		AdditionalData: opts.AAD,
	}

	// Encrypt the data
	encrypted, err := encrypter.Encrypt(data, encOpts)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to encrypt data", Err: err}
	}

	// Build the sealed data result
	sealed := &types.SealedData{
		Backend:    types.BackendTypeAzureKV,
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
		KeyID:      keyAttrs.ID(),
		Metadata:   make(map[string][]byte),
	}

	// Store algorithm in metadata
	sealed.Metadata["azurekv:algorithm"] = []byte(encrypted.Algorithm)

	// Store the GCM nonce mode in metadata whenever it is not the zero
	// value: under GODEBUG=fips140=only, Encrypt may have substituted
	// cipher.NewGCMWithRandomNonce (see azureSymmetricKey.Encrypt), and
	// Unseal must reconstruct the identical AEAD construction regardless of
	// the FIPS posture of the process that later unseals this data.
	if encrypted.GCMNonceMode != types.GCMNonceModeExplicit {
		sealed.Metadata["azurekv:gcm_nonce_mode"] = []byte(encrypted.GCMNonceMode)
	}

	// Store AAD indicator in metadata if provided
	if opts.AAD != nil {
		sealed.Metadata["azurekv:has_aad"] = []byte("true")
	}

	return sealed, nil
}

// Unseal decrypts/recovers data using an Azure Key Vault-managed symmetric key.
//
// The unsealing process:
//  1. Find the symmetric key specified in opts.KeyAttributes
//  2. Decrypt the data using AES-GCM
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sealed: The sealed data from a previous Seal operation
//   - opts: Unsealing options (KeyAttributes required, AAD must match if used during sealing)
//
// Returns the original plaintext data, or error if unsealing fails.
//
// Sealed-data authentication: Azure Key Vault holds the key material and the
// AES-GCM open runs locally, so the error matches
// types.ErrSealedDataAuthentication, joined with the native cause, exactly
// when the sealed data is at fault --
//   - sealed.Backend is not Azure KV, sealed.KeyID names a different key than
//     opts.KeyAttributes, or the azurekv:gcm_nonce_mode metadata names no
//     construction this backend writes;
//   - the AES-GCM decrypt reports ErrCiphertextRejected: a tag or nonce of
//     the wrong length, or gcm.Open refusing a ciphertext that was tampered
//     with, truncated or extended, produced under another key, or sealed
//     under different AAD.
//
// Every other failure -- a cancelled or expired ctx, a key secret Key Vault
// cannot return (unreachable, throttled, forbidden, not found), key material
// that does not build an AES cipher, or a construction the process's FIPS
// mode refuses -- is the environment, not the data, and does not match the
// sentinel.
func (b *Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, &errs.Message{Msg: "sealed data is required"}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if sealed.Backend != types.BackendTypeAzureKV {
		return nil, types.SealedDataAuthenticationError(
			fmt.Sprintf("sealed data was not created by Azure KV backend (got %s)", sealed.Backend), nil)
	}

	if opts == nil || opts.KeyAttributes == nil {
		return nil, &errs.Message{Msg: "unseal options with KeyAttributes required"}
	}

	keyAttrs := opts.KeyAttributes

	// Verify key ID matches if present
	if sealed.KeyID != "" && sealed.KeyID != keyAttrs.ID() {
		return nil, types.SealedDataAuthenticationError(
			fmt.Sprintf("key ID mismatch: sealed with %s, attempting unseal with %s", sealed.KeyID, keyAttrs.ID()), nil)
	}

	// Validate that the key is a symmetric key
	if !keyAttrs.IsSymmetric() {
		return nil, &errs.Message{Msg: fmt.Sprintf("Azure KV unsealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)}
	}

	// Get the GCM nonce mode from metadata if available; its absence means
	// GCMNonceModeExplicit, the zero value, exactly as Seal left it unset.
	// Seal records only GCMNonceModeRandom, so any other recorded value is
	// not something this backend wrote.
	nonceMode := types.GCMNonceModeExplicit
	if mode, ok := sealed.Metadata["azurekv:gcm_nonce_mode"]; ok {
		nonceMode = types.GCMNonceMode(mode)
		if nonceMode != types.GCMNonceModeRandom {
			return nil, types.SealedDataAuthenticationError(
				fmt.Sprintf("unknown GCM nonce mode %q", mode), nil)
		}
	}

	// Get the symmetric encrypter for this key
	encrypter, err := b.SymmetricEncrypter(ctx, keyAttrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get symmetric encrypter", Err: err}
	}

	// Reconstruct encrypted data
	encrypted := &types.EncryptedData{
		Ciphertext:   sealed.Ciphertext,
		Nonce:        sealed.Nonce,
		Tag:          sealed.Tag,
		GCMNonceMode: nonceMode,
	}

	// Get algorithm from metadata if available
	if alg, ok := sealed.Metadata["azurekv:algorithm"]; ok {
		encrypted.Algorithm = string(alg)
	}

	// Set up decryption options
	decOpts := &types.DecryptOptions{
		AdditionalData: opts.AAD,
	}

	// Decrypt the data
	plaintext, err := encrypter.Decrypt(encrypted, decOpts)
	if err != nil {
		wrapped := &errs.Wrapped{Msg: "failed to decrypt data (check key and AAD)", Err: err}
		if errors.Is(err, ErrCiphertextRejected) {
			return nil, types.SealedDataAuthenticationError("", wrapped)
		}
		return nil, wrapped
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
