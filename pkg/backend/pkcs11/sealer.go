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

//go:build pkcs11

package pkcs11

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

// CanSeal returns true if this backend supports sealing operations and is initialized.
// PKCS#11 supports hardware-backed sealing using HSM-resident symmetric keys.
func (b *Backend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pool != nil && b.p11ctx != nil
}

// checkInitialized reports whether the backend has an active PKCS#11 context.
//
// It takes and releases the read lock itself rather than leaving it held. Seal
// and Unseal must not hold b.mu across their call to SymmetricEncrypter, which
// reacquires the same RWMutex through GetSymmetricKey: sync.RWMutex documents
// that a recursive read lock deadlocks if a writer blocks between the two
// acquisitions, and GenerateSymmetricKey, Initialize and Close are all writers.
// The window is small, which is exactly what makes it the kind of deadlock that
// only appears under load in production.
func (b *Backend) checkInitialized() error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.pool == nil || b.p11ctx == nil {
		return ErrNotInitialized
	}
	return nil
}

// Seal encrypts/protects data using an HSM-resident symmetric key.
//
// The sealing process:
//  1. Find or use the symmetric key specified in opts.KeyAttributes
//  2. Encrypt the data using AES-GCM on the HSM hardware
//  3. The key material never leaves the HSM
//
// Security Note: This uses hardware-backed encryption. The symmetric key
// material is sealed within the HSM and can only be used through HSM operations.
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

	if err := b.checkInitialized(); err != nil {
		return nil, err
	}

	keyAttrs := opts.KeyAttributes

	// Validate that the key is a symmetric key
	if !keyAttrs.IsSymmetric() {
		return nil, &errs.Message{Msg: fmt.Sprintf("PKCS#11 sealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)}
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

	// Encrypt the data on the HSM
	encrypted, err := encrypter.Encrypt(data, encOpts)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to encrypt data", Err: err}
	}

	// Build the sealed data result
	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
		KeyID:      keyAttrs.ID(),
		Metadata:   make(map[string][]byte),
	}

	// Store algorithm in metadata
	sealed.Metadata["pkcs11:algorithm"] = []byte(encrypted.Algorithm)

	// Store AAD hash in metadata if provided
	if opts.AAD != nil {
		sealed.Metadata["pkcs11:has_aad"] = []byte("true")
	}

	return sealed, nil
}

// Unseal decrypts/recovers data using an HSM-resident symmetric key.
//
// The unsealing process:
//  1. Find the symmetric key specified in opts.KeyAttributes
//  2. Decrypt the data using AES-GCM on the HSM hardware
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sealed: The sealed data from a previous Seal operation
//   - opts: Unsealing options (KeyAttributes required, AAD must match if used during sealing)
//
// Returns the original plaintext data, or error if unsealing fails.
//
// Sealed-data authentication: the error matches
// types.ErrSealedDataAuthentication, joined with the native cause, exactly
// when the sealed data is at fault --
//   - sealed.Backend is not PKCS#11, or sealed.KeyID names a different key
//     than opts.KeyAttributes;
//   - the nonce or tag is not the AES-GCM length (ErrInvalidNonceLength,
//     ErrInvalidTagLength), checked before the token is touched;
//   - C_Decrypt refuses the ciphertext with a return value that names it
//     (ErrCiphertextRejected): CKR_ENCRYPTED_DATA_INVALID,
//     CKR_ENCRYPTED_DATA_LEN_RANGE or CKR_AEAD_DECRYPT_FAILED -- a ciphertext
//     that was tampered with, truncated or extended, produced under another
//     key, or sealed under different AAD.
//
// Every other failure -- a cancelled or expired ctx, an uninitialized or
// closed backend, a key missing from the token, a C_DecryptInit failure
// (ErrDecryptInit), and any other token answer (CKR_DEVICE_ERROR,
// CKR_DEVICE_REMOVED, CKR_SESSION_*, CKR_*_MEMORY, CKR_USER_NOT_LOGGED_IN,
// CKR_PIN_*, CKR_GENERAL_ERROR) -- does not match the sentinel.
// CKR_GENERAL_ERROR is the specification's unrecoverable token error; a
// module that also returns it for a GCM tag mismatch (SoftHSM v2) reports a
// tampered ciphertext without the sentinel, because the code alone cannot
// tell the tag check from a token fault (see ciphertextRejections).
func (b *Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, &errs.Message{Msg: "sealed data is required"}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if sealed.Backend != types.BackendTypePKCS11 {
		return nil, types.SealedDataAuthenticationError(
			fmt.Sprintf("sealed data was not created by PKCS#11 backend (got %s)", sealed.Backend), nil)
	}

	if opts == nil || opts.KeyAttributes == nil {
		return nil, &errs.Message{Msg: "unseal options with KeyAttributes required"}
	}

	if err := b.checkInitialized(); err != nil {
		return nil, err
	}

	keyAttrs := opts.KeyAttributes

	// Verify key ID matches if present
	if sealed.KeyID != "" && sealed.KeyID != keyAttrs.ID() {
		return nil, types.SealedDataAuthenticationError(
			fmt.Sprintf("key ID mismatch: sealed with %s, attempting unseal with %s", sealed.KeyID, keyAttrs.ID()), nil)
	}

	// Validate that the key is a symmetric key
	if !keyAttrs.IsSymmetric() {
		return nil, &errs.Message{Msg: fmt.Sprintf("PKCS#11 unsealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)}
	}

	// Get the symmetric encrypter for this key
	encrypter, err := b.SymmetricEncrypter(ctx, keyAttrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get symmetric encrypter", Err: err}
	}

	// Reconstruct encrypted data
	encrypted := &types.EncryptedData{
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
	}

	// Get algorithm from metadata if available
	if alg, ok := sealed.Metadata["pkcs11:algorithm"]; ok {
		encrypted.Algorithm = string(alg)
	}

	// Set up decryption options
	decOpts := &types.DecryptOptions{
		AdditionalData: opts.AAD,
	}

	// Decrypt the data on the HSM
	plaintext, err := encrypter.Decrypt(encrypted, decOpts)
	if err != nil {
		wrapped := &errs.Wrapped{Msg: "failed to decrypt data (check key and AAD)", Err: err}
		if rejectsSealedData(err) {
			return nil, types.SealedDataAuthenticationError("", wrapped)
		}
		return nil, wrapped
	}

	return plaintext, nil
}

// rejectsSealedData reports whether a Decrypt error blames the sealed data:
// a malformed nonce or tag, or a ciphertext the token refused.
func rejectsSealedData(err error) bool {
	return errors.Is(err, ErrCiphertextRejected) ||
		errors.Is(err, ErrInvalidNonceLength) ||
		errors.Is(err, ErrInvalidTagLength)
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
