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

//go:build vault

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Ensure Backend implements types.Sealer interface
var _ types.Sealer = (*Backend)(nil)

// CanSeal returns true if this backend supports sealing operations and has a client.
// Vault supports cloud-managed sealing using Transit engine symmetric keys.
func (b *Backend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.client != nil
}

// Seal encrypts/protects data using a Vault Transit engine symmetric key.
//
// The sealing process:
//  1. Find the symmetric key specified in opts.KeyAttributes
//  2. Encrypt the data using Vault Transit Encrypt API
//  3. Key material never leaves Vault
//
// Security Note: This uses Vault-managed encryption. The symmetric key
// material is sealed within Vault and can only be used through Vault APIs.
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
		return nil, &errs.Message{Msg: fmt.Sprintf("Vault sealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)}
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

	// Encrypt the data via Vault Transit
	encrypted, err := encrypter.Encrypt(data, encOpts)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to encrypt data", Err: err}
	}

	// Build the sealed data result
	// Note: Vault returns ciphertext in format "vault:v1:base64..." which
	// includes all necessary information (ciphertext, version, metadata)
	sealed := &types.SealedData{
		Backend:    BackendTypeVault,
		Ciphertext: encrypted.Ciphertext,
		KeyID:      keyAttrs.ID(),
		Metadata:   make(map[string][]byte),
	}

	// Store algorithm in metadata
	sealed.Metadata["vault:algorithm"] = []byte(encrypted.Algorithm)

	// Store AAD indicator in metadata if provided
	if opts.AAD != nil {
		sealed.Metadata["vault:has_aad"] = []byte("true")
	}

	return sealed, nil
}

// Unseal decrypts/recovers data using a Vault Transit engine symmetric key.
//
// The unsealing process:
//  1. Find the symmetric key specified in opts.KeyAttributes
//  2. Decrypt the data using Vault Transit Decrypt API
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
//   - sealed.Backend is not Vault, sealed.KeyID names a different key than
//     opts.KeyAttributes, or the ciphertext is empty (checked locally);
//   - Transit's decrypt answers HTTP 400 with "cipher: message
//     authentication failed" (a ciphertext tampered with, truncated or
//     extended, produced under another key, or sealed under different
//     associated_data) or an "invalid ciphertext" message (no "vault:v"
//     prefix, an undecodable version or base64 body, a body shorter than a
//     nonce). Transit reports these only as text, so the messages are matched;
//     see rejectsSealedData.
//
// Every other failure -- a cancelled or expired ctx, a Vault that is
// unreachable, sealed or throttling (5xx, 429), a token without permission
// (403), a key Transit does not have ("encryption key not found"), a
// ciphertext version the key no longer has or no longer allows ("version is
// too new", "disallowed by policy (too old)"), or a server that ignores
// associated_data (ErrAssociatedDataIgnored) -- is the environment, not the
// data, and does not match the sentinel.
func (b *Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, &errs.Message{Msg: "sealed data is required"}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if sealed.Backend != BackendTypeVault {
		return nil, types.SealedDataAuthenticationError(
			fmt.Sprintf("sealed data was not created by Vault backend (got %s)", sealed.Backend), nil)
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
		return nil, &errs.Message{Msg: fmt.Sprintf("Vault unsealing requires a symmetric key, got %s", keyAttrs.KeyAlgorithm)}
	}

	// A Transit ciphertext is never empty; one that is was truncated away.
	if len(sealed.Ciphertext) == 0 {
		return nil, types.SealedDataAuthenticationError("ciphertext is empty", nil)
	}

	// Get the symmetric encrypter for this key
	encrypter, err := b.SymmetricEncrypter(ctx, keyAttrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get symmetric encrypter", Err: err}
	}

	// Reconstruct encrypted data
	// Vault's ciphertext contains all necessary information
	encrypted := &types.EncryptedData{
		Ciphertext: sealed.Ciphertext,
	}

	// Get algorithm from metadata if available
	if alg, ok := sealed.Metadata["vault:algorithm"]; ok {
		encrypted.Algorithm = string(alg)
	}

	// Set up decryption options
	decOpts := &types.DecryptOptions{
		AdditionalData: opts.AAD,
	}

	// Decrypt the data via Vault Transit
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

// transitCiphertextRejections are the message prefixes Vault Transit's
// decrypt endpoint answers with HTTP 400 when the ciphertext itself does not
// authenticate or does not parse: the AEAD open failure Go's crypto/cipher
// reports, and the "invalid ciphertext" family (no prefix, an undecodable
// version or base64 body, a body shorter than a nonce).
var transitCiphertextRejections = []string{
	"cipher: message authentication failed",
	"invalid ciphertext",
}

// transitKeyReferenceFailures are "invalid ciphertext" answers that are about
// the key Transit holds rather than the ciphertext: a version newer than the
// key's latest means the key lost versions (a restore, a different mount), the
// same as a key that is not found.
var transitKeyReferenceFailures = map[string]struct{}{
	"invalid ciphertext: version is too new": {},
}

// rejectsSealedData reports whether err is a Transit decrypt answer that
// blames the ciphertext: an HTTP 400 whose every message is one of
// transitCiphertextRejections and none a transitKeyReferenceFailures.
func rejectsSealedData(err error) bool {
	var respErr *vaultapi.ResponseError
	if !errors.As(err, &respErr) || respErr.StatusCode != http.StatusBadRequest || len(respErr.Errors) == 0 {
		return false
	}
	for _, msg := range respErr.Errors {
		if _, keyFailure := transitKeyReferenceFailures[msg]; keyFailure || !hasAnyPrefix(msg, transitCiphertextRejections) {
			return false
		}
	}
	return true
}

// hasAnyPrefix reports whether s starts with one of prefixes.
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
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
