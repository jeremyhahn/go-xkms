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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// vaultSymmetricKey implements types.SymmetricKey for Vault Transit engine symmetric keys.
// Since the actual key material never leaves Vault, this implementation stores the
// Vault key name as a reference.
type vaultSymmetricKey struct {
	algorithm string
	keySize   int
	keyName   string // Vault Transit key name
}

// Algorithm returns the symmetric algorithm identifier.
func (k *vaultSymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *vaultSymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns an error because Vault Transit keys cannot expose raw key material.
// The key material stays in Vault and can only be used through Vault operations.
func (k *vaultSymmetricKey) Raw() ([]byte, error) {
	return nil, &errs.Wrapped{Msg: "Vault Transit symmetric keys do not expose raw key material", Err: backend.ErrNotSupported}
}

// vaultSymmetricEncrypter implements types.SymmetricEncrypter using Vault Transit engine.
type vaultSymmetricEncrypter struct {
	backend *Backend
	keyName string
	attrs   *types.KeyAttributes
}

// GenerateSymmetricKey generates a new symmetric key in Vault's Transit engine.
// Vault Transit supports AES-256-GCM for symmetric encryption.
func (b *Backend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("attributes specify asymmetric algorithm: %s", attrs.KeyAlgorithm)}
	}

	// Vault Transit only supports AES-256-GCM for symmetric encryption
	if attrs.SymmetricAlgorithm.KeySize() != 256 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("Vault Transit only supports AES-256 symmetric keys, got: %d bits", attrs.SymmetricAlgorithm.KeySize())}
	}

	keyName := b.sanitizeKeyName(attrs.CN)

	// Check if key already exists in metadata
	exists, err := storage.KeyExists(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to check key existence", Err: err}
	}
	if exists {
		return nil, &errs.Detail{Err: backend.ErrKeyAlreadyExists, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	// Create symmetric key in Vault Transit engine. Unlike GenerateKey's
	// asymmetric keys -- which are hardcoded exportable:false because H8
	// found no legitimate use for exporting a private key whose public half
	// is already available through the ordinary read-key endpoint -- a
	// symmetric key has no such alternative: attrs.Exportable is the caller's
	// only way to opt into ExportKeyMaterial ever working for this key, the
	// same CKA_EXTRACTABLE-equivalent convention every other backend in this
	// project honors. The default stays secure: an attrs.Exportable left
	// unset creates a non-exportable key, exactly as before.
	path := fmt.Sprintf("%s/keys/%s", b.config.TransitPath, keyName)
	data := map[string]interface{}{
		"type":                   "aes256-gcm96", // Vault's AES-256-GCM with 96-bit nonce
		"exportable":             attrs.Exportable,
		"allow_plaintext_backup": false,
		"deletion_allowed":       true, // Allow key deletion (required for cleanup)
	}

	logical := b.client.Logical()
	_, err = logical.WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create symmetric key in vault", Err: err}
	}

	// Store metadata. exportable and sensitive both mirror the caller's own
	// KeyAttributes so ListKeys can round-trip them truthfully (go-xkms#932).
	metadata := map[string]interface{}{
		"cn":                  attrs.CN,
		"symmetric_algorithm": string(attrs.SymmetricAlgorithm),
		// uint8, matching GenerateKey's asymmetric metadata (vault.go) and
		// the float64 ListKeys parses back: string(attrs.KeyType) converts
		// the numeric KeyType as a Unicode code point, not a decimal string
		// (KeyType is uint8), which round-tripped through JSON as an
		// unparseable single-rune string and left every symmetric key's
		// KeyType at its zero value once ListKeys tried to read it back
		// (go-xkms#705).
		"key_type":   uint8(attrs.KeyType),
		"store_type": backend.STORE_VAULT,
		"vault_name": keyName,
		"key_size":   256,
		"symmetric":  true,
		"exportable": attrs.Exportable,
		"sensitive":  attrs.Sensitive,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	// Initialize AEAD tracking options after successful key generation.
	// The caller's policy wins; the default only applies when none was given.
	// Discarding it would silently downgrade a conservative nonce or bytes
	// limit to the default.
	if b.tracker != nil {
		aeadOpts := attrs.AEADOptions
		if aeadOpts == nil {
			aeadOpts = types.DefaultAEADOptions()
		}
		if err := b.tracker.SetAEADOptions(attrs.CN, aeadOpts); err != nil {
			fmt.Printf("Warning: failed to set AEAD options: %v\n", err)
		}
	}

	return &vaultSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   256, // Vault Transit symmetric keys are always 256-bit
		keyName:   keyName,
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key by its attributes.
func (b *Backend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("attributes specify asymmetric algorithm: %s", attrs.KeyAlgorithm)}
	}

	// Load metadata. Only a genuine storage.ErrNotFound is reported as
	// ErrKeyNotFound; any other failure from the metadata store must not be
	// conflated with "no key yet" (matches GetKey's classification).
	metadataBytes, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("metadata lookup for %s: %v", attrs.CN, err)}
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unmarshal metadata", Err: err}
	}

	// Verify it's a symmetric key
	isSymmetric, ok := metadata["symmetric"].(bool)
	if !ok || !isSymmetric {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key is not a symmetric key: %s", attrs.CN)}
	}

	keyName, ok := metadata["vault_name"].(string)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "missing vault_name"}
	}

	// Verify key exists in Vault. A nil secret with no error is Vault's
	// convention for a Transit path that does not exist, so only that
	// combination is reported as ErrKeyNotFound; a non-nil error is a
	// transport, auth, or ACL failure and must not be conflated with "no
	// key yet" (matches getPublicKeyVersion's classification).
	path := fmt.Sprintf("%s/keys/%s", b.config.TransitPath, keyName)
	logical := b.client.Logical()
	secret, err := logical.ReadWithContext(ctx, path)
	if err != nil {
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("failed to read key from vault: %v", err)}
	}
	if secret == nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: keyName}
	}

	return &vaultSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   256, // Vault Transit symmetric keys are always 256-bit
		keyName:   keyName,
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the key identified by attrs.
func (b *Backend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("attributes specify asymmetric algorithm: %s", attrs.KeyAlgorithm)}
	}

	// Load metadata to verify key exists. Only a genuine storage.ErrNotFound
	// is reported as ErrKeyNotFound; any other failure from the metadata
	// store must not be conflated with "no key yet" (matches GetKey's
	// classification).
	b.mu.RLock()
	metadataBytes, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
	b.mu.RUnlock()

	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("metadata lookup for %s: %v", attrs.CN, err)}
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unmarshal metadata", Err: err}
	}

	// Verify it's a symmetric key
	isSymmetric, ok := metadata["symmetric"].(bool)
	if !ok || !isSymmetric {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key is not a symmetric key: %s", attrs.CN)}
	}

	keyName, ok := metadata["vault_name"].(string)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "missing vault_name"}
	}

	return &vaultSymmetricEncrypter{
		backend: b,
		keyName: keyName,
		attrs:   attrs,
	}, nil
}

// Encrypt encrypts plaintext using Vault Transit engine Encrypt API.
// Vault Transit handles nonce generation and authentication automatically.
// Additional authenticated data (AAD) is supported via the context parameter.
func (e *vaultSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	// Vault Transit returns a self-describing ciphertext string and never
	// exposes the authentication tag, so the tag length is not this backend's
	// to choose.
	if opts != nil {
		if err := aead.RequireDefaultTagSize(opts.TagSize, "Vault Transit"); err != nil {
			return nil, err
		}
		// Vault Transit's encrypt endpoint manages nonce generation
		// server-side and exposes no parameter to override it. A
		// caller-supplied nonce used to be accepted here and silently
		// dropped, which let a caller believe its own nonce discipline
		// governed this encryption when Vault's did instead. Refused
		// outright rather than ignored.
		if opts.Nonce != nil {
			return nil, backend.ErrCallerNonceNotSupported
		}
	}

	// Track bytes encrypted (Vault manages nonces server-side)
	keyID := e.attrs.CN
	if e.backend.tracker != nil {
		if err := e.backend.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, &errs.Wrapped{Msg: "AEAD safety check failed", Err: err}
		}
	}

	ctx := context.Background()
	logical := e.backend.client.Logical()

	// Vault Transit requires base64-encoded plaintext
	input := base64.StdEncoding.EncodeToString(plaintext)

	path := fmt.Sprintf("%s/encrypt/%s", e.backend.config.TransitPath, e.keyName)
	data := map[string]interface{}{
		"plaintext": input,
	}

	// Vault Transit supports AAD via the "context" parameter (must be base64-encoded)
	if opts != nil && opts.AdditionalData != nil {
		data["context"] = base64.StdEncoding.EncodeToString(opts.AdditionalData)
	}

	secret, err := logical.WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "Vault Transit encryption failed", Err: err}
	}

	if secret == nil || secret.Data == nil {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no ciphertext returned"}
	}

	ciphertextInterface, ok := secret.Data["ciphertext"]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no ciphertext in response"}
	}

	ciphertextStr, ok := ciphertextInterface.(string)
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid ciphertext format"}
	}

	// Vault returns ciphertext in format "vault:v1:base64..."
	// We store the entire string as-is since it includes version and metadata
	return &types.EncryptedData{
		Ciphertext: []byte(ciphertextStr), // Store Vault's formatted ciphertext
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
		// Vault handles nonce and tag internally, no need to expose them
		Nonce: nil,
		Tag:   nil,
	}, nil
}

// Decrypt decrypts ciphertext using Vault Transit engine Decrypt API.
// Vault Transit automatically verifies authentication before decrypting.
// Additional authenticated data (AAD) must match what was provided during encryption.
func (e *vaultSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	// See the matching check in Encrypt.
	if opts != nil {
		if err := aead.RequireDefaultTagSize(opts.TagSize, "Vault Transit"); err != nil {
			return nil, err
		}
	}

	ctx := context.Background()
	logical := e.backend.client.Logical()

	path := fmt.Sprintf("%s/decrypt/%s", e.backend.config.TransitPath, e.keyName)
	requestData := map[string]interface{}{
		"ciphertext": string(data.Ciphertext), // Vault-formatted ciphertext
	}

	// If AAD was used during encryption, it must be provided during decryption
	if opts != nil && opts.AdditionalData != nil {
		requestData["context"] = base64.StdEncoding.EncodeToString(opts.AdditionalData)
	}

	secret, err := logical.WriteWithContext(ctx, path, requestData)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "Vault Transit decryption failed (authentication or key error)", Err: err}
	}

	if secret == nil || secret.Data == nil {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no plaintext returned"}
	}

	plaintextInterface, ok := secret.Data["plaintext"]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no plaintext in response"}
	}

	plaintextStr, ok := plaintextInterface.(string)
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid plaintext format"}
	}

	// Vault returns base64-encoded plaintext
	plaintext, err := base64.StdEncoding.DecodeString(plaintextStr)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode plaintext", Err: err}
	}

	return plaintext, nil
}

// GetTracker returns the AEAD safety tracker for this backend.
// This allows external code to inspect tracking state and configuration.
func (b *Backend) GetTracker() types.AEADSafetyTracker {
	return b.tracker
}

// Verify interface compliance at compile time
var _ types.SymmetricKeyProvider = (*Backend)(nil)
var _ types.SymmetricKeyProviderWithTracking = (*Backend)(nil)
var _ types.SymmetricKey = (*vaultSymmetricKey)(nil)
var _ types.SymmetricEncrypter = (*vaultSymmetricEncrypter)(nil)
