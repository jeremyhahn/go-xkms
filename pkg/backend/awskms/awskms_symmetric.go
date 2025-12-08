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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// awsKMSSymmetricKey implements types.SymmetricKey for AWS KMS symmetric keys.
// Since the actual key material never leaves AWS KMS, this implementation
// stores the KMS key ID/ARN as a reference.
type awsKMSSymmetricKey struct {
	algorithm string
	keySize   int
	keyID     string // AWS KMS key ID or ARN
}

// Algorithm returns the symmetric algorithm identifier.
func (k *awsKMSSymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *awsKMSSymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns an error because AWS KMS keys cannot expose raw key material.
// The key material stays in AWS KMS and can only be used through KMS operations.
func (k *awsKMSSymmetricKey) Raw() ([]byte, error) {
	return nil, fmt.Errorf("AWS KMS symmetric keys do not expose raw key material: %w", backend.ErrNotSupported)
}

// awsKMSSymmetricEncrypter implements types.SymmetricEncrypter using AWS KMS.
type awsKMSSymmetricEncrypter struct {
	backend *Backend
	keyID   string
	attrs   *types.KeyAttributes
}

// GenerateSymmetricKey generates a new symmetric key in AWS KMS.
// AWS KMS only supports AES-256 symmetric keys (SYMMETRIC_DEFAULT).
func (b *Backend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm: %s", backend.ErrInvalidKeyType, attrs.KeyAlgorithm)
	}

	// AWS KMS only supports 256-bit symmetric keys (AES-256-GCM)
	if attrs.AESAttributes.KeySize != 256 {
		return nil, fmt.Errorf("%w: AWS KMS only supports AES-256 symmetric keys, got: %d bits", backend.ErrNotSupported, attrs.AESAttributes.KeySize)
	}

	// Check if key already exists
	if _, exists := b.metadata[attrs.CN]; exists {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyAlreadyExists, attrs.CN)
	}

	// Create the KMS key with SYMMETRIC_DEFAULT spec (AES-256-GCM)
	input := &kms.CreateKeyInput{
		KeySpec:  awstypes.KeySpecSymmetricDefault, // AES-256-GCM
		KeyUsage: awstypes.KeyUsageTypeEncryptDecrypt,
		Description: aws.String(fmt.Sprintf("Symmetric encryption key for %s (%s)",
			attrs.CN, attrs.KeyType)),
		Tags: []awstypes.Tag{
			{
				TagKey:   aws.String("CN"),
				TagValue: aws.String(attrs.CN),
			},
			{
				TagKey:   aws.String("KeyType"),
				TagValue: aws.String(string(attrs.KeyType)),
			},
			{
				TagKey:   aws.String("Algorithm"),
				TagValue: aws.String(string(attrs.SymmetricAlgorithm)),
			},
		},
	}

	output, err := b.client.CreateKey(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create symmetric key in AWS KMS: %w", err)
	}

	keyID := aws.ToString(output.KeyMetadata.KeyId)

	// Create an alias for easier reference
	aliasName := fmt.Sprintf("alias/%s", attrs.CN)
	if _, err := b.client.CreateAlias(ctx, &kms.CreateAliasInput{
		AliasName:   aws.String(aliasName),
		TargetKeyId: aws.String(keyID),
	}); err != nil {
		// Log warning but continue - alias is optional for key functionality
		// Alias might already exist or there may be permission issues
		fmt.Printf("warning: failed to create alias %s for key %s: %v\n", aliasName, keyID, err)
	}

	// Store metadata mapping CN -> KMS key information
	metadata := map[string]interface{}{
		"key_id":    keyID,
		"alias":     aliasName,
		"key_spec":  string(awstypes.KeySpecSymmetricDefault),
		"key_usage": string(awstypes.KeyUsageTypeEncryptDecrypt),
		"algorithm": string(attrs.SymmetricAlgorithm),
		"cn":        attrs.CN,
		"key_type":  string(attrs.KeyType),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	b.metadata[attrs.CN] = metadataBytes

	// Initialize AEAD tracking options for this key
	if b.tracker != nil {
		aeadOpts := attrs.AEADOptions
		if aeadOpts == nil {
			aeadOpts = types.DefaultAEADOptions()
		}
		trackingKeyID := attrs.ID()
		if err := b.tracker.SetAEADOptions(trackingKeyID, aeadOpts); err != nil {
			// Log warning but don't fail key generation
			fmt.Printf("warning: failed to set AEAD options for key %s: %v\n", trackingKeyID, err)
		}
	}

	// Return a reference key (actual key material stays in AWS KMS)
	return &awsKMSSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   256, // AWS KMS symmetric keys are always 256-bit
		keyID:     keyID,
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key by its attributes.
func (b *Backend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm: %s", backend.ErrInvalidKeyType, attrs.KeyAlgorithm)
	}

	// Check if metadata exists
	metadataBytes, exists := b.metadata[attrs.CN]
	if !exists {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	// Extract key ID from metadata
	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	keyID, ok := metadata["key_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid metadata: missing key_id")
	}

	// Verify key exists in KMS
	_, err := b.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to describe key: %v", backend.ErrKeyNotFound, err)
	}

	return &awsKMSSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   256, // AWS KMS symmetric keys are always 256-bit
		keyID:     keyID,
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the key identified by attrs.
func (b *Backend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm: %s", backend.ErrInvalidKeyType, attrs.KeyAlgorithm)
	}

	// Get the key ID
	keyID := b.getKeyID(attrs.CN)

	// Verify key exists
	b.mu.RLock()
	_, exists := b.metadata[attrs.CN]
	b.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	return &awsKMSSymmetricEncrypter{
		backend: b,
		keyID:   keyID,
		attrs:   attrs,
	}, nil
}

// Encrypt encrypts plaintext using AWS KMS Encrypt API.
// AWS KMS handles nonce generation and authentication automatically.
// Additional authenticated data (AAD) is supported via EncryptionContext.
//
// AEAD Safety Tracking:
//  1. Checks bytes limit before encryption (prevents exceeding NIST limits)
//  2. AWS KMS manages nonce generation internally (no client-side nonce tracking needed)
//  3. Performs encryption in AWS KMS
//
// Note: Nonce reuse tracking is not applicable since AWS KMS manages nonces server-side.
// Only bytes encrypted tracking is performed to enforce NIST cryptographic limits.
func (e *awsKMSSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	ctx := context.Background()
	if err := e.backend.initClient(ctx); err != nil {
		return nil, err
	}

	// Get key ID for tracking
	keyID := e.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if e.backend.tracker != nil {
		if err := e.backend.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w (consider rotating this key)", err)
		}
	}

	input := &kms.EncryptInput{
		KeyId:     aws.String(e.keyID),
		Plaintext: plaintext,
	}

	// AWS KMS supports additional authenticated data via EncryptionContext
	// EncryptionContext is a key-value map, so we encode AAD as a single entry
	if opts != nil && opts.AdditionalData != nil {
		// Convert AAD bytes to a string for EncryptionContext
		// Use a well-known key name
		input.EncryptionContext = map[string]string{
			"aad": string(opts.AdditionalData),
		}
	}

	output, err := e.backend.client.Encrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS encryption failed: %w", err)
	}

	// AWS KMS returns an opaque ciphertext blob that includes everything
	// (ciphertext, nonce, tag, algorithm info). We store it as-is.
	return &types.EncryptedData{
		Ciphertext: output.CiphertextBlob,
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
		// AWS KMS handles nonce and tag internally, no need to expose them
		Nonce: nil,
		Tag:   nil,
	}, nil
}

// Decrypt decrypts ciphertext using AWS KMS Decrypt API.
// AWS KMS automatically verifies authentication before decrypting.
// Additional authenticated data (AAD) must match what was provided during encryption.
func (e *awsKMSSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	ctx := context.Background()
	if err := e.backend.initClient(ctx); err != nil {
		return nil, err
	}

	input := &kms.DecryptInput{
		KeyId:          aws.String(e.keyID),
		CiphertextBlob: data.Ciphertext,
	}

	// If AAD was used during encryption, it must be provided during decryption
	if opts != nil && opts.AdditionalData != nil {
		input.EncryptionContext = map[string]string{
			"aad": string(opts.AdditionalData),
		}
	}

	output, err := e.backend.client.Decrypt(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS decryption failed (authentication or key error): %w", err)
	}

	return output.Plaintext, nil
}

// Verify interface compliance at compile time
var _ types.SymmetricBackend = (*Backend)(nil)
var _ types.SymmetricKey = (*awsKMSSymmetricKey)(nil)
var _ types.SymmetricEncrypter = (*awsKMSSymmetricEncrypter)(nil)
