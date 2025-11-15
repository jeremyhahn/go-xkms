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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Ensure Backend implements types.SymmetricBackend interface
var _ types.SymmetricBackend = (*Backend)(nil)

// GenerateSymmetricKey generates a new AES symmetric key and stores it as an Azure Key Vault secret.
// Azure Key Vault standard tier doesn't support oct (symmetric) keys through the Keys API,
// so we generate the key locally and store it securely as a secret.
func (b *Backend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if attrs == nil {
		return nil, fmt.Errorf("attributes cannot be nil")
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("invalid attributes: %w", err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("attributes specify asymmetric algorithm: %s", attrs.KeyAlgorithm)
	}

	ctx := context.Background()

	// Determine key size in bytes
	keySize := attrs.AESAttributes.KeySize
	if keySize == 0 {
		keySize = 256 // Default to 256 bits
	}

	// Validate key size
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, fmt.Errorf("invalid AES key size: %d (supported: 128, 192, or 256 bits)", keySize)
	}

	keySizeBytes := keySize / 8

	// Generate random AES key
	keyBytes := make([]byte, keySizeBytes)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Store the key as a secret in Azure Key Vault
	if err := b.storeSymmetricKeySecret(ctx, attrs.CN, keyBytes, attrs); err != nil {
		return nil, fmt.Errorf("failed to store symmetric key: %w", err)
	}

	// Store metadata in memory
	metadata := map[string]interface{}{
		"cn":        attrs.CN,
		"algorithm": string(attrs.SymmetricAlgorithm),
		"key_size":  keySize,
		"symmetric": true,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	b.mu.Lock()
	b.metadata[attrs.CN] = metadataBytes
	b.mu.Unlock()

	// Initialize AEAD tracking options for this key
	keyID := attrs.ID()
	if b.tracker != nil {
		if err := b.tracker.SetAEADOptions(keyID, types.DefaultAEADOptions()); err != nil {
			// Log but don't fail key generation
			fmt.Printf("Warning: failed to set AEAD options: %v\n", err)
		}
	}

	return &azureSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
		backend:   b,
		attrs:     attrs,
		keyData:   keyBytes,
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key from Azure Key Vault.
func (b *Backend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if attrs == nil {
		return nil, fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()

	// Check if metadata exists
	b.mu.RLock()
	metadataBytes, exists := b.metadata[attrs.CN]
	b.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	// Extract metadata
	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	keySizeFloat, _ := metadata["key_size"].(float64)
	keySize := int(keySizeFloat)

	// Retrieve the key from Azure Key Vault secrets
	keyBytes, err := b.retrieveSymmetricKeySecret(ctx, attrs.CN)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve symmetric key: %w", err)
	}

	return &azureSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize,
		backend:   b,
		attrs:     attrs,
		keyData:   keyBytes,
	}, nil
}

// SymmetricEncrypter returns an encrypter/decrypter for symmetric operations.
func (b *Backend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	if attrs == nil {
		return nil, fmt.Errorf("attributes cannot be nil")
	}

	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric key: %w", err)
	}

	return key.(*azureSymmetricKey), nil
}

// storeSymmetricKeySecret stores a symmetric key as an Azure Key Vault secret
func (b *Backend) storeSymmetricKeySecret(ctx context.Context, name string, keyData []byte, attrs *types.KeyAttributes) error {
	var secretsClient *azsecrets.Client
	var err error

	if b.config.ClientID != "" && b.config.ClientSecret != "" && b.config.TenantID != "" {
		// Use ClientSecretCredential for service principal authentication
		credOptions := &azidentity.ClientSecretCredentialOptions{
			AdditionallyAllowedTenants: []string{"*"},
		}
		cred, err := azidentity.NewClientSecretCredential(
			b.config.TenantID,
			b.config.ClientID,
			b.config.ClientSecret,
			credOptions,
		)
		if err != nil {
			return fmt.Errorf("failed to create client secret credential: %w", err)
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return fmt.Errorf("failed to create secrets client: %w", err)
		}
	} else {
		// Use DefaultAzureCredential for managed identity or other auth methods
		credOptions := &azidentity.DefaultAzureCredentialOptions{
			AdditionallyAllowedTenants: []string{"*"},
		}
		cred, err := azidentity.NewDefaultAzureCredential(credOptions)
		if err != nil {
			return fmt.Errorf("failed to create Azure credential: %w", err)
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return fmt.Errorf("failed to create secrets client: %w", err)
		}
	}

	// Encode key as base64
	encodedKey := base64.StdEncoding.EncodeToString(keyData)

	// Store as secret with metadata tags
	params := azsecrets.SetSecretParameters{
		Value: &encodedKey,
		SecretAttributes: &azsecrets.SecretAttributes{
			Enabled: ptrBool(true),
		},
		Tags: map[string]*string{
			"type":      ptrString("symmetric-key"),
			"algorithm": ptrString(string(attrs.SymmetricAlgorithm)),
			"keySize":   ptrString(fmt.Sprintf("%d", attrs.AESAttributes.KeySize)),
		},
	}

	_, err = secretsClient.SetSecret(ctx, name, params, nil)
	if err != nil {
		return fmt.Errorf("failed to set secret: %w", err)
	}

	return nil
}

// retrieveSymmetricKeySecret retrieves a symmetric key from Azure Key Vault secrets
func (b *Backend) retrieveSymmetricKeySecret(ctx context.Context, name string) ([]byte, error) {
	var secretsClient *azsecrets.Client
	var err error

	if b.config.ClientID != "" && b.config.ClientSecret != "" && b.config.TenantID != "" {
		// Use ClientSecretCredential for service principal authentication
		credOptions := &azidentity.ClientSecretCredentialOptions{
			AdditionallyAllowedTenants: []string{"*"},
		}
		cred, err := azidentity.NewClientSecretCredential(
			b.config.TenantID,
			b.config.ClientID,
			b.config.ClientSecret,
			credOptions,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create client secret credential: %w", err)
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create secrets client: %w", err)
		}
	} else {
		// Use DefaultAzureCredential for managed identity or other auth methods
		credOptions := &azidentity.DefaultAzureCredentialOptions{
			AdditionallyAllowedTenants: []string{"*"},
		}
		cred, err := azidentity.NewDefaultAzureCredential(credOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure credential: %w", err)
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create secrets client: %w", err)
		}
	}

	// Get the secret
	resp, err := secretsClient.GetSecret(ctx, name, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("secret value is nil")
	}

	// Decode base64
	keyData, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret: %w", err)
	}

	return keyData, nil
}

// azureSymmetricKey implements types.SymmetricKey and types.SymmetricEncrypter
type azureSymmetricKey struct {
	algorithm string
	keySize   int
	backend   *Backend
	attrs     *types.KeyAttributes
	keyData   []byte
}

// Algorithm returns the symmetric algorithm
func (k *azureSymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits
func (k *azureSymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns the raw key material. For Azure KV, we have it since we generate locally.
// However, it's sensitive data and should be protected.
func (k *azureSymmetricKey) Raw() ([]byte, error) {
	// Return a copy to prevent modification
	raw := make([]byte, len(k.keyData))
	copy(raw, k.keyData)
	return raw, nil
}

// Encrypt encrypts plaintext using AES-GCM
func (k *azureSymmetricKey) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	// Get key ID for tracking
	keyID := k.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if k.backend.tracker != nil {
		if err := k.backend.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w (consider rotating this key)", err)
		}
	}

	// Create AES cipher
	block, err := aes.NewCipher(k.keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// STEP 2: Generate or use provided nonce
	var nonce []byte
	if opts != nil && opts.Nonce != nil {
		nonce = opts.Nonce
		if len(nonce) != gcm.NonceSize() {
			return nil, fmt.Errorf("invalid nonce size: %d (expected %d)", len(nonce), gcm.NonceSize())
		}
	} else {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	}

	// STEP 3: Check nonce uniqueness before encryption
	if k.backend.tracker != nil {
		if err := k.backend.tracker.CheckNonce(keyID, nonce); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w (CRITICAL: rotate this key immediately)", err)
		}
	}

	// Get additional data if provided
	var aad []byte
	if opts != nil && opts.AdditionalData != nil {
		aad = opts.AdditionalData
	}

	// STEP 4: Encrypt (GCM appends the tag to the ciphertext)
	ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, aad)

	// GCM tag is the last 16 bytes
	tagSize := gcm.Overhead()
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
	tag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]

	// STEP 5: Record nonce after successful encryption
	if k.backend.tracker != nil {
		if err := k.backend.tracker.RecordNonce(keyID, nonce); err != nil {
			// Log warning but return successful encryption
			fmt.Printf("warning: failed to record nonce: %v\n", err)
		}
	}

	return &types.EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  k.algorithm,
	}, nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (k *azureSymmetricKey) Decrypt(encrypted *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if encrypted == nil {
		return nil, fmt.Errorf("encrypted data cannot be nil")
	}

	// Create AES cipher
	block, err := aes.NewCipher(k.keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Get additional data if provided
	var aad []byte
	if opts != nil && opts.AdditionalData != nil {
		aad = opts.AdditionalData
	}

	// Reconstruct ciphertext with tag
	ciphertextWithTag := append(encrypted.Ciphertext, encrypted.Tag...)

	// Decrypt
	plaintext, err := gcm.Open(nil, encrypted.Nonce, ciphertextWithTag, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Helper functions
func ptrBool(b bool) *bool {
	return &b
}

func ptrString(s string) *string {
	return &s
}
