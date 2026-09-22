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
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Ensure Backend implements types.SymmetricKeyProvider interface
var _ types.SymmetricKeyProvider = (*Backend)(nil)

// GenerateSymmetricKey generates a new AES symmetric key and stores it as an Azure Key Vault secret.
// Azure Key Vault standard tier doesn't support oct (symmetric) keys through the Keys API,
// so we generate the key locally and store it securely as a secret.
func (b *Backend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if attrs == nil {
		return nil, &errs.Message{Msg: "attributes cannot be nil"}
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "invalid attributes", Err: err}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Message{Msg: fmt.Sprintf("attributes specify asymmetric algorithm: %s", attrs.KeyAlgorithm)}
	}

	// Determine key size in bytes
	keySize := attrs.SymmetricAlgorithm.KeySize()
	if keySize == 0 {
		keySize = 256 // Default to 256 bits
	}

	// Validate key size
	if keySize != 128 && keySize != 192 && keySize != 256 {
		return nil, &errs.Message{Msg: fmt.Sprintf("invalid AES key size: %d (supported: 128, 192, or 256 bits)", keySize)}
	}

	keySizeBytes := keySize / 8

	// Generate random AES key
	keyBytes := make([]byte, keySizeBytes)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate random key", Err: err}
	}

	// Store the key as a secret in Azure Key Vault
	if err := b.storeSymmetricKeySecret(ctx, attrs.CN, keyBytes, attrs); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store symmetric key", Err: err}
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
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	b.mu.Lock()
	b.metadata[attrs.CN] = metadataBytes
	b.mu.Unlock()

	// Initialize AEAD tracking options for this key
	keyID := attrs.ID()
	if b.tracker != nil {
		// The caller's policy wins; the default only applies when none was
		// given. Discarding it would silently downgrade a conservative nonce
		// or bytes limit to the default.
		aeadOpts := attrs.AEADOptions
		if aeadOpts == nil {
			aeadOpts = types.DefaultAEADOptions()
		}
		if err := b.tracker.SetAEADOptions(keyID, aeadOpts); err != nil {
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
func (b *Backend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if attrs == nil {
		return nil, &errs.Message{Msg: "attributes cannot be nil"}
	}

	// Check if metadata exists
	b.mu.RLock()
	metadataBytes, exists := b.metadata[attrs.CN]
	b.mu.RUnlock()

	if !exists {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	// Extract metadata
	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unmarshal metadata", Err: err}
	}

	keySizeFloat, _ := metadata["key_size"].(float64)
	keySize := int(keySizeFloat)

	// Retrieve the key from Azure Key Vault secrets
	keyBytes, err := b.retrieveSymmetricKeySecret(ctx, attrs.CN)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to retrieve symmetric key", Err: err}
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
func (b *Backend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	if attrs == nil {
		return nil, &errs.Message{Msg: "attributes cannot be nil"}
	}

	key, err := b.GetSymmetricKey(ctx, attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get symmetric key", Err: err}
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
			return &errs.Wrapped{Msg: "failed to create client secret credential", Err: err}
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create secrets client", Err: err}
		}
	} else {
		// Use DefaultAzureCredential for managed identity or other auth methods
		credOptions := &azidentity.DefaultAzureCredentialOptions{
			AdditionallyAllowedTenants: []string{"*"},
		}
		cred, err := azidentity.NewDefaultAzureCredential(credOptions)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create Azure credential", Err: err}
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create secrets client", Err: err}
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
			"keySize":   ptrString(fmt.Sprintf("%d", attrs.SymmetricAlgorithm.KeySize())),
		},
	}

	_, err = secretsClient.SetSecret(ctx, name, params, nil)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to set secret", Err: err}
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
			return nil, &errs.Wrapped{Msg: "failed to create client secret credential", Err: err}
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to create secrets client", Err: err}
		}
	} else {
		// Use DefaultAzureCredential for managed identity or other auth methods
		credOptions := &azidentity.DefaultAzureCredentialOptions{
			AdditionallyAllowedTenants: []string{"*"},
		}
		cred, err := azidentity.NewDefaultAzureCredential(credOptions)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to create Azure credential", Err: err}
		}

		secretsClient, err = azsecrets.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to create secrets client", Err: err}
		}
	}

	// Get the secret
	resp, err := secretsClient.GetSecret(ctx, name, "", nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get secret", Err: err}
	}

	if resp.Value == nil {
		return nil, &errs.Message{Msg: "secret value is nil"}
	}

	// Decode base64
	keyData, err := base64.StdEncoding.DecodeString(*resp.Value)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode secret", Err: err}
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
	if opts == nil {
		opts = &types.EncryptOptions{}
	}

	// Get key ID for tracking
	keyID := k.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if k.backend.tracker != nil {
		if err := k.backend.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (consider rotating this key)"}
		}
	}

	// Create AES cipher
	block, err := aes.NewCipher(k.keyData)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// Create GCM mode. The tag length comes from the request, not from a
	// fixed constant: NIST SP 800-38D section 5.2.1.2 defines a t-bit tag as
	// the leading t bits of the full tag, and a caller that asked for one and
	// got 128 bits back has a ciphertext its peer cannot authenticate.
	//
	// Under GODEBUG=fips140=only, Go refuses every AES-GCM construction that
	// accepts a caller- or process-supplied IV, so when opts.Nonce is unset
	// this substitutes cipher.NewGCMWithRandomNonce (randomNonce true) and
	// reports it via GCMNonceMode so Decrypt reconstructs the same
	// construction later. See pkg/crypto/aead.NewGCMForFreshEncrypt.
	gcm, randomNonce, err := aead.NewGCMForFreshEncrypt(block, opts.TagSize, opts.Nonce != nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Get additional data if provided
	aad := opts.AdditionalData

	var nonce, ciphertext, tag []byte

	if randomNonce {
		// gcm's NonceSize is 0: it generates the nonce itself and prepends
		// it to Seal's output, so Seal is called with a nil nonce argument
		// and the nonce is not known until this returns.
		sealed := gcm.Seal(nil, nil, plaintext, aad)
		nonce, ciphertext, tag, err = aead.SplitGCMWithRandomNonce(sealed)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to split random-nonce GCM output", Err: err}
		}

		// STEP 3: Check nonce uniqueness. Unlike the explicit-nonce path,
		// the nonce cannot be checked before Seal produces it.
		if k.backend.tracker != nil {
			if err := k.backend.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (CRITICAL: rotate this key immediately)"}
			}
		}
	} else {
		// STEP 2: Generate or use provided nonce
		if opts.Nonce != nil {
			nonce = opts.Nonce
			if len(nonce) != gcm.NonceSize() {
				return nil, &errs.Message{Msg: fmt.Sprintf("invalid nonce size: %d (expected %d)", len(nonce), gcm.NonceSize())}
			}
		} else {
			nonce = make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return nil, &errs.Wrapped{Msg: "failed to generate nonce", Err: err}
			}
		}

		// STEP 3: Check nonce uniqueness before encryption
		if k.backend.tracker != nil {
			if err := k.backend.tracker.CheckNonce(keyID, nonce); err != nil {
				return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (CRITICAL: rotate this key immediately)"}
			}
		}

		// STEP 4: Encrypt (GCM appends the tag to the ciphertext)
		ciphertextWithTag := gcm.Seal(nil, nonce, plaintext, aad)

		// The tag is the trailing gcm.Overhead() bytes, which is the
		// requested length rather than a fixed 16.
		tagSize := gcm.Overhead()
		ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
		tag = ciphertextWithTag[len(ciphertextWithTag)-tagSize:]
	}

	// STEP 5: Record nonce after successful encryption
	if k.backend.tracker != nil {
		if err := k.backend.tracker.RecordNonce(keyID, nonce); err != nil {
			// Log warning but return successful encryption
			fmt.Printf("warning: failed to record nonce: %v\n", err)
		}
	}

	nonceMode := types.GCMNonceModeExplicit
	if randomNonce {
		nonceMode = types.GCMNonceModeRandom
	}

	return &types.EncryptedData{
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		Tag:          tag,
		Algorithm:    k.algorithm,
		GCMNonceMode: nonceMode,
	}, nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (k *azureSymmetricKey) Decrypt(encrypted *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if encrypted == nil {
		return nil, &errs.Message{Msg: "encrypted data cannot be nil"}
	}
	if opts == nil {
		opts = &types.DecryptOptions{}
	}

	// Create AES cipher
	block, err := aes.NewCipher(k.keyData)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create cipher", Err: err}
	}

	// The tag length is taken from the request, never inferred from the tag
	// that arrived: SP 800-38D section 5.2.2 verifies a t-bit tag by
	// recomputing it at t bits, and letting the ciphertext bundle choose t
	// would let an attacker pick how many bits get checked.
	//
	// The construction is selected by encrypted.GCMNonceMode, not by the
	// current process's FIPS posture, so a random-nonce ciphertext a
	// fips140=only process wrote still opens under fips140=on (and a
	// classic explicit-nonce ciphertext still opens on any process that can
	// construct arbitrary-IV GCM). See pkg/crypto/aead.NewGCMForDecrypt.
	randomNonce := encrypted.GCMNonceMode == types.GCMNonceModeRandom
	gcm, err := aead.NewGCMForDecrypt(block, opts.TagSize, randomNonce)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create GCM", Err: err}
	}

	// Get additional data if provided
	aad := opts.AdditionalData

	if randomNonce {
		// gcm is cipher.NewGCMWithRandomNonce: NonceSize is 0 and Overhead
		// is nonce+tag combined, so the wire-carried fields are checked
		// against the fixed random-nonce framing rather than against gcm's
		// own (zero) NonceSize.
		if len(encrypted.Tag) != aead.GCMFullTagSize {
			return nil, &errs.Message{Msg: fmt.Sprintf(
				"azurekv: authentication tag is %d bytes, want %d", len(encrypted.Tag), aead.GCMFullTagSize)}
		}
		if len(encrypted.Nonce) != aead.GCMRandomNonceSize {
			return nil, &errs.Message{Msg: fmt.Sprintf(
				"azurekv: nonce is %d bytes, want %d", len(encrypted.Nonce), aead.GCMRandomNonceSize)}
		}

		joined := aead.JoinGCMWithRandomNonce(encrypted.Nonce, encrypted.Ciphertext, encrypted.Tag)
		plaintext, err := gcm.Open(nil, nil, joined, aad)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "decryption failed", Err: err}
		}
		return plaintext, nil
	}

	if len(encrypted.Tag) != gcm.Overhead() {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"azurekv: authentication tag is %d bytes, want %d", len(encrypted.Tag), gcm.Overhead())}
	}

	// crypto/cipher panics rather than returning an error when the nonce is
	// not exactly NonceSize bytes. The nonce arrives from the caller, so
	// without this check any request carrying a short nonce takes the whole
	// daemon down.
	if len(encrypted.Nonce) != gcm.NonceSize() {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"azurekv: nonce is %d bytes, want %d", len(encrypted.Nonce), gcm.NonceSize())}
	}

	// Reconstruct ciphertext with tag
	ciphertextWithTag := append(encrypted.Ciphertext, encrypted.Tag...)

	// Decrypt
	plaintext, err := gcm.Open(nil, encrypted.Nonce, ciphertextWithTag, aad)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "decryption failed", Err: err}
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

// GetTracker returns the AEAD safety tracker for this backend.
// This allows external code to inspect tracking state and configuration.
func (b *Backend) GetTracker() types.AEADSafetyTracker {
	return b.tracker
}

// Verify interface compliance at compile time
var _ types.SymmetricKeyProviderWithTracking = (*Backend)(nil)
