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

//go:build vault

package vault

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"sync"

	vault "github.com/hashicorp/vault/api"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

const (
	BackendTypeVault types.BackendType = "vault"
)

// Backend implements the types.Backend interface for HashiCorp Vault Transit engine.
type Backend struct {
	config  *Config
	client  VaultClient
	tracker types.AEADSafetyTracker
	mu      sync.RWMutex
}

// vaultSigner implements crypto.Signer interface for Vault keys.
type vaultSigner struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
}

// vaultDecrypter implements crypto.Decrypter interface for Vault keys.
type vaultDecrypter struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
}

// NewBackend creates a new Vault backend instance.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Create Vault client configuration
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address

	if config.TLSSkipVerify {
		tlsConfig := &vault.TLSConfig{
			Insecure: true,
		}
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	// Create Vault client
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVaultConnection, err)
	}

	vaultClient.SetToken(config.Token)

	if config.Namespace != "" {
		vaultClient.SetNamespace(config.Namespace)
	}

	// Initialize tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	b := &Backend{
		config:  config,
		client:  newDefaultVaultClient(vaultClient),
		tracker: tracker,
	}

	return b, nil
}

// NewBackendWithClient creates a new Vault backend with a custom client (for testing).
func NewBackendWithClient(config *Config, client VaultClient) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Initialize tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	b := &Backend{
		config:  config,
		client:  client,
		tracker: tracker,
	}

	return b, nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return BackendTypeVault
}

// Capabilities returns the features this backend supports.
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false, // Vault is software-based, though it can use HSM for master keys
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,  // Vault Transit engine supports symmetric encryption
		Import:              false, // Key import not implemented in current version
		Export:              false, // Key export not implemented in current version
	}
}

// GenerateKey generates a new key in Vault's Transit engine.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, fmt.Errorf("%w: CN is required", backend.ErrInvalidAttributes)
	}

	ctx := context.Background()
	keyName := b.sanitizeKeyName(attrs.CN)

	// Determine Vault key type based on attributes
	vaultKeyType, err := b.getVaultKeyType(attrs)
	if err != nil {
		return nil, err
	}

	// Create key in Vault
	path := fmt.Sprintf("%s/keys/%s", b.config.TransitPath, keyName)
	data := map[string]interface{}{
		"type":                   vaultKeyType,
		"exportable":             true, // Allow exporting public key
		"allow_plaintext_backup": false,
		"deletion_allowed":       true, // Allow key deletion (required for cleanup)
	}

	logical := b.client.Logical()
	_, err = logical.WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to create key in vault: %w", err)
	}

	// Store metadata
	metadata := map[string]interface{}{
		"cn":            attrs.CN,
		"key_algorithm": int(attrs.KeyAlgorithm),
		"key_type":      uint8(attrs.KeyType),
		"hash":          uint(attrs.Hash),
		"store_type":    backend.STORE_VAULT,
		"vault_name":    keyName,
	}

	if attrs.RSAAttributes != nil {
		metadata["rsa_key_size"] = attrs.RSAAttributes.KeySize
	}
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		metadata["ecc_curve"] = attrs.ECCAttributes.Curve.Params().Name
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := storage.SaveKey(b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
		return nil, fmt.Errorf("failed to store metadata: %w", err)
	}

	// Get and return the public key
	return b.getPublicKey(ctx, keyName, attrs)
}

// GetKey retrieves an existing key from Vault.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, fmt.Errorf("%w: CN is required", backend.ErrInvalidAttributes)
	}

	// Load metadata to verify key exists
	_, err := storage.GetKey(b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	ctx := context.Background()
	keyName := b.sanitizeKeyName(attrs.CN)

	return b.getPublicKey(ctx, keyName, attrs)
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
func (b *Backend) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_VAULT,
	}
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: key %s does not implement crypto.Signer", backend.ErrInvalidKeyType, keyID)
	}
	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
func (b *Backend) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_VAULT,
	}
	key, err := b.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("%w: key %s does not implement crypto.Decrypter", backend.ErrInvalidKeyType, keyID)
	}
	return decrypter, nil
}

// DeleteKey removes a key from Vault and cleans up metadata.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	if attrs == nil || attrs.CN == "" {
		return fmt.Errorf("%w: CN is required", backend.ErrInvalidAttributes)
	}

	ctx := context.Background()
	keyName := b.sanitizeKeyName(attrs.CN)
	logical := b.client.Logical()

	// First, enable deletion for the key (Vault requires this for security)
	configPath := fmt.Sprintf("%s/keys/%s/config", b.config.TransitPath, keyName)
	configData := map[string]interface{}{
		"deletion_allowed": true,
	}
	_, err := logical.WriteWithContext(ctx, configPath, configData)
	if err != nil {
		// If config update fails, log but continue to try deletion anyway
		// (key might already have deletion enabled)
	}

	// Delete from Vault
	path := fmt.Sprintf("%s/keys/%s", b.config.TransitPath, keyName)
	_, err = logical.DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete key from vault: %w", err)
	}

	// Delete metadata
	if err := storage.DeleteKey(b.config.KeyStorage, attrs.CN); err != nil {
		return fmt.Errorf("failed to delete metadata: %w", err)
	}

	return nil
}

// ListKeys returns all keys managed by this backend.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	ctx := context.Background()
	path := fmt.Sprintf("%s/keys", b.config.TransitPath)

	logical := b.client.Logical()
	secret, err := logical.ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []*types.KeyAttributes{}, nil
	}

	keysInterface, ok := secret.Data["keys"]
	if !ok {
		return []*types.KeyAttributes{}, nil
	}

	keys, ok := keysInterface.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: unexpected keys format", ErrInvalidResponse)
	}

	var result []*types.KeyAttributes
	for _, keyInterface := range keys {
		keyName, ok := keyInterface.(string)
		if !ok {
			continue
		}

		// Convert Vault key name back to CN
		cn := b.desanitizeKeyName(keyName)

		// Load metadata
		metadataBytes, err := storage.GetKey(b.config.KeyStorage, cn)
		if err != nil {
			// If metadata doesn't exist, create basic attributes
			attrs := &types.KeyAttributes{
				CN: cn,
			}
			result = append(result, attrs)
			continue
		}

		var metadata map[string]interface{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			continue
		}

		attrs := &types.KeyAttributes{
			CN: cn,
		}

		if keyAlgFloat, ok := metadata["key_algorithm"].(float64); ok {
			attrs.KeyAlgorithm = x509.PublicKeyAlgorithm(int(keyAlgFloat))
		}
		if hashFloat, ok := metadata["hash"].(float64); ok {
			attrs.Hash = crypto.Hash(uint(hashFloat))
		}
		if keyTypeFloat, ok := metadata["key_type"].(float64); ok {
			attrs.KeyType = types.KeyType(uint8(keyTypeFloat))
		}

		result = append(result, attrs)
	}

	return result, nil
}

// Signer returns a crypto.Signer for the specified key.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, fmt.Errorf("%w: CN is required", backend.ErrInvalidAttributes)
	}

	// Verify key exists
	_, err := storage.GetKey(b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	ctx := context.Background()
	keyName := b.sanitizeKeyName(attrs.CN)

	publicKey, err := b.getPublicKey(ctx, keyName, attrs)
	if err != nil {
		return nil, err
	}

	return &vaultSigner{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the specified key.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, fmt.Errorf("%w: CN is required", backend.ErrInvalidAttributes)
	}

	// Verify key exists
	_, err := storage.GetKey(b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	ctx := context.Background()
	keyName := b.sanitizeKeyName(attrs.CN)

	publicKey, err := b.getPublicKey(ctx, keyName, attrs)
	if err != nil {
		return nil, err
	}

	return &vaultDecrypter{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
	}, nil
}

// Encrypt encrypts plaintext using the specified RSA key via Vault's Transit engine.
// This method is used to create Vault-format ciphertext that can be decrypted
// using the Decrypter interface.
func (b *Backend) Encrypt(attrs *types.KeyAttributes, plaintext []byte) ([]byte, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, fmt.Errorf("%w: CN is required", backend.ErrInvalidAttributes)
	}

	if attrs.KeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("%w: encrypt only supports RSA keys, got: %v", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}

	// Verify key exists
	_, err := storage.GetKey(b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	ctx := context.Background()
	keyName := b.sanitizeKeyName(attrs.CN)

	// Encode plaintext as base64
	input := base64.StdEncoding.EncodeToString(plaintext)

	path := fmt.Sprintf("%s/encrypt/%s", b.config.TransitPath, keyName)
	data := map[string]interface{}{
		"plaintext": input,
	}

	logical := b.client.Logical()
	secret, err := logical.WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt with vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: no ciphertext returned", ErrInvalidResponse)
	}

	ciphertextInterface, ok := secret.Data["ciphertext"]
	if !ok {
		return nil, fmt.Errorf("%w: no ciphertext in response", ErrInvalidResponse)
	}

	ciphertextStr, ok := ciphertextInterface.(string)
	if !ok {
		return nil, fmt.Errorf("%w: invalid ciphertext format", ErrInvalidResponse)
	}

	// Vault returns ciphertext in "vault:v1:base64..." format
	// The Decrypter.Decrypt() expects just the base64 portion
	// So we need to extract and decode it
	parts := strings.Split(ciphertextStr, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("%w: invalid ciphertext format", ErrInvalidResponse)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	return ciphertext, nil
}

// RotateKey creates a new version of the key in Vault.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	if attrs == nil || attrs.CN == "" {
		return fmt.Errorf("%w: CN is required", backend.ErrInvalidAttributes)
	}

	ctx := context.Background()
	keyName := b.sanitizeKeyName(attrs.CN)

	// Rotate key in Vault
	path := fmt.Sprintf("%s/keys/%s/rotate", b.config.TransitPath, keyName)
	logical := b.client.Logical()
	_, err := logical.WriteWithContext(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to rotate key in vault: %w", err)
	}

	return nil
}

// Close releases resources held by the backend.
func (b *Backend) Close() error {
	// Vault client doesn't require explicit cleanup
	return nil
}

// Helper methods

func (b *Backend) sanitizeKeyName(cn string) string {
	// Vault key names must be lowercase and use hyphens instead of special characters
	name := strings.ToLower(cn)
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

func (b *Backend) desanitizeKeyName(keyName string) string {
	// For now, just return as-is since we can't perfectly reverse the sanitization
	// This is acceptable because we store the original CN in metadata
	return keyName
}

func (b *Backend) getVaultKeyType(attrs *types.KeyAttributes) (string, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		size := 2048
		if attrs.RSAAttributes != nil {
			size = attrs.RSAAttributes.KeySize
		}
		switch size {
		case 2048:
			return "rsa-2048", nil
		case 3072:
			return "rsa-3072", nil
		case 4096:
			return "rsa-4096", nil
		default:
			return "", fmt.Errorf("%w: unsupported RSA key size: %d", backend.ErrInvalidAlgorithm, size)
		}
	case x509.ECDSA:
		if attrs.ECCAttributes == nil || attrs.ECCAttributes.Curve == nil {
			return "ecdsa-p256", nil
		}
		curve := attrs.ECCAttributes.Curve
		switch curve.Params().Name {
		case "P-256":
			return "ecdsa-p256", nil
		case "P-384":
			return "ecdsa-p384", nil
		case "P-521":
			return "ecdsa-p521", nil
		default:
			return "", fmt.Errorf("%w: unsupported curve: %s", backend.ErrInvalidAlgorithm, curve.Params().Name)
		}
	case x509.Ed25519:
		return "ed25519", nil
	default:
		return "", fmt.Errorf("%w: %v", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}
}

func (b *Backend) getPublicKey(ctx context.Context, keyName string, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	path := fmt.Sprintf("%s/keys/%s", b.config.TransitPath, keyName)
	logical := b.client.Logical()
	secret, err := logical.ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key from vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, keyName)
	}

	// Get the latest key version
	keysInterface, ok := secret.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("%w: no keys data", ErrInvalidResponse)
	}

	keysMap, ok := keysInterface.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: invalid keys format", ErrInvalidResponse)
	}

	// Get latest version
	latestVersionInterface, ok := secret.Data["latest_version"]
	if !ok {
		return nil, fmt.Errorf("%w: no latest_version", ErrInvalidResponse)
	}

	latestVersion := fmt.Sprintf("%v", latestVersionInterface)
	keyDataInterface, ok := keysMap[latestVersion]
	if !ok {
		return nil, fmt.Errorf("%w: version %s not found", ErrInvalidResponse, latestVersion)
	}

	keyData, ok := keyDataInterface.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: invalid key data format", ErrInvalidResponse)
	}

	// Get public key in PEM format
	publicKeyPEMInterface, ok := keyData["public_key"]
	if !ok {
		return nil, fmt.Errorf("%w: no public key in response", ErrInvalidResponse)
	}

	publicKeyPEM, ok := publicKeyPEMInterface.(string)
	if !ok {
		return nil, fmt.Errorf("%w: invalid public key format", ErrInvalidResponse)
	}

	// Check if this is Ed25519 (Vault returns base64, not PEM for Ed25519)
	keyTypeInterface, ok := secret.Data["type"]
	if ok {
		if keyType, ok := keyTypeInterface.(string); ok && keyType == "ed25519" {
			// Ed25519 public key is returned as base64, not PEM
			pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyPEM)
			if err != nil {
				return nil, fmt.Errorf("failed to decode ed25519 public key: %w", err)
			}
			if len(pubKeyBytes) != 32 {
				return nil, fmt.Errorf("invalid ed25519 public key length: %d", len(pubKeyBytes))
			}
			return ed25519.PublicKey(pubKeyBytes), nil
		}
	}

	// Parse PEM for RSA and ECDSA keys
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM", ErrInvalidResponse)
	}

	// Parse public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}

func (b *Backend) getHashAlgorithm(attrs *types.KeyAttributes) (string, crypto.Hash, error) {
	hash := attrs.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}

	var vaultHash string

	switch hash {
	case crypto.SHA256:
		vaultHash = "sha2-256"
	case crypto.SHA384:
		vaultHash = "sha2-384"
	case crypto.SHA512:
		vaultHash = "sha2-512"
	default:
		return "", 0, fmt.Errorf("%w: unsupported hash: %v", backend.ErrInvalidAlgorithm, hash)
	}

	return vaultHash, hash, nil
}

// vaultSigner implementation

func (s *vaultSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *vaultSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()
	keyName := s.backend.sanitizeKeyName(s.attrs.CN)

	var path string
	var data map[string]interface{}

	// Ed25519 requires pure signatures (no prehashing)
	if s.attrs.KeyAlgorithm == x509.Ed25519 {
		// For Ed25519, pass raw message without hash algorithm
		input := base64.StdEncoding.EncodeToString(digest)
		path = fmt.Sprintf("%s/sign/%s", s.backend.config.TransitPath, keyName)
		data = map[string]interface{}{
			"input":     input,
			"prehashed": false,
		}
	} else {
		// For RSA and ECDSA, use prehashed digest
		vaultHash, _, err := s.backend.getHashAlgorithm(s.attrs)
		if err != nil {
			return nil, err
		}

		input := base64.StdEncoding.EncodeToString(digest)
		path = fmt.Sprintf("%s/sign/%s/%s", s.backend.config.TransitPath, keyName, vaultHash)
		data = map[string]interface{}{
			"input":               input,
			"prehashed":           true,
			"signature_algorithm": s.getSignatureAlgorithm(opts),
		}
	}

	logical := s.backend.client.Logical()
	secret, err := logical.WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: no signature returned", ErrInvalidResponse)
	}

	signatureInterface, ok := secret.Data["signature"]
	if !ok {
		return nil, fmt.Errorf("%w: no signature in response", ErrInvalidResponse)
	}

	signatureStr, ok := signatureInterface.(string)
	if !ok {
		return nil, fmt.Errorf("%w: invalid signature format", ErrInvalidResponse)
	}

	// Vault signatures are in format "vault:v1:base64..."
	// Extract the base64 portion
	parts := strings.Split(signatureStr, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("%w: invalid signature format", ErrInvalidResponse)
	}

	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return signature, nil
}

func (s *vaultSigner) getSignatureAlgorithm(opts crypto.SignerOpts) string {
	switch s.attrs.KeyAlgorithm {
	case x509.RSA:
		// Check if PSS options were provided
		if _, ok := opts.(*rsa.PSSOptions); ok {
			return "pss"
		}
		return "pkcs1v15"
	default:
		return ""
	}
}

// vaultDecrypter implementation

func (d *vaultDecrypter) Public() crypto.PublicKey {
	return d.publicKey
}

func (d *vaultDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	ctx := context.Background()
	keyName := d.backend.sanitizeKeyName(d.attrs.CN)

	// Encode ciphertext as base64 and add Vault prefix
	// Vault expects ciphertext in "vault:v1:base64..." format
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
	input := fmt.Sprintf("vault:v1:%s", encodedCiphertext)

	path := fmt.Sprintf("%s/decrypt/%s", d.backend.config.TransitPath, keyName)
	data := map[string]interface{}{
		"ciphertext": input,
	}

	logical := d.backend.client.Logical()
	secret, err := logical.WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: no plaintext returned", ErrInvalidResponse)
	}

	plaintextInterface, ok := secret.Data["plaintext"]
	if !ok {
		return nil, fmt.Errorf("%w: no plaintext in response", ErrInvalidResponse)
	}

	plaintextStr, ok := plaintextInterface.(string)
	if !ok {
		return nil, fmt.Errorf("%w: invalid plaintext format", ErrInvalidResponse)
	}

	plaintext, err := base64.StdEncoding.DecodeString(plaintextStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}
