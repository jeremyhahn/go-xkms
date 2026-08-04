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
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	vault "github.com/hashicorp/vault/api"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	BackendTypeVault types.BackendType = "vault"
)

// Backend implements the types.KeyProvider interface for HashiCorp Vault Transit engine.
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
		return nil, &errs.Wrapped{Msg: "config validation failed", Err: err}
	}

	// Create Vault client configuration
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address

	if config.TLSSkipVerify {
		slog.Warn("vault: TLS certificate verification disabled via TLSSkipVerify; do not use in production",
			"address", config.Address)
		tlsConfig := &vault.TLSConfig{
			Insecure: true,
		}
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to configure TLS", Err: err}
		}
	}

	// Create Vault client
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, &errs.Detail{Err: ErrVaultConnection, Detail: fmt.Sprintf("%v", err)}
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
		return nil, &errs.Wrapped{Msg: "config validation failed", Err: err}
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
// SecurityLevel is Medium - keys are protected by Vault's Transit engine.
// Note: While Vault is software-based by default, it can use HSM for master keys.
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
		SecurityLevel:       types.SecurityLevelMedium,
	}
}

// GenerateKey generates a new key in Vault's Transit engine.
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

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
		return nil, &errs.Wrapped{Msg: "failed to create key in vault", Err: err}
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
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
		return nil, &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	// Get and return the public key
	return b.getPublicKey(ctx, keyName, attrs)
}

// GetKey retrieves an existing key from Vault.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	// Load metadata to verify key exists
	_, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	keyName := b.sanitizeKeyName(attrs.CN)

	return b.getPublicKey(ctx, keyName, attrs)
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
func (b *Backend) GetSignerByID(ctx context.Context, keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_VAULT,
	}
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key %s does not implement crypto.Signer", keyID)}
	}
	return signer, nil
}

// GetDecrypterByID retrieves a crypto.Decrypter for the specified key by name.
func (b *Backend) GetDecrypterByID(ctx context.Context, keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_VAULT,
	}
	key, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key %s does not implement crypto.Decrypter", keyID)}
	}
	return decrypter, nil
}

// DeleteKey removes a key from Vault and cleans up metadata.
func (b *Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil || attrs.CN == "" {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

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
		return &errs.Wrapped{Msg: "failed to delete key from vault", Err: err}
	}

	// Delete metadata
	if err := storage.DeleteKey(ctx, b.config.KeyStorage, attrs.CN); err != nil {
		return &errs.Wrapped{Msg: "failed to delete metadata", Err: err}
	}

	return nil
}

// ListKeys returns all keys managed by this backend.
func (b *Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	path := fmt.Sprintf("%s/keys", b.config.TransitPath)

	logical := b.client.Logical()
	secret, err := logical.ListWithContext(ctx, path)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list keys from vault", Err: err}
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
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "unexpected keys format"}
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
		metadataBytes, err := storage.GetKey(ctx, b.config.KeyStorage, cn)
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
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	// Verify key exists
	_, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

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
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	// Verify key exists
	_, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

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
func (b *Backend) Encrypt(ctx context.Context, attrs *types.KeyAttributes, plaintext []byte) ([]byte, error) {
	if attrs == nil || attrs.CN == "" {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	if attrs.KeyAlgorithm != x509.RSA {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("encrypt only supports RSA keys, got: %v", attrs.KeyAlgorithm)}
	}

	// Verify key exists
	_, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

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
		return nil, &errs.Wrapped{Msg: "failed to encrypt with vault", Err: err}
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

	// Vault returns ciphertext in "vault:v1:base64..." format
	// The Decrypter.Decrypt() expects just the base64 portion
	// So we need to extract and decode it
	parts := strings.Split(ciphertextStr, ":")
	if len(parts) < 3 {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid ciphertext format"}
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode ciphertext", Err: err}
	}

	return ciphertext, nil
}

// RotateKey creates a new version of the key in Vault.
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil || attrs.CN == "" {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "CN is required"}
	}

	keyName := b.sanitizeKeyName(attrs.CN)

	// Rotate key in Vault
	path := fmt.Sprintf("%s/keys/%s/rotate", b.config.TransitPath, keyName)
	logical := b.client.Logical()
	_, err := logical.WriteWithContext(ctx, path, nil)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to rotate key in vault", Err: err}
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
			return "", &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported RSA key size: %d", size)}
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
			return "", &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported curve: %s", curve.Params().Name)}
		}
	case x509.Ed25519:
		return "ed25519", nil
	default:
		return "", &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("%v", attrs.KeyAlgorithm)}
	}
}

func (b *Backend) getPublicKey(ctx context.Context, keyName string, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	path := fmt.Sprintf("%s/keys/%s", b.config.TransitPath, keyName)
	logical := b.client.Logical()
	secret, err := logical.ReadWithContext(ctx, path)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to read key from vault", Err: err}
	}

	if secret == nil || secret.Data == nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", keyName)}
	}

	// Get the latest key version
	keysInterface, ok := secret.Data["keys"]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no keys data"}
	}

	keysMap, ok := keysInterface.(map[string]interface{})
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid keys format"}
	}

	// Get latest version
	latestVersionInterface, ok := secret.Data["latest_version"]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no latest_version"}
	}

	latestVersion := fmt.Sprintf("%v", latestVersionInterface)
	keyDataInterface, ok := keysMap[latestVersion]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: fmt.Sprintf("version %s not found", latestVersion)}
	}

	keyData, ok := keyDataInterface.(map[string]interface{})
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid key data format"}
	}

	// Get public key in PEM format
	publicKeyPEMInterface, ok := keyData["public_key"]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no public key in response"}
	}

	publicKeyPEM, ok := publicKeyPEMInterface.(string)
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid public key format"}
	}

	// Check if this is Ed25519 (Vault returns base64, not PEM for Ed25519)
	keyTypeInterface, ok := secret.Data["type"]
	if ok {
		if keyType, ok := keyTypeInterface.(string); ok && keyType == "ed25519" {
			// Ed25519 public key is returned as base64, not PEM
			pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyPEM)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode ed25519 public key", Err: err}
			}
			if len(pubKeyBytes) != 32 {
				return nil, &errs.Message{Msg: fmt.Sprintf("invalid ed25519 public key length: %d", len(pubKeyBytes))}
			}
			return ed25519.PublicKey(pubKeyBytes), nil
		}
	}

	// Parse PEM for RSA and ECDSA keys
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "failed to decode PEM"}
	}

	// Parse public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
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
		return "", 0, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported hash: %v", hash)}
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
		return nil, &errs.Wrapped{Msg: "failed to sign with vault", Err: err}
	}

	if secret == nil || secret.Data == nil {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no signature returned"}
	}

	signatureInterface, ok := secret.Data["signature"]
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "no signature in response"}
	}

	signatureStr, ok := signatureInterface.(string)
	if !ok {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid signature format"}
	}

	// Vault signatures are in format "vault:v1:base64..."
	// Extract the base64 portion
	parts := strings.Split(signatureStr, ":")
	if len(parts) < 3 {
		return nil, &errs.Detail{Err: ErrInvalidResponse, Detail: "invalid signature format"}
	}

	signature, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode signature", Err: err}
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
		return nil, &errs.Wrapped{Msg: "failed to decrypt with vault", Err: err}
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

	plaintext, err := base64.StdEncoding.DecodeString(plaintextStr)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to decode plaintext", Err: err}
	}

	return plaintext, nil
}
