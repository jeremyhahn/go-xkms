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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// KeyVaultClient defines the interface for Azure Key Vault operations.
// This interface allows for mocking in tests.
type KeyVaultClient interface {
	CreateKey(ctx context.Context, name string, params azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
	GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error)
	Sign(ctx context.Context, keyName, keyVersion string, params azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
	Verify(ctx context.Context, keyName, keyVersion string, params azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error)
	Decrypt(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
	WrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
	ImportKey(ctx context.Context, name string, params azkeys.ImportKeyParameters, options *azkeys.ImportKeyOptions) (azkeys.ImportKeyResponse, error)
	GetPublicKey(ctx context.Context, name, version string) ([]byte, error)
	NewListKeyPropertiesPager(options *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse]
	RotateKey(ctx context.Context, name string, options *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error)
	Close() error
}

// realKeyVaultClient wraps the actual Azure Key Vault client to implement our interface.
type realKeyVaultClient struct {
	*azkeys.Client
}

func (r *realKeyVaultClient) CreateKey(ctx context.Context, name string, params azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	return r.Client.CreateKey(ctx, name, params, options)
}

func (r *realKeyVaultClient) GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return r.Client.GetKey(ctx, name, version, options)
}

func (r *realKeyVaultClient) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	return r.Client.DeleteKey(ctx, name, options)
}

func (r *realKeyVaultClient) Sign(ctx context.Context, keyName, keyVersion string, params azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return r.Client.Sign(ctx, keyName, keyVersion, params, options)
}

func (r *realKeyVaultClient) Verify(ctx context.Context, keyName, keyVersion string, params azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
	return r.Client.Verify(ctx, keyName, keyVersion, params, options)
}

func (r *realKeyVaultClient) Decrypt(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	return r.Client.Decrypt(ctx, keyName, keyVersion, params, options)
}

func (r *realKeyVaultClient) WrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	return r.Client.WrapKey(ctx, keyName, keyVersion, params, options)
}

func (r *realKeyVaultClient) UnwrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	return r.Client.UnwrapKey(ctx, keyName, keyVersion, params, options)
}

func (r *realKeyVaultClient) ImportKey(ctx context.Context, name string, params azkeys.ImportKeyParameters, options *azkeys.ImportKeyOptions) (azkeys.ImportKeyResponse, error) {
	return r.Client.ImportKey(ctx, name, params, options)
}

func (r *realKeyVaultClient) GetPublicKey(ctx context.Context, name, version string) ([]byte, error) {
	// Get the key first
	resp, err := r.Client.GetKey(ctx, name, version, nil)
	if err != nil {
		return nil, err
	}

	// Extract and encode public key
	if resp.Key == nil {
		return nil, fmt.Errorf("no key in response")
	}

	// Convert JWK to crypto.PublicKey
	pubKey, err := jwkToPublicKey(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWK to public key: %w", err)
	}

	// Marshal to PKIX format
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return derBytes, nil
}

func (r *realKeyVaultClient) NewListKeyPropertiesPager(options *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse] {
	return r.Client.NewListKeyPropertiesPager(options)
}

func (r *realKeyVaultClient) RotateKey(ctx context.Context, name string, options *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error) {
	return r.Client.RotateKey(ctx, name, options)
}

func (r *realKeyVaultClient) Close() error {
	// Azure SDK client doesn't require explicit closing
	return nil
}

// Backend implements the types.Backend interface for Azure Key Vault.
// It provides secure key management operations using Azure Key Vault.
type Backend struct {
	config   *Config
	client   KeyVaultClient
	metadata map[string][]byte // In-memory metadata storage keyed by CN
	tracker  types.AEADSafetyTracker
	mu       sync.RWMutex
}

// NewBackend creates a new Azure Key Vault backend instance.
// It initializes the Azure Key Vault client with the provided configuration.
func NewBackend(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Create default tracker if none provided
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	b := &Backend{
		config:   config,
		metadata: make(map[string][]byte),
		tracker:  tracker,
	}

	return b, nil
}

// NewBackendWithClient creates a new Azure Key Vault backend with a custom client.
// This is primarily used for testing with mock clients.
func NewBackendWithClient(config *Config, client KeyVaultClient) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Create default tracker if none provided
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	b := &Backend{
		config:   config,
		client:   client,
		metadata: make(map[string][]byte),
		tracker:  tracker,
	}

	return b, nil
}

// initClient initializes the Azure Key Vault client if not already initialized.
func (b *Backend) initClient(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client != nil {
		return nil
	}

	var client *azkeys.Client

	if b.config.ClientID != "" && b.config.ClientSecret != "" && b.config.TenantID != "" {
		// Use ClientSecretCredential for service principal authentication
		// with additional allowed tenants
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

		// Create Azure Key Vault client with ClientSecretCredential
		client, err = azkeys.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return fmt.Errorf("failed to create Azure Key Vault client: %w", err)
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

		// Create Azure Key Vault client
		client, err = azkeys.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return fmt.Errorf("failed to create Azure Key Vault client: %w", err)
		}
	}

	b.client = &realKeyVaultClient{Client: client}

	return nil
}

// Capabilities returns the capabilities of this backend.
// Azure Key Vault is a cloud-based HSM service with hardware-backed security.
// Symmetric encryption is supported by storing AES keys as secrets (not oct key type).
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true // Supported via Secrets API
	caps.Import = true              // Supported via ImportKey API
	caps.Export = false             // Azure KV does not allow key extraction for security
	return caps
}

// Get retrieves data for a key with the specified attributes and extension.
// For Azure Key Vault, this retrieves the public key or metadata associated with the key.
func (b *Backend) Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error) {
	if attrs == nil {
		return nil, fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// For metadata/blob extensions, return stored metadata
	if extension == backend.FSEXT_PRIVATE_BLOB || extension == backend.FSEXT_PUBLIC_BLOB {
		data, ok := b.metadata[attrs.CN]
		if !ok {
			return nil, fmt.Errorf("%w: %s", backend.ErrFileNotFound, attrs.CN)
		}
		return data, nil
	}

	// For public key extensions, retrieve from Azure Key Vault
	if extension == backend.FSEXT_PUBLIC_PKCS1 || extension == backend.FSEXT_PUBLIC_PEM {
		pubKey, err := b.client.GetPublicKey(ctx, attrs.CN, "")
		if err != nil {
			return nil, fmt.Errorf("%w: failed to get public key: %v", backend.ErrFileNotFound, err)
		}
		return pubKey, nil
	}

	return nil, fmt.Errorf("%w: extension not supported for Azure Key Vault", backend.ErrInvalidExtension)
}

// Save stores data for a key with the specified attributes and extension.
// For Azure Key Vault, this creates a new key or stores metadata.
func (b *Backend) Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error {
	if attrs == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if metadata already exists
	if !overwrite {
		if _, exists := b.metadata[attrs.CN]; exists {
			return fmt.Errorf("%w: %s", backend.ErrFileAlreadyExists, attrs.CN)
		}
	}

	// Store metadata
	b.metadata[attrs.CN] = data

	return nil
}

// Delete removes all data associated with a key identified by its attributes.
// For Azure Key Vault, this deletes the key and removes metadata.
func (b *Backend) Delete(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return err
	}

	b.mu.Lock()
	// Remove metadata
	delete(b.metadata, attrs.CN)
	b.mu.Unlock()

	// Delete key from Azure Key Vault
	_, err := b.client.DeleteKey(ctx, attrs.CN, nil)
	if err != nil {
		// If key doesn't exist, that's okay (idempotent operation)
		// We still removed the metadata above
		return nil
	}

	return nil
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.metadata = make(map[string][]byte)
	if b.client != nil {
		if err := b.client.Close(); err != nil {
			return err
		}
		b.client = nil
	}

	return nil
}

// CreateKey creates a new Azure Key Vault key with the specified attributes.
// Returns the key ID of the created key.
// This operation is idempotent - if the key already exists, it returns the existing key ID.
func (b *Backend) CreateKey(attrs *types.KeyAttributes) (string, error) {
	if attrs == nil {
		return "", fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return "", err
	}

	// Check if key already exists (idempotent operation)
	b.mu.RLock()
	existingResp, err := b.client.GetKey(ctx, attrs.CN, "", nil)
	b.mu.RUnlock()

	if err == nil && existingResp.Key != nil && existingResp.Key.KID != nil {
		// Key already exists, return its ID
		return string(*existingResp.Key.KID), nil
	}

	// Create key parameters based on algorithm
	params, err := b.getKeyParameters(attrs)
	if err != nil {
		return "", err
	}

	// Create the key
	resp, err := b.client.CreateKey(ctx, attrs.CN, params, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create Azure Key Vault key: %w", err)
	}

	if resp.Key == nil || resp.Key.KID == nil {
		return "", fmt.Errorf("invalid response from Azure Key Vault")
	}

	keyID := *resp.Key.KID

	// Store metadata
	metadata := map[string]interface{}{
		"key_id":    keyID,
		"key_type":  attrs.KeyType,
		"cn":        attrs.CN,
		"algorithm": attrs.KeyAlgorithm.String(),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return string(keyID), fmt.Errorf("failed to marshal metadata: %w", err)
	}

	b.mu.Lock()
	b.metadata[attrs.CN] = metadataBytes
	b.mu.Unlock()

	return string(keyID), nil
}

// Sign signs a digest using the Azure Key Vault key.
// Note: This method uses default PKCS#1 v1.5 padding. For PSS signatures, use Signer() instead.
func (b *Backend) Sign(attrs *types.KeyAttributes, digest []byte) ([]byte, error) {
	if attrs == nil {
		return nil, fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Get signing algorithm (use attrs.Hash as default, no PSS)
	var opts crypto.SignerOpts = attrs.Hash
	if opts == nil || opts.HashFunc() == 0 {
		opts = crypto.SHA256
	}
	algorithm, err := b.getSigningAlgorithm(attrs, opts)
	if err != nil {
		return nil, err
	}

	// Build sign parameters
	params := azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     digest,
	}

	// Perform signing
	resp, err := b.client.Sign(ctx, attrs.CN, "", params, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault sign operation failed: %w", err)
	}

	return resp.Result, nil
}

// Verify verifies a signature using the Azure Key Vault key.
// Note: This method uses default PKCS#1 v1.5 padding. For PSS verification, use local verification after Signer() instead.
func (b *Backend) Verify(attrs *types.KeyAttributes, digest, signature []byte) error {
	if attrs == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Get signing algorithm (use attrs.Hash as default, no PSS)
	var opts crypto.SignerOpts = attrs.Hash
	if opts == nil || opts.HashFunc() == 0 {
		opts = crypto.SHA256
	}
	algorithm, err := b.getSigningAlgorithm(attrs, opts)
	if err != nil {
		return err
	}

	// Build verify parameters
	params := azkeys.VerifyParameters{
		Algorithm: &algorithm,
		Digest:    digest,
		Signature: signature,
	}

	// Perform verification
	resp, err := b.client.Verify(ctx, attrs.CN, "", params, nil)
	if err != nil {
		return fmt.Errorf("Azure Key Vault verify operation failed: %w", err)
	}

	if resp.Value == nil || !*resp.Value {
		return ErrSignatureFailed
	}

	return nil
}

// getKeyParameters converts types.KeyAttributes to Azure Key Vault CreateKeyParameters.
func (b *Backend) getKeyParameters(attrs *types.KeyAttributes) (azkeys.CreateKeyParameters, error) {
	params := azkeys.CreateKeyParameters{}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		keyType := azkeys.KeyTypeRSA
		params.Kty = &keyType

		// Default to RSA 2048 if not specified
		keySize := int32(2048)
		params.KeySize = &keySize

		// Set key operations
		params.KeyOps = []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationSign),
			ptrKeyOp(azkeys.KeyOperationVerify),
		}

	case x509.ECDSA:
		keyType := azkeys.KeyTypeEC
		params.Kty = &keyType

		// Default to P-256 if not specified
		curve := azkeys.CurveNameP256
		params.Curve = &curve

		// Set key operations
		params.KeyOps = []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationSign),
			ptrKeyOp(azkeys.KeyOperationVerify),
		}

	default:
		return params, fmt.Errorf("%w: %s", ErrUnsupportedKeyType, attrs.KeyAlgorithm)
	}

	return params, nil
}

// getSigningAlgorithm returns the appropriate Azure Key Vault signing algorithm for the key attributes.
func (b *Backend) getSigningAlgorithm(attrs *types.KeyAttributes, opts crypto.SignerOpts) (azkeys.SignatureAlgorithm, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		// Check if PSS options were provided
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			// Use PSS signature algorithm based on hash
			switch pssOpts.Hash {
			case crypto.SHA256:
				return azkeys.SignatureAlgorithmPS256, nil
			case crypto.SHA384:
				return azkeys.SignatureAlgorithmPS384, nil
			case crypto.SHA512:
				return azkeys.SignatureAlgorithmPS512, nil
			default:
				return azkeys.SignatureAlgorithmPS256, nil // Default to PS256
			}
		}
		// Use PKCS#1 v1.5 signature algorithm based on hash (from attrs or default to SHA256)
		if attrs.Hash != 0 {
			switch attrs.Hash {
			case crypto.SHA256:
				return azkeys.SignatureAlgorithmRS256, nil
			case crypto.SHA384:
				return azkeys.SignatureAlgorithmRS384, nil
			case crypto.SHA512:
				return azkeys.SignatureAlgorithmRS512, nil
			default:
				return azkeys.SignatureAlgorithmRS256, nil
			}
		}
		return azkeys.SignatureAlgorithmRS256, nil // Default to RS256
	case x509.ECDSA:
		// Use ECDSA signature algorithm based on hash
		if attrs.Hash != 0 {
			switch attrs.Hash {
			case crypto.SHA256:
				return azkeys.SignatureAlgorithmES256, nil
			case crypto.SHA384:
				return azkeys.SignatureAlgorithmES384, nil
			case crypto.SHA512:
				return azkeys.SignatureAlgorithmES512, nil
			default:
				return azkeys.SignatureAlgorithmES256, nil
			}
		}
		return azkeys.SignatureAlgorithmES256, nil // Default to ES256
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}
}

// ptrKeyOp returns a pointer to a KeyOperation value.
func ptrKeyOp(op azkeys.KeyOperation) *azkeys.KeyOperation {
	return &op
}

// CreateSecretKey creates a new symmetric secret key in Azure Key Vault.
// This method creates an oct (octet) key type for symmetric encryption operations.
//
// Parameters:
//   - attrs: Key attributes specifying the key name and type
//   - keySize: Key size in bytes (16 for AES-128, 32 for AES-256)
//
// Returns the key ID of the created key, or an error if creation fails.
func (b *Backend) CreateSecretKey(attrs *types.KeyAttributes, keySize int) (string, error) {
	if attrs == nil {
		return "", fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return "", err
	}

	// Check if key already exists (idempotent operation)
	b.mu.RLock()
	existingResp, err := b.client.GetKey(ctx, attrs.CN, "", nil)
	b.mu.RUnlock()

	if err == nil && existingResp.Key != nil && existingResp.Key.KID != nil {
		// Key already exists, return its ID
		return string(*existingResp.Key.KID), nil
	}

	// Create symmetric key parameters
	keyType := azkeys.KeyTypeOct
	keySizeInt32 := int32(keySize * 8) // Convert bytes to bits

	params := azkeys.CreateKeyParameters{
		Kty:     &keyType,
		KeySize: &keySizeInt32,
		KeyOps: []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationEncrypt),
			ptrKeyOp(azkeys.KeyOperationDecrypt),
			ptrKeyOp(azkeys.KeyOperationWrapKey),
			ptrKeyOp(azkeys.KeyOperationUnwrapKey),
		},
	}

	// Create the key
	resp, err := b.client.CreateKey(ctx, attrs.CN, params, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create symmetric key in Azure Key Vault: %w", err)
	}

	if resp.Key == nil || resp.Key.KID == nil {
		return "", fmt.Errorf("invalid response from Azure Key Vault")
	}

	keyID := *resp.Key.KID

	// Store metadata
	metadata := map[string]interface{}{
		"key_id":    keyID,
		"key_type":  attrs.KeyType,
		"cn":        attrs.CN,
		"key_size":  keySize,
		"symmetric": true,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return string(keyID), fmt.Errorf("failed to marshal metadata: %w", err)
	}

	b.mu.Lock()
	b.metadata[attrs.CN] = metadataBytes
	b.mu.Unlock()

	return string(keyID), nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeAzureKV
}

// GenerateKey generates a new private key with the given attributes.
// For Azure Key Vault, this creates a new key and stores metadata.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	// Create the Azure Key Vault key
	keyID, err := b.CreateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault key: %w", err)
	}

	// For Azure Key Vault, we don't return the actual private key material (it stays in the vault)
	// Instead, we return a reference that can be used via Signer/Decrypter
	_ = keyID

	// Return nil for private key since it's not extractable from Azure Key Vault
	// Callers should use Signer() or Decrypter() instead
	return nil, nil
}

// GetKey retrieves an existing private key by its attributes.
// For Azure Key Vault, this verifies the key exists and returns a reference.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Check if metadata exists
	b.mu.RLock()
	_, exists := b.metadata[attrs.CN]
	b.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	// Verify key exists in Azure Key Vault
	_, err := b.client.GetKey(ctx, attrs.CN, "", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get key: %v", backend.ErrKeyNotFound, err)
	}

	// Return nil for private key since it's not extractable from Azure Key Vault
	// Callers should use Signer() or Decrypter() instead
	return nil, nil
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
func (b *Backend) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_AZUREKV,
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
		StoreType: backend.STORE_AZUREKV,
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

// DeleteKey removes a key identified by its attributes.
func (b *Backend) DeleteKey(attrs *types.KeyAttributes) error {
	return b.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	var allKeys []*types.KeyAttributes

	// List all keys from metadata
	// We rely on metadata since Azure Key Vault ListKeys requires pagination
	// and metadata provides the key type information we need
	b.mu.RLock()
	metadataCopy := make(map[string][]byte, len(b.metadata))
	for k, v := range b.metadata {
		metadataCopy[k] = v
	}
	b.mu.RUnlock()

	// Reconstruct KeyAttributes from metadata
	for cn, metadataBytes := range metadataCopy {
		var metadata map[string]interface{}
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			continue // Skip invalid metadata
		}

		attrs := &types.KeyAttributes{
			CN: cn,
		}

		// Extract key type
		if keyTypeStr, ok := metadata["key_type"].(string); ok {
			attrs.KeyType = types.ParseKeyType(keyTypeStr)
		}

		// Extract key algorithm
		if algorithmStr, ok := metadata["algorithm"].(string); ok {
			// Convert string to x509.PublicKeyAlgorithm using the types package
			if algo, exists := types.AvailableKeyAlgorithms()[algorithmStr]; exists {
				attrs.KeyAlgorithm = algo
			}
		}

		// Set store type
		attrs.StoreType = backend.STORE_AZUREKV

		allKeys = append(allKeys, attrs)
	}

	return allKeys, nil
}

// azurekvSigner implements crypto.Signer using Azure Key Vault.
type azurekvSigner struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
}

// azurekvDecrypter implements crypto.Decrypter using Azure Key Vault.
type azurekvDecrypter struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	if attrs == nil {
		return nil, fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Get the public key
	pubKeyBytes, err := b.client.GetPublicKey(ctx, attrs.CN, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse the public key from PEM
	publicKey, err := parsePublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &azurekvSigner{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil {
		return nil, fmt.Errorf("%w: attributes cannot be nil", backend.ErrInvalidAttributes)
	}

	// Only RSA keys support decryption in Azure Key Vault
	if attrs.KeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("%w: only RSA keys support decryption", backend.ErrInvalidAlgorithm)
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Get the public key
	pubKeyBytes, err := b.client.GetPublicKey(ctx, attrs.CN, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse the public key from PEM
	publicKey, err := parsePublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &azurekvDecrypter{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
	}, nil
}

// RotateKey rotates/updates a key identified by attrs.
// For Azure Key Vault, this uses the RotateKey API to create a new key version.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Rotate the key using Azure Key Vault's RotateKey API
	_, err := b.client.RotateKey(ctx, attrs.CN, nil)
	if err != nil {
		return fmt.Errorf("failed to rotate key: %w", err)
	}

	return nil
}

// Public returns the public key corresponding to the Azure Key Vault signing key.
func (s *azurekvSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the given digest using Azure Key Vault.
// The digest must be pre-hashed according to the key's hash algorithm.
// Supports both PKCS#1 v1.5 and PSS padding via opts parameter.
func (s *azurekvSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()
	if err := s.backend.initClient(ctx); err != nil {
		return nil, err
	}

	// Get signing algorithm (detects PSS from opts)
	algorithm, err := s.backend.getSigningAlgorithm(s.attrs, opts)
	if err != nil {
		return nil, err
	}

	// Build sign parameters
	params := azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     digest,
	}

	// Perform signing
	resp, err := s.backend.client.Sign(ctx, s.attrs.CN, "", params, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault sign operation failed: %w", err)
	}

	return resp.Result, nil
}

// Public returns the public key corresponding to the Azure Key Vault decryption key.
func (d *azurekvDecrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// Decrypt decrypts the given ciphertext using Azure Key Vault.
// The opts parameter specifies the decryption options (e.g., OAEP padding).
func (d *azurekvDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	ctx := context.Background()
	if err := d.backend.initClient(ctx); err != nil {
		return nil, err
	}

	// Determine encryption algorithm based on opts
	// Default to RSA-OAEP with SHA-256
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256

	// Check if OAEP options are provided
	if oaepOpts, ok := opts.(*rsa.OAEPOptions); ok && oaepOpts != nil {
		// Use OAEP with the specified hash
		switch oaepOpts.Hash {
		case crypto.SHA1:
			algorithm = azkeys.EncryptionAlgorithmRSAOAEP
		case crypto.SHA256:
			algorithm = azkeys.EncryptionAlgorithmRSAOAEP256
		default:
			return nil, fmt.Errorf("unsupported OAEP hash algorithm: %v", oaepOpts.Hash)
		}
	} else if opts == nil {
		// If opts is nil, use PKCS#1 v1.5 padding (legacy/compatibility mode)
		algorithm = azkeys.EncryptionAlgorithmRSA15
	}
	// Otherwise, keep default OAEP256

	// Build decrypt parameters
	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     ciphertext,
	}

	// Perform decryption
	resp, err := d.backend.client.Decrypt(ctx, d.attrs.CN, "", params, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault decrypt operation failed: %w", err)
	}

	return resp.Result, nil
}

// jwkToPublicKey converts an Azure Key Vault JWK to a crypto.PublicKey
func jwkToPublicKey(jwk *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if jwk == nil {
		return nil, fmt.Errorf("JWK is nil")
	}

	// Check key type
	if jwk.Kty == nil {
		return nil, fmt.Errorf("key type is nil")
	}

	switch *jwk.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		// RSA key
		if jwk.N == nil || jwk.E == nil {
			return nil, fmt.Errorf("RSA key missing N or E")
		}

		// Convert modulus and exponent from base64url bytes to big.Int
		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(jwk.N),
		}

		// E is typically 65537 (0x010001) which is 3 bytes
		eInt := new(big.Int).SetBytes(jwk.E)
		if !eInt.IsInt64() {
			return nil, fmt.Errorf("RSA exponent too large")
		}
		pubKey.E = int(eInt.Int64())

		return pubKey, nil

	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		// ECDSA key
		if jwk.X == nil || jwk.Y == nil || jwk.Crv == nil {
			return nil, fmt.Errorf("EC key missing X, Y, or Crv")
		}

		var curve elliptic.Curve
		switch *jwk.Crv {
		case azkeys.CurveNameP256:
			curve = elliptic.P256()
		case azkeys.CurveNameP384:
			curve = elliptic.P384()
		case azkeys.CurveNameP521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve: %v", *jwk.Crv)
		}

		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(jwk.X),
			Y:     new(big.Int).SetBytes(jwk.Y),
		}

		return pubKey, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %v", *jwk.Kty)
	}
}

// parsePublicKey parses a public key from PEM or DER format.
func parsePublicKey(pubKeyBytes []byte) (crypto.PublicKey, error) {
	// Try to parse as PEM first
	block, _ := pem.Decode(pubKeyBytes)
	if block != nil {
		pubKeyBytes = block.Bytes
	}

	// Parse PKIX public key
	publicKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return publicKey, nil
}
