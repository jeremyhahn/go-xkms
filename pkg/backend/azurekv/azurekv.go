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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
		return nil, &errs.Message{Msg: "no key in response"}
	}

	// Convert JWK to crypto.PublicKey
	pubKey, err := jwkToPublicKey(resp.Key)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to convert JWK to public key", Err: err}
	}

	// Marshal to PKIX format
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal public key", Err: err}
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

// Backend implements the types.KeyProvider interface for Azure Key Vault.
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
		return nil, &errs.Wrapped{Msg: "config validation failed", Err: err}
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
		return nil, &errs.Wrapped{Msg: "config validation failed", Err: err}
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

// hasServicePrincipal reports whether the backend is configured with a full
// Azure service principal (tenant, client ID, and client secret), the
// prerequisite for azidentity.NewClientSecretCredential over
// azidentity.NewDefaultAzureCredential.
func (b *Backend) hasServicePrincipal() bool {
	return b.config.ClientID != "" && b.config.TenantID != "" && b.config.ClientSecret != nil
}

// newClientSecretCredential builds an azidentity.ClientSecretCredential from
// the configured service principal. azidentity.NewClientSecretCredential
// takes the client secret as a plain string — the documented third-party-SDK
// boundary (go-xkms#610): the plaintext leaves ClientSecret's SecretValue
// enclave only for the duration of this constructor call.
func (b *Backend) newClientSecretCredential(credOptions *azidentity.ClientSecretCredentialOptions) (*azidentity.ClientSecretCredential, error) {
	clientSecret, err := types.SecretValueBytes(b.config.ClientSecret)
	if err != nil {
		return nil, err
	}
	return azidentity.NewClientSecretCredential(
		b.config.TenantID,
		b.config.ClientID,
		string(clientSecret),
		credOptions,
	)
}

// initClient initializes the Azure Key Vault client if not already initialized.
// Uses double-checked locking pattern to minimize contention.
func (b *Backend) initClient(ctx context.Context) error {
	// Fast path: check if client is already initialized with read lock
	b.mu.RLock()
	if b.client != nil {
		b.mu.RUnlock()
		return nil
	}
	b.mu.RUnlock()

	// Slow path: acquire write lock and double-check
	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check after acquiring write lock
	if b.client != nil {
		return nil
	}

	var client *azkeys.Client

	if b.hasServicePrincipal() {
		// Use ClientSecretCredential for service principal authentication
		// with additional allowed tenants
		credOptions := &azidentity.ClientSecretCredentialOptions{
			AdditionallyAllowedTenants: []string{"*"},
		}
		cred, err := b.newClientSecretCredential(credOptions)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create client secret credential", Err: err}
		}

		// Create Azure Key Vault client with ClientSecretCredential
		client, err = azkeys.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create Azure Key Vault client", Err: err}
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

		// Create Azure Key Vault client
		client, err = azkeys.NewClient(b.config.VaultURL, cred, nil)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to create Azure Key Vault client", Err: err}
		}
	}

	b.client = &realKeyVaultClient{Client: client}

	return nil
}

// Capabilities returns the capabilities of this backend.
// Azure Key Vault is a cloud-based HSM service with hardware-backed security.
// Symmetric encryption is supported by storing AES keys as secrets (not oct key type).
// SecurityLevel is Medium - keys are protected by cloud HSMs but network-dependent.
func (b *Backend) Capabilities() types.Capabilities {
	caps := types.NewHardwareCapabilities()
	caps.SymmetricEncryption = true // Supported via Secrets API
	caps.Import = true              // Supported via ImportKey API
	caps.Export = false             // Azure KV does not allow key extraction for security
	caps.SecurityLevel = types.SecurityLevelMedium
	return caps
}

// Get retrieves data for a key with the specified attributes and extension.
// For Azure Key Vault, this retrieves the public key or metadata associated with the key.
func (b *Backend) Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error) {
	if attrs == nil {
		return nil, &errs.Message{Msg: "attributes cannot be nil"}
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
			return nil, &errs.Detail{Err: backend.ErrFileNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
		}
		return data, nil
	}

	// For public key extensions, retrieve from Azure Key Vault
	if extension == backend.FSEXT_PUBLIC_PKCS1 || extension == backend.FSEXT_PUBLIC_PEM {
		pubKey, err := b.client.GetPublicKey(ctx, attrs.CN, "")
		if err != nil {
			return nil, &errs.Detail{Err: backend.ErrFileNotFound, Detail: fmt.Sprintf("failed to get public key: %v", err)}
		}
		return pubKey, nil
	}

	return nil, &errs.Detail{Err: backend.ErrInvalidExtension, Detail: "extension not supported for Azure Key Vault"}
}

// Save stores data for a key with the specified attributes and extension.
// For Azure Key Vault, this creates a new key or stores metadata.
func (b *Backend) Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error {
	if attrs == nil {
		return &errs.Message{Msg: "attributes cannot be nil"}
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
			return &errs.Detail{Err: backend.ErrFileAlreadyExists, Detail: fmt.Sprintf("%s", attrs.CN)}
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
		return &errs.Message{Msg: "attributes cannot be nil"}
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
		return "", &errs.Message{Msg: "attributes cannot be nil"}
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
		return "", &errs.Wrapped{Msg: "failed to create Azure Key Vault key", Err: err}
	}

	if resp.Key == nil || resp.Key.KID == nil {
		return "", &errs.Message{Msg: "invalid response from Azure Key Vault"}
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
		return string(keyID), &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
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
		return nil, &errs.Message{Msg: "attributes cannot be nil"}
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
		return nil, &errs.Wrapped{Msg: "Azure Key Vault sign operation failed", Err: err}
	}

	if attrs.KeyAlgorithm == x509.ECDSA {
		return ecdsaResultToDER(resp.Result)
	}
	return resp.Result, nil
}

// ecdsaResultToDER normalizes an Azure Key Vault ECDSA signature to ASN.1 DER.
// Azure returns ES256/384/512 signatures in IEEE-P1363 fixed-width r‖s form, but
// the crypto.Signer contract (and therefore x509, SSH, and every other consumer)
// requires ASN.1 DER. Input that is already DER is returned unchanged, so the
// helper is safe regardless of the client's wire format.
func ecdsaResultToDER(sig []byte) ([]byte, error) {
	var probe struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &probe); err == nil {
		return sig, nil // already ASN.1 DER
	}
	if len(sig) == 0 || len(sig)%2 != 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("azurekv: unexpected ECDSA signature length %d", len(sig))}
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "azurekv: encode ECDSA signature", Err: err}
	}
	return der, nil
}

// Verify verifies a signature using the Azure Key Vault key.
// Note: This method uses default PKCS#1 v1.5 padding. For PSS verification, use local verification after Signer() instead.
func (b *Backend) Verify(attrs *types.KeyAttributes, digest, signature []byte) error {
	if attrs == nil {
		return &errs.Message{Msg: "attributes cannot be nil"}
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
		return &errs.Wrapped{Msg: "Azure Key Vault verify operation failed", Err: err}
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
		return params, &errs.Detail{Err: ErrUnsupportedKeyType, Detail: fmt.Sprintf("%s", attrs.KeyAlgorithm)}
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
		return "", &errs.Detail{Err: ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s", attrs.KeyAlgorithm)}
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
		return "", &errs.Message{Msg: "attributes cannot be nil"}
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
		return "", &errs.Wrapped{Msg: "failed to create symmetric key in Azure Key Vault", Err: err}
	}

	if resp.Key == nil || resp.Key.KID == nil {
		return "", &errs.Message{Msg: "invalid response from Azure Key Vault"}
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
		return string(keyID), &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
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
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	// Create the Azure Key Vault key
	keyID, err := b.CreateKey(attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create Azure Key Vault key", Err: err}
	}

	// For Azure Key Vault, we don't return the actual private key material (it stays in the vault)
	// Instead, we return a reference that can be used via Signer/Decrypter
	// Log the key ID for debugging purposes
	fmt.Printf("azurekv: generated key %s (private key material remains in vault)\n", keyID)

	// Return nil for private key since it's not extractable from Azure Key Vault
	// Callers should use Signer() or Decrypter() instead
	return nil, nil
}

// GetKey retrieves an existing private key by its attributes.
// For Azure Key Vault, this verifies the key exists and returns a reference.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Check if metadata exists
	b.mu.RLock()
	_, exists := b.metadata[attrs.CN]
	b.mu.RUnlock()

	if !exists {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s", attrs.CN)}
	}

	// Verify key exists in Azure Key Vault. Only an HTTP 404 -- Key Vault's
	// signal that the key genuinely does not exist -- is reported as
	// ErrKeyNotFound. Any other failure (throttling, a transport fault, an
	// RBAC/authorization denial) must not be conflated with "no key yet":
	// getOrGenerateCAKey relies on that distinction to decide whether
	// generating a replacement key is safe.
	_, err := b.client.GetKey(ctx, attrs.CN, "", nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("failed to get key: %v", err)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("failed to get key: %v", err)}
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
	key, err := b.GetKey(context.Background(), attrs)
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
func (b *Backend) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: backend.STORE_AZUREKV,
	}
	key, err := b.GetKey(context.Background(), attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key %s does not implement crypto.Decrypter", keyID)}
	}
	return decrypter, nil
}

// DeleteKey removes a key identified by its attributes.
func (b *Backend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return b.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
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

// azurekvSigner implements crypto.Signer using Azure Key Vault. It pins the
// key version resolved when the Signer was constructed, so Public() always
// matches the exact version Sign() uses even if the key is rotated later.
type azurekvSigner struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
	version   string
}

// azurekvDecrypter implements crypto.Decrypter using Azure Key Vault. It
// pins the key version resolved when the Decrypter was constructed, so
// Public() always matches the exact version Decrypt() uses even if the key
// is rotated later.
type azurekvDecrypter struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
	version   string
}

// resolveKeyVersion returns the current version identifier of the named
// key, parsed from the key identifier (KID) Azure Key Vault reports for its
// latest version. Callers that must stay pinned to a specific version
// regardless of later rotations (Signer and Decrypter) resolve it once at
// construction and pass it explicitly on every subsequent operation instead
// of the empty string, which Azure would otherwise resolve to whatever is
// latest at call time.
func (b *Backend) resolveKeyVersion(ctx context.Context, name string) (string, error) {
	resp, err := b.client.GetKey(ctx, name, "", nil)
	if err != nil {
		return "", &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("failed to get key: %v", err)}
	}
	if resp.Key == nil || resp.Key.KID == nil {
		return "", &errs.Detail{Err: ErrKeyNotFound, Detail: name}
	}
	return parseKeyVersion(*resp.Key.KID)
}

// parseKeyVersion extracts the version segment from an Azure Key Vault key
// identifier, which has the form
// "https://{vault}.vault.azure.net/keys/{name}/{version}".
func parseKeyVersion(kid azkeys.ID) (string, error) {
	s := string(kid)
	idx := strings.LastIndex(s, "/")
	if idx < 0 || idx == len(s)-1 {
		return "", &errs.Detail{Err: ErrInvalidKeyID, Detail: s}
	}
	return s[idx+1:], nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Resolve the current key version and pin the signer to it, so Public()
	// always matches the exact version Sign() uses even if the key is
	// rotated later.
	version, err := b.resolveKeyVersion(ctx, attrs.CN)
	if err != nil {
		return nil, err
	}

	// Get the public key for that exact version
	pubKeyBytes, err := b.client.GetPublicKey(ctx, attrs.CN, version)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get public key", Err: err}
	}

	// Parse the public key from PEM
	publicKey, err := parsePublicKey(pubKeyBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
	}

	return &azurekvSigner{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
		version:   version,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "attributes cannot be nil"}
	}

	// Only RSA keys support decryption in Azure Key Vault
	if attrs.KeyAlgorithm != x509.RSA {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: "only RSA keys support decryption"}
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Resolve the current key version and pin the decrypter to it, so
	// Public() always matches the exact version Decrypt() uses even if the
	// key is rotated later.
	version, err := b.resolveKeyVersion(ctx, attrs.CN)
	if err != nil {
		return nil, err
	}

	// Get the public key for that exact version
	pubKeyBytes, err := b.client.GetPublicKey(ctx, attrs.CN, version)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get public key", Err: err}
	}

	// Parse the public key from PEM
	publicKey, err := parsePublicKey(pubKeyBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
	}

	return &azurekvDecrypter{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
		version:   version,
	}, nil
}

// RotateKey rotates/updates a key identified by attrs.
// For Azure Key Vault, this uses the RotateKey API to create a new key version.
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return &errs.Message{Msg: "attributes cannot be nil"}
	}

	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Rotate the key using Azure Key Vault's RotateKey API
	_, err := b.client.RotateKey(ctx, attrs.CN, nil)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to rotate key", Err: err}
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

	// Sign against the version pinned at construction, not the latest
	// version, so this call always uses the same key whose public half
	// Public() reports.
	resp, err := s.backend.client.Sign(ctx, s.attrs.CN, s.version, params, nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "Azure Key Vault sign operation failed", Err: err}
	}

	// Azure returns ECDSA signatures as IEEE-P1363 r‖s; crypto.Signer requires
	// ASN.1 DER. Normalize so the key works as an x509/SSH signer.
	if _, ok := s.publicKey.(*ecdsa.PublicKey); ok {
		return ecdsaResultToDER(resp.Result)
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
			return nil, &errs.Message{Msg: fmt.Sprintf("unsupported OAEP hash algorithm: %v", oaepOpts.Hash)}
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

	// Decrypt against the version pinned at construction, not the latest
	// version, so this call always uses the same key whose public half
	// Public() reports.
	resp, err := d.backend.client.Decrypt(ctx, d.attrs.CN, d.version, params, nil)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "Azure Key Vault decrypt operation failed", Err: err}
	}

	return resp.Result, nil
}

// jwkToPublicKey converts an Azure Key Vault JWK to a crypto.PublicKey
func jwkToPublicKey(jwk *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if jwk == nil {
		return nil, &errs.Message{Msg: "JWK is nil"}
	}

	// Check key type
	if jwk.Kty == nil {
		return nil, &errs.Message{Msg: "key type is nil"}
	}

	switch *jwk.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		// RSA key
		if jwk.N == nil || jwk.E == nil {
			return nil, &errs.Message{Msg: "RSA key missing N or E"}
		}

		// Convert modulus and exponent from base64url bytes to big.Int
		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(jwk.N),
		}

		// E is typically 65537 (0x010001) which is 3 bytes
		eInt := new(big.Int).SetBytes(jwk.E)
		if !eInt.IsInt64() {
			return nil, &errs.Message{Msg: "RSA exponent too large"}
		}
		pubKey.E = int(eInt.Int64())

		return pubKey, nil

	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		// ECDSA key
		if jwk.X == nil || jwk.Y == nil || jwk.Crv == nil {
			return nil, &errs.Message{Msg: "EC key missing X, Y, or Crv"}
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
			return nil, &errs.Message{Msg: fmt.Sprintf("unsupported curve: %v", *jwk.Crv)}
		}

		pubKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(jwk.X),
			Y:     new(big.Int).SetBytes(jwk.Y),
		}

		return pubKey, nil

	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %v", *jwk.Kty)}
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
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
	}

	return publicKey, nil
}
