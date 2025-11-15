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

//go:build gcpkms

package gcpkms

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
	"hash/crc32"
	"io"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// KMSClient defines the interface for GCP KMS operations.
// This interface allows for mocking in tests.
type KMSClient interface {
	CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error)
	GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error)
	GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...interface{}) ([]*kmspb.CryptoKey, error)
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error)
	AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error)
	CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest, opts ...interface{}) (*kmspb.CryptoKey, error)
	DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error)
	CreateImportJob(ctx context.Context, req *kmspb.CreateImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error)
	GetImportJob(ctx context.Context, req *kmspb.GetImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error)
	ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error)
	Close() error
}

// realKMSClient wraps the actual GCP KMS client to implement our interface.
type realKMSClient struct {
	*kms.KeyManagementClient
}

func (r *realKMSClient) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
	return r.KeyManagementClient.CreateCryptoKey(ctx, req)
}

func (r *realKMSClient) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
	return r.KeyManagementClient.GetCryptoKey(ctx, req)
}

func (r *realKMSClient) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	return r.KeyManagementClient.GetCryptoKeyVersion(ctx, req)
}

func (r *realKMSClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...interface{}) (*kmspb.AsymmetricSignResponse, error) {
	return r.KeyManagementClient.AsymmetricSign(ctx, req)
}

func (r *realKMSClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...interface{}) (*kmspb.PublicKey, error) {
	return r.KeyManagementClient.GetPublicKey(ctx, req)
}

func (r *realKMSClient) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	return r.KeyManagementClient.DestroyCryptoKeyVersion(ctx, req)
}

func (r *realKMSClient) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest, opts ...interface{}) ([]*kmspb.CryptoKey, error) {
	it := r.KeyManagementClient.ListCryptoKeys(ctx, req)
	var keys []*kmspb.CryptoKey
	for {
		key, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (r *realKMSClient) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest, opts ...interface{}) (*kmspb.AsymmetricDecryptResponse, error) {
	return r.KeyManagementClient.AsymmetricDecrypt(ctx, req)
}

func (r *realKMSClient) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	return r.KeyManagementClient.CreateCryptoKeyVersion(ctx, req)
}

func (r *realKMSClient) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest, opts ...interface{}) (*kmspb.CryptoKey, error) {
	return r.KeyManagementClient.UpdateCryptoKeyPrimaryVersion(ctx, req)
}

func (r *realKMSClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...interface{}) (*kmspb.EncryptResponse, error) {
	return r.KeyManagementClient.Encrypt(ctx, req)
}

func (r *realKMSClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...interface{}) (*kmspb.DecryptResponse, error) {
	return r.KeyManagementClient.Decrypt(ctx, req)
}

func (r *realKMSClient) CreateImportJob(ctx context.Context, req *kmspb.CreateImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error) {
	return r.KeyManagementClient.CreateImportJob(ctx, req)
}

func (r *realKMSClient) GetImportJob(ctx context.Context, req *kmspb.GetImportJobRequest, opts ...interface{}) (*kmspb.ImportJob, error) {
	return r.KeyManagementClient.GetImportJob(ctx, req)
}

func (r *realKMSClient) ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	return r.KeyManagementClient.ImportCryptoKeyVersion(ctx, req)
}

// Backend implements the types.Backend interface using Google Cloud KMS.
type Backend struct {
	config  *Config
	client  KMSClient
	tracker types.AEADSafetyTracker // AEAD safety tracker for nonce/bytes tracking
	mu      sync.RWMutex
	types.Backend
}

// NewBackend creates a new GCP KMS backend with the provided configuration.
// It initializes the KMS client and validates the configuration.
func NewBackend(ctx context.Context, config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Build client options
	var opts []option.ClientOption

	// Add credentials if provided
	if len(config.CredentialsJSON) > 0 {
		opts = append(opts, option.WithCredentialsJSON(config.CredentialsJSON))
	} else if config.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(config.CredentialsFile))
	}

	// Add custom endpoint if provided (for testing with emulator)
	if config.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(config.Endpoint))
	}

	// Create KMS client
	kmsClient, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}

	// Create default tracker if none provided
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	return &Backend{
		config:  config,
		client:  &realKMSClient{KeyManagementClient: kmsClient},
		tracker: tracker,
	}, nil
}

// NewBackendWithClient creates a new GCP KMS backend with a custom KMS client.
// This is primarily used for testing with mock clients.
func NewBackendWithClient(config *Config, client KMSClient) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Create default tracker if none provided
	tracker := config.Tracker
	if tracker == nil {
		tracker = backend.NewMemoryAEADTracker()
	}

	return &Backend{
		config:  config,
		client:  client,
		tracker: tracker,
	}, nil
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeGCPKMS
}

// Capabilities returns the capabilities of this backend.
// GCP KMS is a cloud-based HSM service with hardware-backed security.
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      true, // GCP KMS uses FIPS 140-2 Level 3 validated HSMs
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,  // GCP KMS supports symmetric encryption
		Import:              true,  // GCP KMS supports key import via wrapping
		Export:              false, // GCP KMS does not allow key extraction
	}
}

// Get retrieves the public key for a KMS key.
// For GCP KMS, this fetches the public key from the key version.
func (b *Backend) Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	ctx := context.Background()
	keyName := b.cryptoKeyVersionName(attrs.CN)

	req := &kmspb.GetPublicKeyRequest{
		Name: keyName,
	}

	pubKey, err := b.client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", backend.ErrKeyNotFound, attrs.CN, err)
	}

	// Return PEM-encoded public key
	return []byte(pubKey.Pem), nil
}

// Save is not supported for GCP KMS as keys are managed by GCP.
// Use GenerateKey methods to create keys in KMS.
func (b *Backend) Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error {
	return fmt.Errorf("%w: cannot save data to GCP KMS, use GenerateKey methods", backend.ErrOperationNotSupported)
}

// Delete destroys a crypto key version in GCP KMS.
// Note: GCP KMS uses soft deletion and keys can be restored within a retention period.
func (b *Backend) Delete(attrs *types.KeyAttributes) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return ErrNotInitialized
	}

	ctx := context.Background()
	keyName := b.cryptoKeyVersionName(attrs.CN)

	req := &kmspb.DestroyCryptoKeyVersionRequest{
		Name: keyName,
	}

	_, err := b.client.DestroyCryptoKeyVersion(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to destroy key %s: %w", attrs.CN, err)
	}

	return nil
}

// Close releases resources held by the backend.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return nil
	}

	return b.client.Close()
}

// waitForKeyEnabled polls the key version status until it becomes ENABLED.
// GCP KMS keys go through a PENDING_GENERATION state after creation.
// This function waits for the key to be ready for use with a configurable timeout.
func (b *Backend) waitForKeyEnabled(ctx context.Context, keyVersionName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	pollInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		req := &kmspb.GetCryptoKeyVersionRequest{
			Name: keyVersionName,
		}

		version, err := b.client.GetCryptoKeyVersion(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to get key version status: %w", err)
		}

		if version.State == kmspb.CryptoKeyVersion_ENABLED {
			return nil
		}

		if version.State != kmspb.CryptoKeyVersion_PENDING_GENERATION {
			return fmt.Errorf("key version in unexpected state: %s", version.State.String())
		}

		time.Sleep(pollInterval)
	}

	return fmt.Errorf("timeout waiting for key to be enabled after %v", timeout)
}

// GenerateKey generates a new private key with the given attributes.
// For GCP KMS, this creates a new KMS key and stores metadata.
// Returns nil for private key since it's not extractable from KMS.
func (b *Backend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	var err error
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		_, err = b.GenerateRSA(attrs)
	case x509.ECDSA:
		_, err = b.GenerateECDSA(attrs)
	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidKeyType, attrs.KeyAlgorithm)
	}

	if err != nil {
		return nil, err
	}

	// Return nil for private key since it's not extractable from KMS
	// Callers should use Signer() or Decrypter() instead
	return nil, nil
}

// GenerateRSA creates a new RSA signing key in GCP KMS.
func (b *Backend) GenerateRSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.Lock()

	if b.client == nil {
		b.mu.Unlock()
		return nil, ErrNotInitialized
	}

	if attrs == nil || attrs.KeyAlgorithm != x509.RSA {
		b.mu.Unlock()
		return nil, backend.ErrInvalidAttributes
	}

	// Determine RSA key size (default to 2048 if not specified)
	keySize := 2048
	if attrs.KeyAlgorithm == x509.RSA {
		// Key size would come from RSAAttributes in the full implementation
		// For now, we'll use a default
		keySize = 2048
	}

	// Map key size to GCP KMS algorithm
	var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	switch keySize {
	case 2048:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256
	case 3072:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256
	case 4096:
		algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256
	default:
		b.mu.Unlock()
		return nil, fmt.Errorf("%w: unsupported RSA key size %d", backend.ErrInvalidKeyType, keySize)
	}

	ctx := context.Background()
	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      b.config.KeyRingName(),
		CryptoKeyId: attrs.CN,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
			Labels: map[string]string{
				"created-by": "go-keychain",
			},
		},
	}

	cryptoKey, err := b.client.CreateCryptoKey(ctx, req)
	if err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("failed to create RSA key: %w", err)
	}

	// Wait for the key to be enabled (GCP KMS keys start in PENDING_GENERATION state)
	keyVersionName := b.cryptoKeyVersionName(attrs.CN)
	if err := b.waitForKeyEnabled(ctx, keyVersionName, 30*time.Second); err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("key creation failed: %w", err)
	}

	// Store metadata
	metadata := map[string]interface{}{
		"key_name":      cryptoKey.Name,
		"algorithm":     algorithm.String(),
		"purpose":       cryptoKey.Purpose.String(),
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType,
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_GCPKMS,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(b.config.KeyStorage, attrs.ID(), metadataBytes); err != nil {
			b.mu.Unlock()
			return nil, fmt.Errorf("failed to save metadata: %w", err)
		}
	}

	b.mu.Unlock() // Release lock before calling Signer
	return b.Signer(attrs)
}

// GenerateECDSA creates a new ECDSA signing key in GCP KMS.
func (b *Backend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.Lock()

	if b.client == nil {
		b.mu.Unlock()
		return nil, ErrNotInitialized
	}

	if attrs == nil || attrs.KeyAlgorithm != x509.ECDSA {
		b.mu.Unlock()
		return nil, backend.ErrInvalidAttributes
	}

	// Determine elliptic curve (default to P-256)
	curve := "P-256"

	// Map curve to GCP KMS algorithm
	var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	switch curve {
	case "P-256":
		algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	case "P-384":
		algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384
	default:
		return nil, fmt.Errorf("%w: unsupported curve %s", backend.ErrInvalidKeyType, curve)
	}

	ctx := context.Background()
	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      b.config.KeyRingName(),
		CryptoKeyId: attrs.CN,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
			Labels: map[string]string{
				"created-by": "go-keychain",
			},
		},
	}

	cryptoKey, err := b.client.CreateCryptoKey(ctx, req)
	if err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	// Wait for the key to be enabled (GCP KMS keys start in PENDING_GENERATION state)
	keyVersionName := b.cryptoKeyVersionName(attrs.CN)
	if err := b.waitForKeyEnabled(ctx, keyVersionName, 30*time.Second); err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("key creation failed: %w", err)
	}

	// Store metadata
	metadata := map[string]interface{}{
		"key_name":      cryptoKey.Name,
		"algorithm":     algorithm.String(),
		"purpose":       cryptoKey.Purpose.String(),
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType,
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_GCPKMS,
		"curve":         curve,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		b.mu.Unlock()
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(b.config.KeyStorage, attrs.ID(), metadataBytes); err != nil {
			b.mu.Unlock()
			return nil, fmt.Errorf("failed to save metadata: %w", err)
		}
	}

	b.mu.Unlock() // Release lock before calling Signer
	return b.Signer(attrs)
}

// GenerateSymmetricKey creates a new symmetric encryption key in GCP KMS.
//
// GCP KMS only supports AES-256 symmetric keys using the GOOGLE_SYMMETRIC_ENCRYPTION
// algorithm. The key material never leaves GCP infrastructure and can only be used
// through GCP KMS encryption/decryption APIs.
//
// Parameters:
//   - attrs: Key attributes specifying the key identifier (CN), key type, and AES attributes
//
// Returns a SymmetricKey reference (key material remains in KMS) or an error.
func (b *Backend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm %s", backend.ErrInvalidKeyType, attrs.KeyAlgorithm)
	}

	// GCP KMS only supports 256-bit symmetric keys
	if attrs.AESAttributes.KeySize != 256 {
		return nil, fmt.Errorf("%w: GCP KMS only supports AES-256 symmetric keys, got %d", backend.ErrInvalidKeyType, attrs.AESAttributes.KeySize)
	}

	ctx := context.Background()
	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      b.config.KeyRingName(),
		CryptoKeyId: attrs.CN,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
			Labels: map[string]string{
				"created-by":    "go-keychain",
				"key-type":      string(attrs.KeyType),
				"key-algorithm": string(attrs.SymmetricAlgorithm),
			},
		},
	}

	cryptoKey, err := b.client.CreateCryptoKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create symmetric key: %w", err)
	}

	// Wait for the key to be enabled (GCP KMS keys start in PENDING_GENERATION state)
	keyVersionName := b.cryptoKeyVersionName(attrs.CN)
	if err := b.waitForKeyEnabled(ctx, keyVersionName, 30*time.Second); err != nil {
		return nil, fmt.Errorf("key creation failed: %w", err)
	}

	// Store metadata
	metadata := map[string]interface{}{
		"key_name":      cryptoKey.Name,
		"algorithm":     cryptoKey.Primary.Algorithm.String(),
		"purpose":       cryptoKey.Purpose.String(),
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType,
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_GCPKMS,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(b.config.KeyStorage, attrs.ID(), metadataBytes); err != nil {
			return nil, fmt.Errorf("failed to save metadata: %w", err)
		}
	}

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

	// Return a reference key (key material stays in GCP KMS)
	return &gcpKMSSymmetricKey{
		keyName:   cryptoKey.Name,
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   256,
	}, nil
}

// GetSymmetricKey retrieves an existing symmetric key from GCP KMS.
//
// This verifies the key exists and returns a SymmetricKey reference.
// The actual key material remains in GCP KMS and cannot be extracted.
func (b *Backend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	if err := attrs.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", backend.ErrInvalidAttributes, err)
	}

	if !attrs.IsSymmetric() {
		return nil, fmt.Errorf("%w: attributes specify asymmetric algorithm %s", backend.ErrInvalidKeyType, attrs.KeyAlgorithm)
	}

	ctx := context.Background()
	keyName := b.cryptoKeyName(attrs.CN)

	cryptoKey, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: keyName,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get key: %v", backend.ErrKeyNotFound, err)
	}

	// Verify this is a symmetric encryption key
	if cryptoKey.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return nil, fmt.Errorf("%w: key is not a symmetric encryption key, purpose is %s", backend.ErrInvalidKeyType, cryptoKey.Purpose)
	}

	return &gcpKMSSymmetricKey{
		keyName:   cryptoKey.Name,
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   256, // GCP KMS only supports AES-256
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter for the specified symmetric key.
//
// The encrypter uses GCP KMS APIs for all encryption/decryption operations,
// ensuring the key material never leaves GCP infrastructure.
func (b *Backend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	// Verify key exists
	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		return nil, err
	}

	gcpKey, ok := key.(*gcpKMSSymmetricKey)
	if !ok {
		return nil, backend.ErrInvalidKeyType
	}

	return &gcpKMSSymmetricEncrypter{
		backend: b,
		keyName: gcpKey.keyName,
		attrs:   attrs,
	}, nil
}

// Signer returns a crypto.Signer for the specified key.
func (b *Backend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	// Get the public key to create the signer
	ctx := context.Background()
	keyName := b.cryptoKeyVersionName(attrs.CN)

	req := &kmspb.GetPublicKeyRequest{
		Name: keyName,
	}

	pubKey, err := b.client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", backend.ErrKeyNotFound, attrs.CN, err)
	}

	// Parse the PEM-encoded public key
	publicKey, err := parsePublicKey(pubKey.Pem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &kmsSigner{
		backend:   b,
		keyName:   keyName,
		publicKey: publicKey,
		attrs:     attrs,
	}, nil
}

// Sign performs an asymmetric signing operation using GCP KMS.
func (b *Backend) Sign(attrs *types.KeyAttributes, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	if len(digest) == 0 {
		return nil, fmt.Errorf("%w: digest is empty", backend.ErrInvalidAttributes)
	}

	ctx := context.Background()
	keyName := b.cryptoKeyVersionName(attrs.CN)

	// Build the digest structure based on the hash algorithm
	var digestMsg *kmspb.Digest
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			digestMsg = &kmspb.Digest{
				Digest: &kmspb.Digest_Sha256{Sha256: digest},
			}
		case crypto.SHA384:
			digestMsg = &kmspb.Digest{
				Digest: &kmspb.Digest_Sha384{Sha384: digest},
			}
		case crypto.SHA512:
			digestMsg = &kmspb.Digest{
				Digest: &kmspb.Digest_Sha512{Sha512: digest},
			}
		default:
			return nil, fmt.Errorf("%w: unsupported hash algorithm %v", backend.ErrInvalidAlgorithm, opts.HashFunc())
		}
	} else {
		// Default to SHA256
		digestMsg = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digest},
		}
	}

	req := &kmspb.AsymmetricSignRequest{
		Name:   keyName,
		Digest: digestMsg,
	}

	// Add digest CRC32C checksum for data integrity
	if digestMsg != nil {
		req.DigestCrc32C = wrapperspb.Int64(int64(crc32c(digest)))
	}

	resp, err := b.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Verify the response checksum
	if resp.SignatureCrc32C != nil && resp.SignatureCrc32C.Value != int64(crc32c(resp.Signature)) {
		return nil, fmt.Errorf("signature checksum mismatch")
	}

	return resp.Signature, nil
}

// Verify verifies a signature using the public key from GCP KMS.
func (b *Backend) Verify(attrs *types.KeyAttributes, digest, signature []byte) error {
	if len(digest) == 0 {
		return fmt.Errorf("%w: digest is empty", backend.ErrInvalidAttributes)
	}

	if len(signature) == 0 {
		return fmt.Errorf("%w: signature is empty", backend.ErrInvalidAttributes)
	}

	// Get the public key
	pubKeyPEM, err := b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	publicKey, err := parsePublicKey(string(pubKeyPEM))
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Determine the hash algorithm to use (default to SHA256)
	hash := attrs.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}

	// Map backend hash to crypto.Hash
	var cryptoHash crypto.Hash
	switch hash {
	case crypto.SHA256:
		cryptoHash = crypto.SHA256
	case crypto.SHA384:
		cryptoHash = crypto.SHA384
	case crypto.SHA512:
		cryptoHash = crypto.SHA512
	default:
		return fmt.Errorf("%w: unsupported hash algorithm %s", backend.ErrInvalidAlgorithm, hash)
	}

	// Verify based on key type
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		// RSA verification
		return rsa.VerifyPKCS1v15(pub, cryptoHash, digest, signature)
	case *ecdsa.PublicKey:
		// ECDSA verification
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("%w: signature verification failed", backend.ErrInvalidAttributes)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown public key type", backend.ErrInvalidKeyType)
	}
}

// GetKey retrieves an existing private key by its attributes.
// For GCP KMS, this verifies the key exists and returns nil for private key.
func (b *Backend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	// Check if metadata exists
	if b.config.KeyStorage != nil {
		_, err := storage.GetKey(b.config.KeyStorage, attrs.ID())
		if err != nil {
			return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
		}
	}

	// Verify key exists in KMS
	ctx := context.Background()
	keyName := b.cryptoKeyName(attrs.CN)

	_, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: keyName,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get key: %v", backend.ErrKeyNotFound, err)
	}

	// Return nil for private key since it's not extractable from KMS
	// Callers should use Signer() or Decrypter() instead
	return nil, nil
}

// GetSignerByID retrieves a crypto.Signer for the specified key by name.
func (b *Backend) GetSignerByID(keyID string) (crypto.Signer, error) {
	attrs := &types.KeyAttributes{
		CN:        keyID,
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: backend.STORE_GCPKMS,
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
		StoreType: backend.STORE_GCPKMS,
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
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	// Remove metadata
	if b.config.KeyStorage != nil {
		if err := storage.DeleteKey(b.config.KeyStorage, attrs.ID()); err != nil {
			// Continue even if metadata deletion fails
			// The key may not have metadata stored
		}
	}

	// Delegate to existing Delete method
	return b.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *Backend) ListKeys() ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	ctx := context.Background()

	// List all crypto keys from GCP KMS
	req := &kmspb.ListCryptoKeysRequest{
		Parent: b.config.KeyRingName(),
	}

	keys, err := b.client.ListCryptoKeys(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to list crypto keys: %w", err)
	}

	var allKeys []*types.KeyAttributes

	// Reconstruct KeyAttributes for each key
	for _, key := range keys {
		// Extract key ID from the full name
		// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{keyId}
		parts := splitKeyName(key.Name)
		if len(parts) == 0 {
			continue
		}
		keyID := parts[len(parts)-1]

		attrs := &types.KeyAttributes{
			CN:        keyID,
			StoreType: backend.STORE_GCPKMS,
		}

		// Try to load metadata to get additional attributes
		if b.config.KeyStorage != nil {
			metadataBytes, err := storage.GetKey(b.config.KeyStorage, attrs.ID())
			if err == nil {
				var metadata map[string]interface{}
				if err := json.Unmarshal(metadataBytes, &metadata); err == nil {
					// Extract key type
					if keyTypeStr, ok := metadata["key_type"].(string); ok {
						attrs.KeyType = types.ParseKeyType(keyTypeStr)
					}
					// Extract key algorithm - stored as x509.PublicKeyAlgorithm int
					if keyAlgFloat, ok := metadata["key_algorithm"].(float64); ok {
						attrs.KeyAlgorithm = x509.PublicKeyAlgorithm(keyAlgFloat)
					}
				}
			}
		}

		// If metadata is not available, infer from KMS key properties
		if attrs.KeyAlgorithm == 0 && key.Primary != nil {
			switch key.Primary.Algorithm {
			case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
				kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256,
				kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
				kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
				kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
				attrs.KeyAlgorithm = x509.RSA
			case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
				kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
				attrs.KeyAlgorithm = x509.ECDSA
			}
		}

		if attrs.KeyType == 0 {
			switch key.Purpose {
			case kmspb.CryptoKey_ASYMMETRIC_SIGN:
				attrs.KeyType = backend.KEY_TYPE_SIGNING
			case kmspb.CryptoKey_ASYMMETRIC_DECRYPT:
				attrs.KeyType = backend.KEY_TYPE_ENCRYPTION
			case kmspb.CryptoKey_ENCRYPT_DECRYPT:
				attrs.KeyType = backend.KEY_TYPE_ENCRYPTION
			}
		}

		allKeys = append(allKeys, attrs)
	}

	return allKeys, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (b *Backend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	// Only RSA keys with ASYMMETRIC_DECRYPT purpose support decryption
	if attrs.KeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("%w: only RSA keys support decryption in GCP KMS", backend.ErrOperationNotSupported)
	}

	// Get the public key to verify the key exists and get key details
	ctx := context.Background()
	keyName := b.cryptoKeyVersionName(attrs.CN)

	req := &kmspb.GetPublicKeyRequest{
		Name: keyName,
	}

	pubKey, err := b.client.GetPublicKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", backend.ErrKeyNotFound, attrs.CN, err)
	}

	// Verify the key supports decryption
	switch pubKey.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1,
		kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1:
		// Valid decryption algorithm
	default:
		return nil, fmt.Errorf("%w: key does not support decryption, algorithm is %s", backend.ErrOperationNotSupported, pubKey.Algorithm)
	}

	// Parse the PEM-encoded public key
	publicKey, err := parsePublicKey(pubKey.Pem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &kmsDecrypter{
		backend:   b,
		keyName:   keyName,
		publicKey: publicKey,
		attrs:     attrs,
	}, nil
}

// RotateKey rotates/updates a key identified by attrs.
// For GCP KMS, this creates a new key version and sets it as primary.
func (b *Backend) RotateKey(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return ErrNotInitialized
	}

	ctx := context.Background()
	keyName := b.cryptoKeyName(attrs.CN)

	// Create a new crypto key version
	createReq := &kmspb.CreateCryptoKeyVersionRequest{
		Parent: keyName,
		CryptoKeyVersion: &kmspb.CryptoKeyVersion{
			State: kmspb.CryptoKeyVersion_ENABLED,
		},
	}

	newVersion, err := b.client.CreateCryptoKeyVersion(ctx, createReq)
	if err != nil {
		return fmt.Errorf("failed to create new key version: %w", err)
	}

	// Set the new version as primary
	updateReq := &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
		Name:               keyName,
		CryptoKeyVersionId: extractVersionID(newVersion.Name),
	}

	_, err = b.client.UpdateCryptoKeyPrimaryVersion(ctx, updateReq)
	if err != nil {
		return fmt.Errorf("failed to set new version as primary: %w", err)
	}

	// Reset AEAD tracking after successful rotation
	if b.tracker != nil && attrs.IsSymmetric() {
		trackingKeyID := attrs.ID()
		if err := b.tracker.ResetTracking(trackingKeyID); err != nil {
			// Log but don't fail the rotation - tracking reset is not critical
			// The rotation has already succeeded in GCP KMS
			fmt.Printf("warning: failed to reset AEAD tracking after key rotation: %v\n", err)
		}
	}

	return nil
}

// Client returns the underlying KMS client (for testing purposes).
func (b *Backend) Client() KMSClient {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.client
}

// cryptoKeyVersionName constructs the full resource name for a crypto key version.
// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/1
func (b *Backend) cryptoKeyVersionName(keyID string) string {
	return fmt.Sprintf("%s/cryptoKeys/%s/cryptoKeyVersions/1",
		b.config.KeyRingName(), keyID)
}

// cryptoKeyName constructs the full resource name for a crypto key.
// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}
func (b *Backend) cryptoKeyName(keyID string) string {
	return fmt.Sprintf("%s/cryptoKeys/%s", b.config.KeyRingName(), keyID)
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(pemData string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pub, nil
}

// crc32c computes the CRC32C checksum used by GCP KMS for data integrity.
// Uses the Castagnoli polynomial as required by GCP KMS.
func crc32c(data []byte) uint32 {
	crc32cTable := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, crc32cTable)
}

// kmsSigner implements crypto.Signer for GCP KMS keys.
type kmsSigner struct {
	backend   *Backend
	keyName   string
	publicKey crypto.PublicKey
	attrs     *types.KeyAttributes
}

// Public returns the public key for this signer.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest using GCP KMS.
func (s *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.backend.Sign(s.attrs, digest, opts)
}

// kmsDecrypter implements crypto.Decrypter for GCP KMS keys.
type kmsDecrypter struct {
	backend   *Backend
	keyName   string
	publicKey crypto.PublicKey
	attrs     *types.KeyAttributes
}

// Public returns the public key for this decrypter.
func (d *kmsDecrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// Decrypt decrypts the ciphertext using GCP KMS.
func (d *kmsDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	d.backend.mu.RLock()
	defer d.backend.mu.RUnlock()

	if d.backend.client == nil {
		return nil, ErrNotInitialized
	}

	ctx := context.Background()

	req := &kmspb.AsymmetricDecryptRequest{
		Name:       d.keyName,
		Ciphertext: ciphertext,
	}

	// Add ciphertext CRC32C checksum for data integrity
	req.CiphertextCrc32C = wrapperspb.Int64(int64(crc32c(ciphertext)))

	resp, err := d.backend.client.AsymmetricDecrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Verify the response checksum
	if resp.PlaintextCrc32C != nil && resp.PlaintextCrc32C.Value != int64(crc32c(resp.Plaintext)) {
		return nil, fmt.Errorf("plaintext checksum mismatch")
	}

	return resp.Plaintext, nil
}

// mapCurveToAlgorithm maps an elliptic curve to a GCP KMS algorithm.
func mapCurveToAlgorithm(curve elliptic.Curve) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	switch curve.Params().Name {
	case "P-256":
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil
	case "P-384":
		return kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, nil
	default:
		return 0, fmt.Errorf("%w: unsupported curve %s", backend.ErrInvalidKeyType, curve.Params().Name)
	}
}

// splitKeyName splits a GCP KMS resource name into its component parts.
// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{keyId}
func splitKeyName(name string) []string {
	if name == "" {
		return nil
	}
	parts := []string{}
	current := ""
	for _, part := range name {
		if part == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(part)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// extractVersionID extracts the version ID from a crypto key version resource name.
// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}/cryptoKeyVersions/{version}
func extractVersionID(name string) string {
	parts := splitKeyName(name)
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// gcpKMSSymmetricKey implements types.SymmetricKey for GCP KMS symmetric keys.
// The key material never leaves GCP KMS infrastructure.
type gcpKMSSymmetricKey struct {
	keyName   string
	algorithm string
	keySize   int
}

func (k *gcpKMSSymmetricKey) Algorithm() string {
	return k.algorithm
}

func (k *gcpKMSSymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns an error because GCP KMS keys cannot expose raw key material.
// The key material stays in GCP KMS and can only be used through KMS operations.
func (k *gcpKMSSymmetricKey) Raw() ([]byte, error) {
	return nil, fmt.Errorf("GCP KMS symmetric keys do not expose raw key material: %w", backend.ErrNotSupported)
}

// gcpKMSSymmetricEncrypter implements types.SymmetricEncrypter for GCP KMS.
// All encryption/decryption operations are performed within GCP KMS.
type gcpKMSSymmetricEncrypter struct {
	backend *Backend
	keyName string
	attrs   *types.KeyAttributes
}

// Encrypt encrypts plaintext using GCP KMS symmetric encryption.
// The encryption is performed entirely within GCP KMS infrastructure.
//
// AEAD Safety Tracking:
//  1. Checks bytes limit before encryption (prevents exceeding NIST limits)
//  2. GCP KMS manages nonce generation internally (no client-side nonce tracking needed)
//  3. Performs encryption in GCP KMS
//
// Note: Nonce reuse tracking is not applicable since GCP KMS manages nonces server-side.
// Only bytes encrypted tracking is performed to enforce NIST cryptographic limits.
func (e *gcpKMSSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	e.backend.mu.RLock()
	defer e.backend.mu.RUnlock()

	if e.backend.client == nil {
		return nil, ErrNotInitialized
	}

	// Get key ID for tracking
	keyID := e.attrs.ID()

	// STEP 1: Check bytes limit before encryption
	if e.backend.tracker != nil {
		if err := e.backend.tracker.IncrementBytes(keyID, int64(len(plaintext))); err != nil {
			return nil, fmt.Errorf("AEAD safety check failed: %w (consider rotating this key)", err)
		}
	}

	ctx := context.Background()

	req := &kmspb.EncryptRequest{
		Name:      e.keyName,
		Plaintext: plaintext,
	}

	// Add additional authenticated data if provided
	if opts != nil && opts.AdditionalData != nil {
		// GCP KMS uses AdditionalAuthenticatedData field
		req.AdditionalAuthenticatedData = opts.AdditionalData
	}

	// Add plaintext CRC32C checksum for data integrity
	req.PlaintextCrc32C = wrapperspb.Int64(int64(crc32c(plaintext)))

	resp, err := e.backend.client.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS encryption failed: %w", err)
	}

	// Verify the response checksum
	if resp.CiphertextCrc32C != nil && resp.CiphertextCrc32C.Value != int64(crc32c(resp.Ciphertext)) {
		return nil, fmt.Errorf("ciphertext checksum mismatch")
	}

	// GCP KMS returns a single ciphertext blob that includes nonce and tag
	// We store it as-is in Ciphertext field
	return &types.EncryptedData{
		Ciphertext: resp.Ciphertext,
		Nonce:      nil, // GCP KMS manages nonce internally
		Tag:        nil, // GCP KMS manages tag internally
		Algorithm:  string(e.attrs.SymmetricAlgorithm),
	}, nil
}

// Decrypt decrypts ciphertext using GCP KMS symmetric decryption.
// The decryption is performed entirely within GCP KMS infrastructure.
func (e *gcpKMSSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	e.backend.mu.RLock()
	defer e.backend.mu.RUnlock()

	if e.backend.client == nil {
		return nil, ErrNotInitialized
	}

	ctx := context.Background()

	req := &kmspb.DecryptRequest{
		Name:       e.keyName,
		Ciphertext: data.Ciphertext,
	}

	// Add additional authenticated data if provided
	if opts != nil && opts.AdditionalData != nil {
		req.AdditionalAuthenticatedData = opts.AdditionalData
	}

	// Add ciphertext CRC32C checksum for data integrity
	req.CiphertextCrc32C = wrapperspb.Int64(int64(crc32c(data.Ciphertext)))

	resp, err := e.backend.client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS decryption failed: %w", err)
	}

	// Verify the response checksum
	if resp.PlaintextCrc32C != nil && resp.PlaintextCrc32C.Value != int64(crc32c(resp.Plaintext)) {
		return nil, fmt.Errorf("plaintext checksum mismatch")
	}

	return resp.Plaintext, nil
}

// Verify interface compliance at compile time
var _ types.SymmetricBackend = (*Backend)(nil)
var _ types.SymmetricKey = (*gcpKMSSymmetricKey)(nil)
var _ types.SymmetricEncrypter = (*gcpKMSSymmetricEncrypter)(nil)
