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
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// KMSClient defines the interface for GCP KMS operations.
// This interface allows for mocking in tests. It lists exactly the
// operations Backend calls; GetImportJob was removed (go-xkms#705) because
// no Backend method ever called it -- an unused interface method can only
// be covered by a test that calls it directly with no Backend behavior to
// assert, which is coverage padding, not a real test.
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

func (r *realKMSClient) ImportCryptoKeyVersion(ctx context.Context, req *kmspb.ImportCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
	return r.KeyManagementClient.ImportCryptoKeyVersion(ctx, req)
}

// Backend implements the types.KeyProvider interface using Google Cloud KMS.
type Backend struct {
	config  *Config
	client  KMSClient
	tracker types.AEADSafetyTracker // AEAD safety tracker for nonce/bytes tracking
	mu      sync.RWMutex

	// versionCache maps a key's CN to the full resource name of its current
	// primary crypto key version. It is populated lazily by
	// resolvePrimaryVersionName and kept current by RotateKey and by key
	// creation, so sign/decrypt/public-key operations track rotations
	// instead of remaining pinned to the version created at generation
	// time. Signers and Decrypters capture the resolved name at
	// construction and never consult this cache again, so they stay
	// pinned to the version whose public key they reported.
	versionCache sync.Map

	types.KeyProvider
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
		opts = append(opts, option.WithCredentialsJSON(config.CredentialsJSON)) //nolint:staticcheck // SA1019: Config.CredentialsJSON is a supported knob of this backend's own API; switching the underlying client-auth mechanism is a separate, behavior-sensitive change
	} else if config.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(config.CredentialsFile)) //nolint:staticcheck // SA1019: Config.CredentialsFile is a supported knob of this backend's own API; see CredentialsJSON above
	}

	// Add custom endpoint if provided (for testing with emulator)
	if config.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(config.Endpoint))
	}

	// Plaintext gRPC without authentication, for local emulators only.
	// Validate() rejects Insecure without a custom Endpoint.
	if config.Insecure {
		opts = append(opts,
			option.WithoutAuthentication(),
			option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials()))) // insecure-ok: explicit Config.Insecure, gated to a custom Endpoint (local emulator only) by Validate(). Allowlisted in Makefile check-insecure-tls.
	}

	// Create KMS client
	kmsClient, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create KMS client", Err: err}
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
// SecurityLevel is Medium - keys are protected by cloud HSMs but network-dependent.
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
		SecurityLevel:       types.SecurityLevelMedium,
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
	keyName, err := b.resolvePrimaryVersionName(ctx, attrs.CN)
	if err != nil {
		return nil, err
	}

	req := &kmspb.GetPublicKeyRequest{
		Name: keyName,
	}

	// Only a gRPC NotFound status -- Cloud KMS's signal that the key version
	// genuinely does not exist -- is reported as ErrKeyNotFound. Any other
	// failure (throttling, a transport fault, an IAM/authorization denial)
	// must not be conflated with "no key yet" (matches GetKey's
	// classification).
	pubKey, err := b.client.GetPublicKey(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
	}

	// Return PEM-encoded public key
	return []byte(pubKey.Pem), nil
}

// Save is not supported for GCP KMS as keys are managed by GCP.
// Use GenerateKey methods to create keys in KMS.
func (b *Backend) Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error {
	return &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: "cannot save data to GCP KMS, use GenerateKey methods"}
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
	keyName, err := b.resolvePrimaryVersionName(ctx, attrs.CN)
	if err != nil {
		return err
	}

	req := &kmspb.DestroyCryptoKeyVersionRequest{
		Name: keyName,
	}

	_, err = b.client.DestroyCryptoKeyVersion(ctx, req)
	if err != nil {
		return &errs.Wrapped{Msg: fmt.Sprintf("failed to destroy key %s", attrs.CN), Err: err}
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
			return &errs.Wrapped{Msg: "failed to get key version status", Err: err}
		}

		if version.State == kmspb.CryptoKeyVersion_ENABLED {
			return nil
		}

		if version.State != kmspb.CryptoKeyVersion_PENDING_GENERATION {
			return &errs.Message{Msg: fmt.Sprintf("key version in unexpected state: %s", version.State.String())}
		}

		time.Sleep(pollInterval)
	}

	return &errs.Message{Msg: fmt.Sprintf("timeout waiting for key to be enabled after %v", timeout)}
}

// GenerateKey generates a new private key with the given attributes.
// For GCP KMS, this creates a new KMS key and stores metadata.
// Returns nil for private key since it's not extractable from KMS.
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	var err error
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		_, err = b.GenerateRSA(ctx, attrs)
	case x509.ECDSA:
		_, err = b.GenerateECDSA(ctx, attrs)
	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: attrs.KeyAlgorithm.String()}
	}

	if err != nil {
		return nil, err
	}

	// Return nil for private key since it's not extractable from KMS
	// Callers should use Signer() or Decrypter() instead
	return nil, nil
}

// GenerateRSA creates a new RSA signing key in GCP KMS.
func (b *Backend) GenerateRSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
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
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("unsupported RSA key size %d", keySize)}
	}

	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      b.config.KeyRingName(),
		CryptoKeyId: attrs.CN,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
			Labels: map[string]string{
				"created-by": "go-xkms",
			},
		},
	}

	cryptoKey, err := b.client.CreateCryptoKey(ctx, req)
	if err != nil {
		b.mu.Unlock()
		return nil, &errs.Wrapped{Msg: "failed to create RSA key", Err: err}
	}

	// Wait for the key to be enabled (GCP KMS keys start in PENDING_GENERATION state).
	// A freshly created key's primary version is version 1, reported directly
	// on the CreateCryptoKey response, so cache it rather than re-deriving a
	// hardcoded name.
	if cryptoKey.Primary == nil || cryptoKey.Primary.Name == "" {
		b.mu.Unlock()
		return nil, &errs.Detail{Err: ErrNoPrimaryVersion, Detail: attrs.CN}
	}
	keyVersionName := cryptoKey.Primary.Name
	if err := b.waitForKeyEnabled(ctx, keyVersionName, 30*time.Second); err != nil {
		b.mu.Unlock()
		return nil, &errs.Wrapped{Msg: "key creation failed", Err: err}
	}
	b.versionCache.Store(attrs.CN, keyVersionName)

	// Store metadata
	metadata := map[string]interface{}{
		"key_name":      cryptoKey.Name,
		"algorithm":     algorithm.String(),
		"purpose":       cryptoKey.Purpose.String(),
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType.String(), // see ListKeys: read back via types.ParseKeyType (go-xkms#705)
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_GCPKMS,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		b.mu.Unlock()
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
			b.mu.Unlock()
			return nil, &errs.Wrapped{Msg: "failed to save metadata", Err: err}
		}
	}

	b.mu.Unlock() // Release lock before calling Signer
	return b.Signer(ctx, attrs)
}

// GenerateECDSA creates a new ECDSA signing key in GCP KMS.
func (b *Backend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
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
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("unsupported curve %s", curve)}
	}

	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      b.config.KeyRingName(),
		CryptoKeyId: attrs.CN,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: algorithm,
			},
			Labels: map[string]string{
				"created-by": "go-xkms",
			},
		},
	}

	cryptoKey, err := b.client.CreateCryptoKey(ctx, req)
	if err != nil {
		b.mu.Unlock()
		return nil, &errs.Wrapped{Msg: "failed to create ECDSA key", Err: err}
	}

	// Wait for the key to be enabled (GCP KMS keys start in PENDING_GENERATION state).
	// A freshly created key's primary version is version 1, reported directly
	// on the CreateCryptoKey response, so cache it rather than re-deriving a
	// hardcoded name.
	if cryptoKey.Primary == nil || cryptoKey.Primary.Name == "" {
		b.mu.Unlock()
		return nil, &errs.Detail{Err: ErrNoPrimaryVersion, Detail: attrs.CN}
	}
	keyVersionName := cryptoKey.Primary.Name
	if err := b.waitForKeyEnabled(ctx, keyVersionName, 30*time.Second); err != nil {
		b.mu.Unlock()
		return nil, &errs.Wrapped{Msg: "key creation failed", Err: err}
	}
	b.versionCache.Store(attrs.CN, keyVersionName)

	// Store metadata
	metadata := map[string]interface{}{
		"key_name":      cryptoKey.Name,
		"algorithm":     algorithm.String(),
		"purpose":       cryptoKey.Purpose.String(),
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType.String(), // see ListKeys: read back via types.ParseKeyType (go-xkms#705)
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_GCPKMS,
		"curve":         curve,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		b.mu.Unlock()
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
			b.mu.Unlock()
			return nil, &errs.Wrapped{Msg: "failed to save metadata", Err: err}
		}
	}

	b.mu.Unlock() // Release lock before calling Signer
	return b.Signer(ctx, attrs)
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
func (b *Backend) GenerateSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("attributes specify asymmetric algorithm %s", attrs.KeyAlgorithm)}
	}

	// GCP KMS only supports 256-bit symmetric keys
	if attrs.SymmetricAlgorithm.KeySize() != 256 {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("GCP KMS only supports AES-256 symmetric keys, got %d-bit", attrs.SymmetricAlgorithm.KeySize())}
	}

	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      b.config.KeyRingName(),
		CryptoKeyId: attrs.CN,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
			Labels: map[string]string{
				"created-by":    "go-xkms",
				"key-type":      string(attrs.KeyType),
				"key-algorithm": string(attrs.SymmetricAlgorithm),
			},
		},
	}

	cryptoKey, err := b.client.CreateCryptoKey(ctx, req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create symmetric key", Err: err}
	}

	// Wait for the key to be enabled (GCP KMS keys start in PENDING_GENERATION state).
	// A freshly created key's primary version is version 1, reported directly
	// on the CreateCryptoKey response, so use it rather than re-deriving a
	// hardcoded name.
	if cryptoKey.Primary == nil || cryptoKey.Primary.Name == "" {
		return nil, &errs.Detail{Err: ErrNoPrimaryVersion, Detail: attrs.CN}
	}
	keyVersionName := cryptoKey.Primary.Name
	if err := b.waitForKeyEnabled(ctx, keyVersionName, 30*time.Second); err != nil {
		return nil, &errs.Wrapped{Msg: "key creation failed", Err: err}
	}

	// Store metadata
	metadata := map[string]interface{}{
		"key_name":      cryptoKey.Name,
		"algorithm":     cryptoKey.Primary.Algorithm.String(),
		"purpose":       cryptoKey.Purpose.String(),
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType.String(), // see ListKeys: read back via types.ParseKeyType (go-xkms#705)
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_GCPKMS,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
			return nil, &errs.Wrapped{Msg: "failed to save metadata", Err: err}
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
func (b *Backend) GetSymmetricKey(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}

	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("attributes specify asymmetric algorithm %s", attrs.KeyAlgorithm)}
	}

	keyName := b.cryptoKeyName(attrs.CN)

	// Only a gRPC NotFound status -- Cloud KMS's signal that the crypto key
	// resource genuinely does not exist -- is reported as ErrKeyNotFound.
	// Any other failure (throttling, a transport fault, an IAM/authorization
	// denial) must not be conflated with "no key yet" (matches GetKey's
	// classification).
	cryptoKey, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: keyName,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("failed to get key: %v", err)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("failed to get key: %v", err)}
	}

	// Verify this is a symmetric encryption key
	if cryptoKey.Purpose != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("key is not a symmetric encryption key, purpose is %s", cryptoKey.Purpose)}
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
func (b *Backend) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	// Verify key exists
	key, err := b.GetSymmetricKey(ctx, attrs)
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
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	// Resolve the current primary key version and pin the signer to it, so
	// Public() always matches the exact version Sign() uses even if the key
	// is rotated later.
	keyName, err := b.resolvePrimaryVersionName(ctx, attrs.CN)
	if err != nil {
		return nil, err
	}

	req := &kmspb.GetPublicKeyRequest{
		Name: keyName,
	}

	// Only a gRPC NotFound status is reported as ErrKeyNotFound; any other
	// failure must not be conflated with "no key yet" (matches GetKey's
	// classification).
	pubKey, err := b.client.GetPublicKey(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
	}

	// Parse the PEM-encoded public key
	publicKey, err := parsePublicKey(pubKey.Pem)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
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
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "digest is empty"}
	}

	ctx := context.Background()
	keyName, err := b.resolvePrimaryVersionName(ctx, attrs.CN)
	if err != nil {
		return nil, err
	}

	return b.signWithVersion(ctx, keyName, digest, opts)
}

// signWithVersion performs an asymmetric signing operation against an
// already-resolved GCP KMS crypto key version resource name. Callers that
// must stay pinned to a specific version (e.g. kmsSigner, which reports a
// Public() key resolved at construction time) call this directly instead of
// going through Sign, which always re-resolves the current primary version.
func (b *Backend) signWithVersion(ctx context.Context, keyName string, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
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
			return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported hash algorithm %v", opts.HashFunc())}
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

	// Add digest CRC32C checksum for data integrity. digestMsg is always
	// non-nil here: every path through the switch above either sets it or
	// returns (SA4031).
	req.DigestCrc32C = wrapperspb.Int64(int64(crc32c(digest)))

	resp, err := b.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to sign", Err: err}
	}

	// Verify the response checksum
	if resp.SignatureCrc32C != nil && resp.SignatureCrc32C.Value != int64(crc32c(resp.Signature)) {
		return nil, &errs.Message{Msg: "signature checksum mismatch"}
	}

	return resp.Signature, nil
}

// Verify verifies a signature using the public key from GCP KMS.
func (b *Backend) Verify(attrs *types.KeyAttributes, digest, signature []byte) error {
	if len(digest) == 0 {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "digest is empty"}
	}

	if len(signature) == 0 {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "signature is empty"}
	}

	// Get the public key
	pubKeyPEM, err := b.Get(attrs, backend.FSEXT_PUBLIC_PEM)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to get public key", Err: err}
	}

	publicKey, err := parsePublicKey(string(pubKeyPEM))
	if err != nil {
		return &errs.Wrapped{Msg: "failed to parse public key", Err: err}
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
		return &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported hash algorithm %s", hash)}
	}

	// Verify based on key type
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		// RSA verification
		return rsa.VerifyPKCS1v15(pub, cryptoHash, digest, signature)
	case *ecdsa.PublicKey:
		// ECDSA verification
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "signature verification failed"}
		}
		return nil
	default:
		return &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "unknown public key type"}
	}
}

// GetKey retrieves an existing private key by its attributes.
// For GCP KMS, this verifies the key exists and returns nil for private key.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	// Check if metadata exists. Keyed by CN alone, not attrs.ID() (which
	// also folds in KeyType and KeyAlgorithm): GetSignerByID, GetDecrypterByID
	// and ListKeys all reach this path with a KeyAttributes that has only CN
	// (and sometimes KeyType) set -- ListKeys in particular is reading this
	// same metadata specifically to learn KeyAlgorithm, so an ID() keyed on
	// KeyAlgorithm can never be computed by the reader in the first place.
	// Every write site in this package (GenerateRSA, GenerateECDSA,
	// GenerateSymmetricKey, ImportKey) persists under attrs.CN for the same
	// reason (go-xkms#705).
	// Only a genuine storage.ErrNotFound is reported as ErrKeyNotFound; any
	// other failure from the metadata store (I/O error, unavailable backend)
	// must not be conflated with "no key yet".
	if b.config.KeyStorage != nil {
		_, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: attrs.CN}
			}
			return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("metadata lookup for %s: %v", attrs.CN, err)}
		}
	}

	// Verify key exists in KMS. Only a gRPC NotFound status -- Cloud KMS's
	// signal that the crypto key resource genuinely does not exist -- is
	// reported as ErrKeyNotFound. Any other failure (throttling, a
	// transport fault, an IAM/authorization denial) must not be conflated
	// with "no key yet": getOrGenerateCAKey relies on that distinction to
	// decide whether generating a replacement key is safe.
	keyName := b.cryptoKeyName(attrs.CN)

	_, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: keyName,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("failed to get key: %v", err)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("failed to get key: %v", err)}
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
		StoreType: backend.STORE_GCPKMS,
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
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	// Remove metadata. Best-effort: the key may not have metadata stored,
	// and Delete below is the operation that must succeed.
	if b.config.KeyStorage != nil {
		_ = storage.DeleteKey(ctx, b.config.KeyStorage, attrs.CN) // best-effort metadata cleanup; see comment above -- the explicit `_ =` already satisfies errcheck
	}

	// Delegate to existing Delete method
	return b.Delete(attrs)
}

// ListKeys returns attributes for all keys managed by this backend.
func (b *Backend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	// List all crypto keys from GCP KMS
	req := &kmspb.ListCryptoKeysRequest{
		Parent: b.config.KeyRingName(),
	}

	keys, err := b.client.ListCryptoKeys(ctx, req)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to list crypto keys", Err: err}
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
			metadataBytes, err := storage.GetKey(ctx, b.config.KeyStorage, attrs.CN)
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

		// Exportable is unconditionally false and Sensitive is unconditionally
		// true for every key this backend enumerates (go-xkms#932).
		// Capabilities().Export is false unconditionally, and
		// ExportKey/ExportKeyMaterial (gcpkms_importexport.go) both refuse
		// every key with backend.ErrExportNotSupported regardless of policy:
		// GCP KMS exposes no API to release private key material for any
		// protection level or import method, so Exportable=true would be a
		// promise this backend cannot keep for any key it manages.
		attrs.Exportable = false
		attrs.Sensitive = true

		allKeys = append(allKeys, attrs)
	}

	return allKeys, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
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
		return nil, &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: "only RSA keys support decryption in GCP KMS"}
	}

	// Resolve the current primary key version and pin the decrypter to it,
	// so Public() always matches the exact version Decrypt() uses even if
	// the key is rotated later.
	keyName, err := b.resolvePrimaryVersionName(ctx, attrs.CN)
	if err != nil {
		return nil, err
	}

	req := &kmspb.GetPublicKeyRequest{
		Name: keyName,
	}

	// Only a gRPC NotFound status is reported as ErrKeyNotFound; any other
	// failure must not be conflated with "no key yet" (matches GetKey's
	// classification).
	pubKey, err := b.client.GetPublicKey(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
		}
		return nil, &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", attrs.CN, err)}
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
		return nil, &errs.Detail{Err: backend.ErrOperationNotSupported, Detail: fmt.Sprintf("key does not support decryption, algorithm is %s", pubKey.Algorithm)}
	}

	// Parse the PEM-encoded public key
	publicKey, err := parsePublicKey(pubKey.Pem)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
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
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return ErrNotInitialized
	}

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
		return &errs.Wrapped{Msg: "failed to create new key version", Err: err}
	}

	// Set the new version as primary
	updateReq := &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
		Name:               keyName,
		CryptoKeyVersionId: extractVersionID(newVersion.Name),
	}

	updatedKey, err := b.client.UpdateCryptoKeyPrimaryVersion(ctx, updateReq)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to set new version as primary", Err: err}
	}

	// Advance the cached primary version immediately so subsequent sign,
	// decrypt, and public-key operations use the newly promoted version
	// instead of the one resolved before rotation. Signers/Decrypters
	// already constructed keep the version name they captured at
	// construction and are unaffected by this update.
	if updatedKey.Primary != nil && updatedKey.Primary.Name != "" {
		b.versionCache.Store(attrs.CN, updatedKey.Primary.Name)
	} else {
		b.versionCache.Store(attrs.CN, newVersion.Name)
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

// resolvePrimaryVersionName resolves the full resource name of keyID's
// current primary crypto key version, consulting a per-key cache before
// calling GetCryptoKey. The cache is populated here and kept current by
// RotateKey (and by key creation, which already knows its own primary
// version), so callers observe rotations instead of a version pinned
// forever at key-creation time.
//
// Callers that must stay pinned to a specific version regardless of later
// rotations (e.g. a previously constructed Signer or Decrypter) must not
// call this method again after construction; they hold the resolved name
// directly instead.
func (b *Backend) resolvePrimaryVersionName(ctx context.Context, keyID string) (string, error) {
	if cached, ok := b.versionCache.Load(keyID); ok {
		return cached.(string), nil
	}

	// Only a gRPC NotFound status -- Cloud KMS's signal that the crypto key
	// resource genuinely does not exist -- is reported as ErrKeyNotFound.
	// Any other failure (throttling, a transport fault, an IAM/authorization
	// denial) must not be conflated with "no key yet" (matches GetKey's
	// classification).
	cryptoKey, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: b.cryptoKeyName(keyID),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return "", &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("%s: %v", keyID, err)}
		}
		return "", &errs.Detail{Err: ErrKeyRetrievalFailed, Detail: fmt.Sprintf("%s: %v", keyID, err)}
	}

	if cryptoKey.Primary == nil || cryptoKey.Primary.Name == "" {
		return "", &errs.Detail{Err: ErrNoPrimaryVersion, Detail: keyID}
	}

	b.versionCache.Store(keyID, cryptoKey.Primary.Name)
	return cryptoKey.Primary.Name, nil
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
		return nil, &errs.Message{Msg: "failed to decode PEM block"}
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
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

// Sign signs the digest using GCP KMS. It always targets the key version
// resolved when this signer was constructed, so the signature is always
// verifiable with the key returned by Public(), even if the key has since
// been rotated to a new primary version.
func (s *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()

	if s.backend.client == nil {
		return nil, ErrNotInitialized
	}

	if len(digest) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "digest is empty"}
	}

	return s.backend.signWithVersion(context.Background(), s.keyName, digest, opts)
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
		return nil, &errs.Wrapped{Msg: "failed to decrypt", Err: err}
	}

	// Verify the response checksum
	if resp.PlaintextCrc32C != nil && resp.PlaintextCrc32C.Value != int64(crc32c(resp.Plaintext)) {
		return nil, &errs.Message{Msg: "plaintext checksum mismatch"}
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
		return 0, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("unsupported curve %s", curve.Params().Name)}
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
	return nil, &errs.Wrapped{Msg: "GCP KMS symmetric keys do not expose raw key material", Err: backend.ErrNotSupported}
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
	// GCP KMS returns an opaque ciphertext blob and never exposes the
	// authentication tag, so the tag length is not this backend's to choose.
	if opts != nil {
		if err := aead.RequireDefaultTagSize(opts.TagSize, "GCP KMS"); err != nil {
			return nil, err
		}
		// GCP KMS's Encrypt RPC manages nonce generation server-side and
		// exposes no parameter to override it. A caller-supplied nonce used
		// to be accepted here and silently dropped, which let a caller
		// believe its own nonce discipline governed this encryption when GCP
		// KMS's did instead. Refused outright rather than ignored.
		if opts.Nonce != nil {
			return nil, backend.ErrCallerNonceNotSupported
		}
	}

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
			return nil, &errs.Affix{Prefix: "AEAD safety check failed: ", Err: err, Suffix: " (consider rotating this key)"}
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
		return nil, &errs.Wrapped{Msg: "GCP KMS encryption failed", Err: err}
	}

	// Verify the response checksum
	if resp.CiphertextCrc32C != nil && resp.CiphertextCrc32C.Value != int64(crc32c(resp.Ciphertext)) {
		return nil, &errs.Message{Msg: "ciphertext checksum mismatch"}
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
	// See the matching check in Encrypt.
	if opts != nil {
		if err := aead.RequireDefaultTagSize(opts.TagSize, "GCP KMS"); err != nil {
			return nil, err
		}
	}

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
		return nil, &errs.Wrapped{Msg: "GCP KMS decryption failed", Err: err}
	}

	// Verify the response checksum
	if resp.PlaintextCrc32C != nil && resp.PlaintextCrc32C.Value != int64(crc32c(resp.Plaintext)) {
		return nil, &errs.Message{Msg: "plaintext checksum mismatch"}
	}

	return resp.Plaintext, nil
}

// GetTracker returns the AEAD safety tracker for this backend.
// This allows external code to inspect tracking state and configuration.
func (b *Backend) GetTracker() types.AEADSafetyTracker {
	return b.tracker
}

// Verify interface compliance at compile time
var _ types.SymmetricKeyProvider = (*Backend)(nil)
var _ types.SymmetricKeyProviderWithTracking = (*Backend)(nil)
var _ types.SymmetricKey = (*gcpKMSSymmetricKey)(nil)
var _ types.SymmetricEncrypter = (*gcpKMSSymmetricEncrypter)(nil)
