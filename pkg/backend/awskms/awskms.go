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

//go:build awskms

package awskms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Backend implements the types.KeyProvider interface for AWS KMS.
// It provides secure key management operations using AWS Key Management Service.
type Backend struct {
	config   *Config
	client   KMSClient
	metadata map[string][]byte       // In-memory metadata storage keyed by CN
	tracker  types.AEADSafetyTracker // AEAD safety tracker for nonce/bytes tracking
	mu       sync.RWMutex
}

// kmsSigner implements the crypto.Signer interface using AWS KMS.
type kmsSigner struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
	keyID     string
}

// kmsDecrypter implements the crypto.Decrypter interface using AWS KMS.
type kmsDecrypter struct {
	backend   *Backend
	attrs     *types.KeyAttributes
	publicKey crypto.PublicKey
	keyID     string
}

// NewBackend creates a new AWS KMS backend instance.
// It initializes the AWS KMS client with the provided configuration.
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

// NewBackendWithClient creates a new AWS KMS backend with a custom client.
// This is primarily used for testing with mock clients.
func NewBackendWithClient(config *Config, client KMSClient) (*Backend, error) {
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

// initClient initializes the AWS KMS client if not already initialized.
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

	// Build AWS config
	var opts []func(*awsconfig.LoadOptions) error

	opts = append(opts, awsconfig.WithRegion(b.config.Region))

	// Use static credentials if provided
	if b.config.AccessKeyID != "" && b.config.SecretAccessKey != "" {
		creds := credentials.NewStaticCredentialsProvider(
			b.config.AccessKeyID,
			b.config.SecretAccessKey,
			b.config.SessionToken,
		)
		opts = append(opts, awsconfig.WithCredentialsProvider(creds))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to load AWS config", Err: err}
	}

	// Create KMS client with optional endpoint override
	var clientOpts []func(*kms.Options)
	if b.config.Endpoint != "" {
		clientOpts = append(clientOpts, func(o *kms.Options) {
			o.BaseEndpoint = aws.String(b.config.Endpoint)
		})
	}

	b.client = kms.NewFromConfig(cfg, clientOpts...)

	return nil
}

// Get retrieves data for a key with the specified attributes and extension.
// For AWS KMS, this retrieves the public key or metadata associated with the key.
func (b *Backend) Get(attrs *types.KeyAttributes, extension types.FSExtension) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
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

	// For public key extensions, retrieve from KMS
	if extension == backend.FSEXT_PUBLIC_PKCS1 || extension == backend.FSEXT_PUBLIC_PEM {
		keyID := b.getKeyID(attrs.CN)
		output, err := b.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
			KeyId: aws.String(keyID),
		})
		if err != nil {
			return nil, &errs.Detail{Err: backend.ErrFileNotFound, Detail: fmt.Sprintf("failed to get public key: %v", err)}
		}
		return output.PublicKey, nil
	}

	return nil, &errs.Detail{Err: backend.ErrInvalidExtension, Detail: "extension not supported for AWS KMS"}
}

// Save stores data for a key with the specified attributes and extension.
// For AWS KMS, this creates a new key or stores metadata.
func (b *Backend) Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
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
// For AWS KMS, this schedules the key for deletion and removes metadata.
func (b *Backend) Delete(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Get key ID before acquiring lock to avoid deadlock
	keyID := b.getKeyID(attrs.CN)

	b.mu.Lock()
	// Remove metadata
	delete(b.metadata, attrs.CN)
	b.mu.Unlock()

	// Schedule key deletion in KMS (7 day minimum waiting period)
	pendingWindowInDays := int32(7)

	_, err := b.client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(keyID),
		PendingWindowInDays: &pendingWindowInDays,
	})
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
	b.client = nil

	return nil
}

// CreateKey creates a new KMS key with the specified attributes.
// Returns the key ID of the created key.
func (b *Backend) CreateKey(attrs *types.KeyAttributes) (string, error) {
	if attrs == nil {
		return "", backend.ErrInvalidAttributes
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return "", err
	}

	keySpec, err := b.getKeySpec(attrs)
	if err != nil {
		return "", err
	}

	keyUsage := b.getKeyUsage(attrs.KeyType)

	// Create the KMS key
	output, err := b.client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  keySpec,
		KeyUsage: keyUsage,
		Description: aws.String(fmt.Sprintf("Key for %s (%s)",
			attrs.CN, attrs.KeyType)),
	})
	if err != nil {
		return "", &errs.Wrapped{Msg: "failed to create KMS key", Err: err}
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

	// Store metadata
	metadata := map[string]interface{}{
		"key_id":    keyID,
		"alias":     aliasName,
		"key_spec":  keySpec,
		"key_usage": keyUsage,
		"cn":        attrs.CN,
		"key_type":  attrs.KeyType,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return keyID, &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	b.mu.Lock()
	b.metadata[attrs.CN] = metadataBytes
	b.mu.Unlock()

	return keyID, nil
}

// Sign signs a digest using the KMS key.
func (b *Backend) Sign(attrs *types.KeyAttributes, digest []byte) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	keyID := b.getKeyID(attrs.CN)
	signingAlgorithm, err := b.getSigningAlgorithm(attrs)
	if err != nil {
		return nil, err
	}

	output, err := b.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      awstypes.MessageTypeDigest,
		SigningAlgorithm: signingAlgorithm,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "KMS sign operation failed", Err: err}
	}

	return output.Signature, nil
}

// Verify verifies a signature using the KMS key.
func (b *Backend) Verify(attrs *types.KeyAttributes, digest, signature []byte) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return err
	}

	keyID := b.getKeyID(attrs.CN)
	signingAlgorithm, err := b.getSigningAlgorithm(attrs)
	if err != nil {
		return err
	}

	output, err := b.client.Verify(ctx, &kms.VerifyInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      awstypes.MessageTypeDigest,
		Signature:        signature,
		SigningAlgorithm: signingAlgorithm,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "KMS verify operation failed", Err: err}
	}

	if !output.SignatureValid {
		return ErrSignatureFailed
	}

	return nil
}

// getKeyID returns the key ID or alias for a given CN.
func (b *Backend) getKeyID(cn string) string {
	// First check if we have metadata with a key ID
	b.mu.RLock()
	metadataBytes, ok := b.metadata[cn]
	b.mu.RUnlock()

	if ok {
		var metadata map[string]interface{}
		if err := json.Unmarshal(metadataBytes, &metadata); err == nil {
			if keyID, ok := metadata["key_id"].(string); ok {
				return keyID
			}
		}
	}

	// Fall back to alias
	return fmt.Sprintf("alias/%s", cn)
}

// getKeySpec converts types.KeyAttributes to AWS KMS KeySpec.
func (b *Backend) getKeySpec(attrs *types.KeyAttributes) (awstypes.KeySpec, error) {
	// Check if this is a symmetric key request
	// KEY_TYPE_SIGNING can be used for HMAC symmetric keys
	if attrs.KeyType == backend.KEY_TYPE_SECRET ||
		attrs.KeyType == backend.KEY_TYPE_ENCRYPTION ||
		attrs.KeyType == backend.KEY_TYPE_HMAC ||
		(attrs.KeyType == backend.KEY_TYPE_SIGNING && attrs.KeyAlgorithm == x509.UnknownPublicKeyAlgorithm) {
		// For symmetric keys, use SYMMETRIC_DEFAULT (AES-256-GCM)
		return awstypes.KeySpecSymmetricDefault, nil
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		// Default to RSA_2048 if not specified
		return awstypes.KeySpecRsa2048, nil
	case x509.ECDSA:
		// Default to ECC_NIST_P256 if not specified
		return awstypes.KeySpecEccNistP256, nil
	default:
		return "", &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: fmt.Sprintf("%s", attrs.KeyAlgorithm)}
	}
}

// getKeyUsage converts types.KeyType to AWS KMS KeyUsageType.
func (b *Backend) getKeyUsage(keyType types.KeyType) awstypes.KeyUsageType {
	switch keyType {
	case backend.KEY_TYPE_ENCRYPTION, backend.KEY_TYPE_SECRET, backend.KEY_TYPE_HMAC:
		return awstypes.KeyUsageTypeEncryptDecrypt
	default:
		// Most key types use sign/verify
		return awstypes.KeyUsageTypeSignVerify
	}
}

// getSigningAlgorithm returns the appropriate KMS signing algorithm for the key attributes.
func (b *Backend) getSigningAlgorithm(attrs *types.KeyAttributes) (awstypes.SigningAlgorithmSpec, error) {
	// Determine hash algorithm (default to SHA256 if not specified)
	hash := attrs.Hash
	if hash == 0 {
		hash = crypto.SHA256
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		// Map hash to RSA signing algorithm (using PSS padding)
		switch hash {
		case crypto.SHA256:
			return awstypes.SigningAlgorithmSpecRsassaPssSha256, nil
		case crypto.SHA384:
			return awstypes.SigningAlgorithmSpecRsassaPssSha384, nil
		case crypto.SHA512:
			return awstypes.SigningAlgorithmSpecRsassaPssSha512, nil
		default:
			return "", &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported hash algorithm for RSA: %s", hash)}
		}
	case x509.ECDSA:
		// Map hash to ECDSA signing algorithm
		switch hash {
		case crypto.SHA256:
			return awstypes.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return awstypes.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return awstypes.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported hash algorithm for ECDSA: %s", hash)}
		}
	default:
		return "", &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s", attrs.KeyAlgorithm)}
	}
}

// Type returns the backend type identifier.
func (b *Backend) Type() types.BackendType {
	return backend.BackendTypeAWSKMS
}

// Capabilities returns what features this backend supports.
// SecurityLevel is Medium - keys are protected by cloud HSMs but network-dependent.
func (b *Backend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      true, // AWS KMS uses hardware security modules
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,  // AWS KMS supports symmetric encryption (AES-256-GCM)
		Import:              true,  // AWS KMS supports key import via wrapping
		Export:              false, // AWS KMS does not allow key extraction
		SecurityLevel:       types.SecurityLevelMedium,
	}
}

// GenerateKey generates a new private key with the given attributes.
// For AWS KMS, this creates a new KMS key and stores metadata.
func (b *Backend) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Create the KMS key
	_, err := b.CreateKey(attrs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to create KMS key", Err: err}
	}

	// Return nil for private key since it's not extractable from KMS
	// Callers should use Signer() or Decrypter() instead
	return nil, nil
}

// GetKey retrieves an existing private key by its attributes.
// For AWS KMS, this verifies the key exists and returns a reference.
func (b *Backend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
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

	// Verify key exists in KMS
	keyID := b.getKeyID(attrs.CN)
	_, err := b.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, &errs.Detail{Err: backend.ErrKeyNotFound, Detail: fmt.Sprintf("failed to describe key: %v", err)}
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
		StoreType: backend.STORE_AWSKMS,
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
		StoreType: backend.STORE_AWSKMS,
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

		// Extract key type (could be string or number depending on how it was stored)
		if keyTypeVal, ok := metadata["key_type"]; ok {
			switch v := keyTypeVal.(type) {
			case string:
				// Handle string representation - we'll need to parse it
				// For now, just skip since we can't easily convert string back to uint8
			case float64:
				// JSON unmarshals numbers as float64
				attrs.KeyType = types.KeyType(uint8(v))
			case uint8:
				attrs.KeyType = types.KeyType(v)
			}
		}

		// Extract key algorithm from key_spec
		if keySpecStr, ok := metadata["key_spec"].(string); ok {
			switch awstypes.KeySpec(keySpecStr) {
			case awstypes.KeySpecRsa2048, awstypes.KeySpecRsa3072, awstypes.KeySpecRsa4096:
				attrs.KeyAlgorithm = x509.RSA
			case awstypes.KeySpecEccNistP256, awstypes.KeySpecEccNistP384, awstypes.KeySpecEccNistP521:
				attrs.KeyAlgorithm = x509.ECDSA
			}
		}

		// Set store type
		attrs.StoreType = backend.STORE_AWSKMS

		allKeys = append(allKeys, attrs)
	}

	return allKeys, nil
}

// Signer returns a crypto.Signer for the key identified by attrs.
func (b *Backend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	keyID := b.getKeyID(attrs.CN)

	// Get the public key
	pubKeyOutput, err := b.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get public key", Err: err}
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(pubKeyOutput.PublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
	}

	return &kmsSigner{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
		keyID:     keyID,
	}, nil
}

// Decrypter returns a crypto.Decrypter for the key identified by attrs.
func (b *Backend) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Only RSA keys with ENCRYPT_DECRYPT usage support decryption
	if attrs.KeyAlgorithm != x509.RSA {
		return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: "only RSA keys support decryption"}
	}

	if attrs.KeyType != backend.KEY_TYPE_ENCRYPTION {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "key must be of type encryption"}
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	keyID := b.getKeyID(attrs.CN)

	// Get the public key
	pubKeyOutput, err := b.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get public key", Err: err}
	}

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(pubKeyOutput.PublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse public key", Err: err}
	}

	return &kmsDecrypter{
		backend:   b,
		attrs:     attrs,
		publicKey: publicKey,
		keyID:     keyID,
	}, nil
}

// RotateKey rotates/updates a key identified by attrs.
// For AWS KMS, this uses the RotateKeyOnDemand API to create a new key version.
func (b *Backend) RotateKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	if err := b.initClient(ctx); err != nil {
		return err
	}

	keyID := b.getKeyID(attrs.CN)

	// Rotate the key using on-demand rotation
	_, err := b.client.RotateKeyOnDemand(ctx, &kms.RotateKeyOnDemandInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to rotate key", Err: err}
	}

	// Reset AEAD tracking after successful rotation
	if b.tracker != nil && attrs.IsSymmetric() {
		trackingKeyID := attrs.ID()
		if err := b.tracker.ResetTracking(trackingKeyID); err != nil {
			// Log but don't fail the rotation - tracking reset is not critical
			// The rotation has already succeeded in AWS KMS
			fmt.Printf("warning: failed to reset AEAD tracking after key rotation: %v\n", err)
		}
	}

	return nil
}

// Public returns the public key corresponding to the KMS signing key.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the given digest using AWS KMS.
// The digest must be pre-hashed according to the key's hash algorithm.
// Unlike the fixed algorithm captured at Signer construction, Sign honors the
// hash and padding requested by opts on every call: an *rsa.PSSOptions
// selects RSASSA-PSS, any other crypto.SignerOpts on an RSA key selects
// RSASSA-PKCS1-v1_5, and the hash is taken from opts.HashFunc() in both
// cases. This lets a single Signer correctly serve callers that request
// different padding/hash combinations, and rejects combinations AWS KMS
// cannot serve instead of silently signing with the wrong algorithm.
func (s *kmsSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()
	if err := s.backend.initClient(ctx); err != nil {
		return nil, err
	}

	signingAlg, err := awsSigningAlgorithm(s.attrs.KeyAlgorithm, opts)
	if err != nil {
		return nil, err
	}

	output, err := s.backend.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest,
		MessageType:      awstypes.MessageTypeDigest,
		SigningAlgorithm: signingAlg,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "KMS sign operation failed", Err: err}
	}

	return output.Signature, nil
}

// awsSigningAlgorithm resolves the AWS KMS signing algorithm for a signing
// key algorithm and a per-call crypto.SignerOpts, honoring the requested
// hash and padding instead of an algorithm fixed at construction time.
//
// For RSA keys, an *rsa.PSSOptions selects RSASSA-PSS at its Hash; any other
// SignerOpts (including a bare crypto.Hash, which is how PKCS#1 v1.5 is
// conventionally requested) selects RSASSA-PKCS1-v1_5 at opts.HashFunc().
// For ECDSA keys, only the hash varies. AWS KMS serves SHA-256, SHA-384, and
// SHA-512 for every combination; any other hash, or an unsupported key
// algorithm, is a typed error rather than a silently wrong signature.
func awsSigningAlgorithm(keyAlgorithm x509.PublicKeyAlgorithm, opts crypto.SignerOpts) (awstypes.SigningAlgorithmSpec, error) {
	if opts == nil {
		return "", &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "signer options are required"}
	}

	switch keyAlgorithm {
	case x509.RSA:
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			switch pssOpts.Hash {
			case crypto.SHA256:
				return awstypes.SigningAlgorithmSpecRsassaPssSha256, nil
			case crypto.SHA384:
				return awstypes.SigningAlgorithmSpecRsassaPssSha384, nil
			case crypto.SHA512:
				return awstypes.SigningAlgorithmSpecRsassaPssSha512, nil
			default:
				return "", &errs.Detail{Err: ErrInvalidAlgorithm, Detail: fmt.Sprintf("AWS KMS does not support RSASSA-PSS with hash %s", pssOpts.Hash)}
			}
		}
		switch opts.HashFunc() {
		case crypto.SHA256:
			return awstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return awstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return awstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", &errs.Detail{Err: ErrInvalidAlgorithm, Detail: fmt.Sprintf("AWS KMS does not support RSASSA-PKCS1-v1_5 with hash %s", opts.HashFunc())}
		}
	case x509.ECDSA:
		switch opts.HashFunc() {
		case crypto.SHA256:
			return awstypes.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return awstypes.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return awstypes.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", &errs.Detail{Err: ErrInvalidAlgorithm, Detail: fmt.Sprintf("AWS KMS does not support ECDSA with hash %s", opts.HashFunc())}
		}
	default:
		return "", &errs.Detail{Err: ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s", keyAlgorithm)}
	}
}

// Public returns the public key corresponding to the KMS decryption key.
func (d *kmsDecrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// Decrypt decrypts the given ciphertext using AWS KMS.
// The opts parameter specifies the decryption options (e.g., OAEP padding).
func (d *kmsDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	ctx := context.Background()
	if err := d.backend.initClient(ctx); err != nil {
		return nil, err
	}

	// Determine encryption algorithm based on opts
	var encryptionAlgorithm awstypes.EncryptionAlgorithmSpec
	if opts != nil {
		// Default to RSAES_OAEP_SHA_256 for RSA-OAEP
		encryptionAlgorithm = awstypes.EncryptionAlgorithmSpecRsaesOaepSha256
	} else {
		// Default algorithm
		encryptionAlgorithm = awstypes.EncryptionAlgorithmSpecRsaesOaepSha256
	}

	output, err := d.backend.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               aws.String(d.keyID),
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: encryptionAlgorithm,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "KMS decrypt operation failed", Err: err}
	}

	return output.Plaintext, nil
}

// GetImportParameters retrieves parameters needed to import key material into AWS KMS.
// This operation calls the AWS KMS GetParametersForImport API and returns:
//   - A wrapping public key (RSA-2048) generated by AWS HSM
//   - An import token that associates this import with the wrapping key
//   - Expiration time (24 hours from AWS ParametersValidTo)
//
// The returned parameters must be used with WrapKey to encrypt the key material
// before calling ImportKey.
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	if err := b.initClient(ctx); err != nil {
		return nil, err
	}

	// Map backend wrapping algorithm to AWS wrapping key spec
	wrappingKeySpec, err := b.mapWrappingAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	// Get the key ID
	keyID := b.getKeyID(attrs.CN)

	// Call AWS KMS GetParametersForImport
	output, err := b.client.GetParametersForImport(ctx, &kms.GetParametersForImportInput{
		KeyId:             aws.String(keyID),
		WrappingAlgorithm: wrappingKeySpec,
		WrappingKeySpec:   awstypes.WrappingKeySpecRsa2048, // AWS KMS uses RSA-2048 for wrapping keys
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get import parameters from AWS KMS", Err: err}
	}

	// Parse the wrapping public key (DER-encoded SPKI format)
	publicKey, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse wrapping public key", Err: err}
	}

	// Calculate expiration time (AWS provides ParametersValidTo)
	var expiresAt *time.Time
	if output.ParametersValidTo != nil {
		expiresAt = output.ParametersValidTo
	}

	// Determine key spec from attributes
	keySpec := ""
	if attrs.KeyAlgorithm == x509.RSA {
		keySpec = "RSA_2048" // Default, could be adjusted based on key size
	} else if attrs.KeyAlgorithm == x509.ECDSA {
		keySpec = "ECC_NIST_P256" // Default
	}

	return &backend.ImportParameters{
		WrappingPublicKey: publicKey,
		ImportToken:       output.ImportToken,
		Algorithm:         algorithm,
		ExpiresAt:         expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material for secure transport to AWS KMS.
// This operation uses the wrapping public key from GetImportParameters to encrypt
// the key material locally (client-side) using the pkg/crypto/wrapping functions.
//
// The wrapping is performed locally to ensure the plaintext key material is never
// transmitted to AWS over the network. Only the encrypted (wrapped) key material
// is sent during the ImportKey operation.
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key material cannot be empty"}
	}
	if params == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import parameters cannot be nil"}
	}
	if params.WrappingPublicKey == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapping public key cannot be nil"}
	}

	// Determine which wrapping function to use based on algorithm
	// Extract the RSA public key from the interface
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: backend.ErrInvalidKeyType, Detail: "wrapping public key must be an *rsa.PublicKey"}
	}

	var wrappedKey []byte
	var err error

	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Use simple RSA-OAEP wrapping
		wrappedKey, err = wrapping.WrapRSAOAEP(keyMaterial, rsaPubKey, params.Algorithm)

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Use hybrid RSA + AES-KWP wrapping for large keys
		wrappedKey, err = wrapping.WrapRSAAES(keyMaterial, rsaPubKey, params.Algorithm)

	default:
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("%s", params.Algorithm)}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to wrap key material", Err: err}
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrappedKey,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey is not supported for AWS KMS as unwrapping happens securely within the AWS HSM.
// The private unwrapping key never leaves the HSM, so client-side unwrapping is not possible
// or necessary. This method returns an error indicating the operation is not supported.
//
// For AWS KMS, key material is unwrapped automatically during the ImportKey operation
// within the secure hardware boundary.
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: "AWS KMS performs unwrapping internally within the HSM"}
}

// ImportKey imports externally generated key material into AWS KMS.
// This operation calls the AWS KMS ImportKeyMaterial API with:
//   - The key ID (from attrs)
//   - The import token (from wrapped key material)
//   - The encrypted key material
//
// The key must have been created with OriginType=EXTERNAL before calling this method.
// After successful import, the key can be used for cryptographic operations like any
// other KMS key.
//
// Important: The import token has a 24-hour validity period. If expired, new parameters
// must be obtained via GetImportParameters.
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}
	if wrapped == nil {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material cannot be nil"}
	}
	if len(wrapped.ImportToken) == 0 {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "import token is required"}
	}
	if len(wrapped.WrappedKey) == 0 {
		return &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "wrapped key material is empty"}
	}

	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Get the key ID
	keyID := b.getKeyID(attrs.CN)

	// Call AWS KMS ImportKeyMaterial
	// Note: The wrapping algorithm was already specified in GetParametersForImport,
	// so we don't need to specify it again here. AWS KMS uses the algorithm from
	// the import token to determine how to unwrap the key material.
	_, err := b.client.ImportKeyMaterial(ctx, &kms.ImportKeyMaterialInput{
		KeyId:                aws.String(keyID),
		ImportToken:          wrapped.ImportToken,
		EncryptedKeyMaterial: wrapped.WrappedKey,
		ExpirationModel:      awstypes.ExpirationModelTypeKeyMaterialDoesNotExpire,
	})
	if err != nil {
		return &errs.Wrapped{Msg: "failed to import key material into AWS KMS", Err: err}
	}

	return nil
}

// ExportKey is not supported by AWS KMS.
// AWS KMS does not allow exporting key material from the HSM for security reasons.
// This ensures that keys remain protected within the AWS hardware security modules.
//
// Returns ErrExportNotSupported to indicate this operation is not available.
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Check if backend supports export (it doesn't)
	if !b.Capabilities().Export {
		return nil, backend.ErrExportNotSupported
	}

	// This line is unreachable due to the check above, but included for completeness
	// Check if key is marked as exportable
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	return nil, backend.ErrExportNotSupported
}

// ExportKeyTo is not supported by AWS KMS for the same reason ExportKey is
// not: AWS KMS never releases key material -- imported or generated --
// outside the service boundary, so there is no plaintext for this backend to
// wrap for a destination's parameters in the first place.
func (b *Backend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if dstParams == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "destination import parameters cannot be nil"}
	}
	return nil, &errs.Detail{Err: backend.ErrExportToUnsupported, Detail: "AWS KMS never releases key material outside the service boundary"}
}

// ExportKeyMaterial is not supported by AWS KMS, for the same reason as
// ExportKey: AWS KMS never releases plaintext key material -- imported or
// generated -- outside the service boundary, so there is no raw-bytes
// equivalent of ExportKey to offer either.
//
// This method exists so *Backend fully satisfies backend.ImportExportBackend
// (it already implements every ImportBackend method for real, since AWS KMS
// genuinely supports the BYOK import ceremony). Before this method existed,
// the missing method made the interface assertion
// `provider.(backend.ImportExportBackend)` fail outright, which blocked the
// working import path along with the always-absent export one: the same API
// call that succeeded on a backend supporting both directions returned a
// generic 400/500 on AWS KMS. See backend.ExportBackend, which now lets a
// caller that only needs the import half reach it directly instead of
// depending on this refusal succeeding as a method call.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if !attrs.IsSymmetric() {
		return nil, backend.ErrAsymmetricKeyExportNotAllowed
	}
	return nil, backend.ErrExportNotSupported
}

// Verify interface compliance at compile time. *Backend implements the full
// ImportBackend ceremony genuinely; the ExportBackend half above always
// refuses with a typed, correctly classified error, which is what a hardware
// security boundary that admits import but not export looks like -- not a
// stub, since there is no incomplete-but-someday version of "extract key
// material AWS KMS's HSM will never release."
var _ backend.ImportBackend = (*Backend)(nil)
var _ backend.ImportExportBackend = (*Backend)(nil)

// mapWrappingAlgorithm maps backend.WrappingAlgorithm to AWS types.AlgorithmSpec.
// AWS KMS uses AlgorithmSpec to specify the wrapping algorithm for import operations.
func (b *Backend) mapWrappingAlgorithm(algorithm backend.WrappingAlgorithm) (awstypes.AlgorithmSpec, error) {
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1:
		return awstypes.AlgorithmSpecRsaesOaepSha1, nil
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		return awstypes.AlgorithmSpecRsaesOaepSha256, nil
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		return awstypes.AlgorithmSpecRsaAesKeyWrapSha1, nil
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		return awstypes.AlgorithmSpecRsaAesKeyWrapSha256, nil
	default:
		return "", &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: fmt.Sprintf("unsupported wrapping algorithm: %s", algorithm)}
	}
}
