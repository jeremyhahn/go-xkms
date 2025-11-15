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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Ensure Backend implements ImportExportBackend interface
var _ backend.ImportExportBackend = (*Backend)(nil)

// GetImportParameters retrieves the parameters needed to import a key into GCP KMS.
// This creates or retrieves an import job and extracts the wrapping public key.
//
// GCP KMS import jobs remain valid for up to 3 days and can be used for multiple imports.
// The import job name is returned as the import token.
func (b *Backend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	ctx := context.Background()

	// Map backend wrapping algorithm to GCP KMS import method
	importMethod, err := mapWrappingAlgorithmToImportMethod(algorithm)
	if err != nil {
		return nil, err
	}

	// Generate a unique import job ID based on the key attributes and timestamp
	importJobID := fmt.Sprintf("import-job-%s-%d", attrs.CN, time.Now().Unix())

	// Determine protection level based on key attributes
	protectionLevel := kmspb.ProtectionLevel_HSM
	// Could make this configurable based on attrs in the future

	// Create import job
	createReq := &kmspb.CreateImportJobRequest{
		Parent:      b.config.KeyRingName(),
		ImportJobId: importJobID,
		ImportJob: &kmspb.ImportJob{
			ImportMethod:    importMethod,
			ProtectionLevel: protectionLevel,
		},
	}

	importJob, err := b.client.CreateImportJob(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create import job: %w", err)
	}

	// Parse the wrapping public key from the import job
	if importJob.PublicKey == nil {
		return nil, fmt.Errorf("import job has no public key")
	}

	publicKey, err := parsePublicKey(importJob.PublicKey.Pem)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wrapping public key: %w", err)
	}

	// Determine expiration time (GCP import jobs are valid for 3 days)
	expiresAt := time.Now().Add(3 * 24 * time.Hour)

	// Determine key spec from attributes
	keySpec := determineKeySpec(attrs)

	return &backend.ImportParameters{
		WrappingPublicKey: publicKey,
		ImportToken:       []byte(importJob.Name), // Use import job name as token
		Algorithm:         algorithm,
		ExpiresAt:         &expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material for secure transport using the specified parameters.
// This uses the wrapping functions from pkg/crypto/wrapping.
func (b *Backend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if keyMaterial == nil || len(keyMaterial) == 0 {
		return nil, backend.ErrInvalidAttributes
	}

	if params == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Ensure we have an RSA public key
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: wrapping public key must be RSA", backend.ErrInvalidKeyType)
	}

	var wrapped []byte
	var err error

	// Wrap based on algorithm
	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_OAEP_4096_SHA256:
		// Direct RSA-OAEP wrapping (for small keys like symmetric keys)
		wrapped, err = wrapping.WrapRSAOAEP(keyMaterial, rsaPubKey, params.Algorithm)

	case backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
		backend.WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256:
		// Hybrid wrapping (for large keys like RSA private keys)
		// Map GCP-specific algorithm to standard hybrid algorithm
		hybridAlgorithm := backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
		wrapped, err = wrapping.WrapRSAAES(keyMaterial, rsaPubKey, hybridAlgorithm)

	default:
		return nil, fmt.Errorf("%w: unsupported wrapping algorithm %s", backend.ErrInvalidAlgorithm, params.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to wrap key material: %w", err)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey unwraps key material that was previously wrapped with WrapKey.
// For GCP KMS, unwrapping happens in the HSM during import, so this returns an error.
// This method exists to satisfy the ImportExportBackend interface but is not used
// for GCP KMS imports.
func (b *Backend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, fmt.Errorf("%w: unwrapping is performed by GCP KMS HSM during import", backend.ErrNotSupported)
}

// ImportKey imports externally generated key material into GCP KMS.
// The key material must be wrapped using parameters obtained from GetImportParameters.
func (b *Backend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.client == nil {
		return ErrNotInitialized
	}

	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	if wrapped == nil {
		return backend.ErrInvalidAttributes
	}

	ctx := context.Background()

	// The import token contains the import job name
	importJobName := string(wrapped.ImportToken)

	// Map key attributes to GCP KMS algorithm
	algorithm, err := mapKeyAttributesToAlgorithm(attrs)
	if err != nil {
		return err
	}

	// Construct the crypto key name
	cryptoKeyName := b.cryptoKeyName(attrs.CN)

	// Build import request based on wrapping algorithm
	req := &kmspb.ImportCryptoKeyVersionRequest{
		Parent:    cryptoKeyName,
		ImportJob: importJobName,
		Algorithm: algorithm,
	}

	// Set the wrapped key material based on the algorithm
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_OAEP_4096_SHA256:
		// Direct RSA-OAEP wrapped key
		req.WrappedKeyMaterial = &kmspb.ImportCryptoKeyVersionRequest_RsaAesWrappedKey{
			RsaAesWrappedKey: wrapped.WrappedKey,
		}

	case backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256,
		backend.WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256:
		// Hybrid RSA+AES wrapped key
		req.WrappedKeyMaterial = &kmspb.ImportCryptoKeyVersionRequest_RsaAesWrappedKey{
			RsaAesWrappedKey: wrapped.WrappedKey,
		}

	default:
		return fmt.Errorf("%w: unsupported wrapping algorithm %s", backend.ErrInvalidAlgorithm, wrapped.Algorithm)
	}

	// Import the crypto key version
	keyVersion, err := b.client.ImportCryptoKeyVersion(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to import crypto key version: %w", err)
	}

	// Store metadata about the imported key
	metadata := map[string]interface{}{
		"key_name":      keyVersion.Name,
		"algorithm":     keyVersion.Algorithm.String(),
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType,
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_GCPKMS,
		"import_job":    importJobName,
		"imported":      true,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(b.config.KeyStorage, attrs.ID(), metadataBytes); err != nil {
			return fmt.Errorf("failed to save metadata: %w", err)
		}
	}

	return nil
}

// ExportKey exports a key in wrapped form for secure transport.
// GCP KMS does not support key export for HSM keys, so this returns an error
// unless the key was created with SOFTWARE protection level and EXPORTABLE set.
func (b *Backend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
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

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.client == nil {
		return nil, ErrNotInitialized
	}

	ctx := context.Background()

	// Get the crypto key to check its properties
	cryptoKeyName := b.cryptoKeyName(attrs.CN)
	cryptoKey, err := b.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: cryptoKeyName,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get crypto key: %v", backend.ErrKeyNotFound, err)
	}

	// Check if the key version is exportable
	// In GCP KMS, only SOFTWARE keys can be exported, and only if they're marked as exportable
	if cryptoKey.Primary == nil {
		return nil, fmt.Errorf("crypto key has no primary version")
	}

	// GCP KMS keys created with ProtectionLevel_SOFTWARE can be exportable
	// However, the actual export operation is not directly supported via the API
	// You would need to use GetPublicKey for asymmetric keys (public key only)
	// Private key material cannot be exported from GCP KMS for security reasons

	return nil, backend.ErrExportNotSupported
}

// mapWrappingAlgorithmToImportMethod maps a backend wrapping algorithm to a GCP KMS import method.
func mapWrappingAlgorithmToImportMethod(algorithm backend.WrappingAlgorithm) (kmspb.ImportJob_ImportMethod, error) {
	switch algorithm {
	case backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256:
		return kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256, nil
	case backend.WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256:
		return kmspb.ImportJob_RSA_OAEP_4096_SHA256_AES_256, nil
	case backend.WrappingAlgorithmRSA_OAEP_4096_SHA256,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		return kmspb.ImportJob_RSA_OAEP_4096_SHA256, nil
	default:
		return 0, fmt.Errorf("%w: unsupported wrapping algorithm for GCP KMS: %s", backend.ErrInvalidAlgorithm, algorithm)
	}
}

// mapKeyAttributesToAlgorithm maps key attributes to a GCP KMS algorithm.
func mapKeyAttributesToAlgorithm(attrs *types.KeyAttributes) (kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, error) {
	// Check if this is a symmetric key
	if attrs.IsSymmetric() {
		return kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION, nil
	}

	// Handle asymmetric keys
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		// Default to RSA 2048 PKCS1 if no specific size is given
		// This could be enhanced to check attrs for specific RSA parameters
		return kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, nil

	case x509.ECDSA:
		// Default to P-256 if no specific curve is given
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, nil

	default:
		return 0, fmt.Errorf("%w: unsupported key algorithm %s", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm)
	}
}

// determineKeySpec determines the key spec string from key attributes.
func determineKeySpec(attrs *types.KeyAttributes) string {
	// Check if this is a symmetric key
	if attrs.IsSymmetric() {
		switch attrs.SymmetricAlgorithm {
		case types.SymmetricAES192GCM:
			return "AES_192"
		case types.SymmetricAES256GCM:
			return "AES_256"
		default:
			return "AES_128"
		}
	}

	// Handle asymmetric keys
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return "RSA_2048" // Default, could be enhanced
	case x509.ECDSA:
		return "EC_P256" // Default, could be enhanced
	default:
		return "UNKNOWN"
	}
}
