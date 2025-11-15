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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-keychain/pkg/encoding/jwk"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Ensure Backend implements backend.ImportExportBackend interface
var _ backend.ImportExportBackend = (*Backend)(nil)

// GetImportParameters retrieves the parameters needed to import a key into Azure Key Vault.
//
// Azure Key Vault import process:
//  1. Generate a temporary RSA wrapping key pair
//  2. Return the public key for wrapping key material
//  3. Store the private key temporarily for unwrapping during import
//
// Unlike AWS KMS which generates wrapping keys in the HSM, Azure Key Vault expects
// the key material to be wrapped before import using standard RSA-OAEP.
//
// The returned ImportParameters contain:
//   - A temporary RSA public key for wrapping
//   - An import token (the temporary private key, stored securely)
//   - The specified wrapping algorithm
//   - A 24-hour expiration time
func (b *Backend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if attrs == nil {
		return nil, fmt.Errorf("attributes cannot be nil")
	}

	// Validate wrapping algorithm
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported
	default:
		return nil, fmt.Errorf("%w: Azure Key Vault does not support wrapping algorithm %s", backend.ErrNotSupported, algorithm)
	}

	// Generate a temporary RSA key pair for wrapping
	// Azure Key Vault expects 2048 or 4096 bit keys
	wrappingKeySize := 2048
	wrappingPrivateKey, err := rsa.GenerateKey(rand.Reader, wrappingKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wrapping key pair: %w", err)
	}

	// Serialize the private key as the import token
	// This is stored temporarily until ImportKey is called
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(wrappingPrivateKey)

	// Store the private key temporarily with a unique ID based on CN
	importTokenKey := fmt.Sprintf("import-token-%s", attrs.CN)
	b.mu.Lock()
	b.metadata[importTokenKey] = privateKeyBytes
	b.mu.Unlock()

	// Set expiration to 24 hours from now
	expiresAt := time.Now().Add(24 * time.Hour)

	// Determine key spec from attributes
	keySpec := ""
	if attrs.KeyAlgorithm == x509.RSA {
		if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
			keySpec = fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		} else {
			keySpec = "RSA_2048"
		}
	} else if attrs.KeyAlgorithm == x509.ECDSA {
		if attrs.ECCAttributes != nil {
			keySpec = fmt.Sprintf("ECC_%s", attrs.ECCAttributes.Curve)
		} else {
			keySpec = "ECC_P256"
		}
	}

	return &backend.ImportParameters{
		WrappingPublicKey: &wrappingPrivateKey.PublicKey,
		ImportToken:       privateKeyBytes,
		Algorithm:         algorithm,
		ExpiresAt:         &expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material for secure transport to Azure Key Vault.
// This operation uses the wrapping public key from GetImportParameters to encrypt
// the key material locally (client-side) using RSA-OAEP or hybrid RSA+AES wrapping.
//
// The wrapping is performed locally to ensure the plaintext key material is never
// transmitted to Azure over the network. Only the encrypted (wrapped) key material
// is sent during the ImportKey operation.
func (b *Backend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, fmt.Errorf("key material cannot be empty")
	}
	if params == nil {
		return nil, fmt.Errorf("import parameters cannot be nil")
	}
	if params.WrappingPublicKey == nil {
		return nil, fmt.Errorf("wrapping public key cannot be nil")
	}

	// Extract the RSA public key from the interface
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrapping public key must be an *rsa.PublicKey")
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
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, params.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to wrap key material: %w", err)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrappedKey,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey unwraps key material that was previously wrapped with WrapKey.
// For Azure Key Vault, we perform unwrapping locally using the temporary private key
// that was generated during GetImportParameters.
//
// This is different from AWS KMS, which performs unwrapping in the HSM.
// Azure Key Vault expects plaintext (or wrapped) key material during import.
func (b *Backend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if wrapped == nil {
		return nil, fmt.Errorf("wrapped key material cannot be nil")
	}
	if params == nil {
		return nil, fmt.Errorf("import parameters cannot be nil")
	}
	if len(wrapped.ImportToken) == 0 {
		return nil, fmt.Errorf("import token is required")
	}

	// Parse the private key from the import token
	privateKey, err := x509.ParsePKCS1PrivateKey(wrapped.ImportToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from import token: %w", err)
	}

	var keyMaterial []byte

	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Use simple RSA-OAEP unwrapping
		keyMaterial, err = wrapping.UnwrapRSAOAEP(wrapped.WrappedKey, privateKey, wrapped.Algorithm)

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Use hybrid RSA + AES-KWP unwrapping
		keyMaterial, err = wrapping.UnwrapRSAAES(wrapped.WrappedKey, privateKey, wrapped.Algorithm)

	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, wrapped.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key material: %w", err)
	}

	return keyMaterial, nil
}

// ImportKey imports externally generated key material into Azure Key Vault.
//
// Azure Key Vault import process:
//  1. Unwrap the key material using the temporary private key
//  2. Parse the key material (RSA, ECDSA, etc.)
//  3. Create a JSON Web Key (JWK) from the parsed key
//  4. Import the JWK into Azure Key Vault using the ImportKey API
//
// After successful import, the key can be used for cryptographic operations like any
// other Azure Key Vault key.
func (b *Backend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return fmt.Errorf("attributes cannot be nil")
	}
	if wrapped == nil {
		return fmt.Errorf("wrapped key material cannot be nil")
	}
	if len(wrapped.ImportToken) == 0 {
		return fmt.Errorf("import token is required")
	}
	if len(wrapped.WrappedKey) == 0 {
		return fmt.Errorf("wrapped key material is empty")
	}

	ctx := context.Background()
	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Unwrap the key material
	params := &backend.ImportParameters{
		ImportToken: wrapped.ImportToken,
		Algorithm:   wrapped.Algorithm,
	}
	keyMaterial, err := b.UnwrapKey(wrapped, params)
	if err != nil {
		return fmt.Errorf("failed to unwrap key material: %w", err)
	}

	// Import the key based on its type
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.importRSAKey(ctx, attrs, keyMaterial)
	case x509.ECDSA:
		return b.importECDSAKey(ctx, attrs, keyMaterial)
	default:
		return fmt.Errorf("%w: cannot import keys of type %s", backend.ErrNotSupported, attrs.KeyAlgorithm)
	}
}

// importRSAKey imports an RSA private key into Azure Key Vault
func (b *Backend) importRSAKey(ctx context.Context, attrs *types.KeyAttributes, keyMaterial []byte) error {
	// Parse the RSA private key
	privateKey, err := x509.ParsePKCS8PrivateKey(keyMaterial)
	if err != nil {
		// Try PKCS#1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(keyMaterial)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("key material is not an RSA private key")
	}

	// Convert to standard JWK format using the jwk package
	standardJWK, err := jwk.FromPrivateKey(rsaKey)
	if err != nil {
		return fmt.Errorf("failed to convert RSA key to JWK: %w", err)
	}

	// Set key operations based on key type
	var keyOps []*azkeys.KeyOperation
	if attrs.KeyType == backend.KEY_TYPE_SIGNING {
		keyOps = []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationSign),
			ptrKeyOp(azkeys.KeyOperationVerify),
		}
	} else if attrs.KeyType == backend.KEY_TYPE_ENCRYPTION {
		keyOps = []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationEncrypt),
			ptrKeyOp(azkeys.KeyOperationDecrypt),
			ptrKeyOp(azkeys.KeyOperationWrapKey),
			ptrKeyOp(azkeys.KeyOperationUnwrapKey),
		}
	}

	// Convert standard JWK to Azure's JWK format
	azureJWK, err := convertToAzureJWK(standardJWK, keyOps)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to Azure format: %w", err)
	}

	// Import the key
	params := azkeys.ImportKeyParameters{
		Key: azureJWK,
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled: ptrBool(true),
		},
	}

	_, err = b.client.ImportKey(ctx, attrs.CN, params, nil)
	if err != nil {
		return fmt.Errorf("failed to import RSA key into Azure Key Vault: %w", err)
	}

	// Store metadata
	metadata := map[string]interface{}{
		"cn":          attrs.CN,
		"algorithm":   attrs.KeyAlgorithm.String(),
		"key_type":    string(attrs.KeyType),
		"imported":    true,
		"import_time": time.Now().Unix(),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	b.mu.Lock()
	b.metadata[attrs.CN] = metadataBytes
	b.mu.Unlock()

	// Clean up the temporary import token
	importTokenKey := fmt.Sprintf("import-token-%s", attrs.CN)
	b.mu.Lock()
	delete(b.metadata, importTokenKey)
	b.mu.Unlock()

	return nil
}

// importECDSAKey imports an ECDSA private key into Azure Key Vault
func (b *Backend) importECDSAKey(ctx context.Context, attrs *types.KeyAttributes, keyMaterial []byte) error {
	// Parse the ECDSA private key
	privateKey, err := x509.ParsePKCS8PrivateKey(keyMaterial)
	if err != nil {
		// Try EC private key format
		privateKey, err = x509.ParseECPrivateKey(keyMaterial)
		if err != nil {
			return fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
	}

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("key material is not an ECDSA private key")
	}

	// Convert to standard JWK format using the jwk package
	standardJWK, err := jwk.FromPrivateKey(ecKey)
	if err != nil {
		return fmt.Errorf("failed to convert ECDSA key to JWK: %w", err)
	}

	// Set key operations
	keyOps := []*azkeys.KeyOperation{
		ptrKeyOp(azkeys.KeyOperationSign),
		ptrKeyOp(azkeys.KeyOperationVerify),
	}

	// Convert standard JWK to Azure's JWK format
	azureJWK, err := convertToAzureJWK(standardJWK, keyOps)
	if err != nil {
		return fmt.Errorf("failed to convert JWK to Azure format: %w", err)
	}

	// Import the key
	params := azkeys.ImportKeyParameters{
		Key: azureJWK,
		KeyAttributes: &azkeys.KeyAttributes{
			Enabled: ptrBool(true),
		},
	}

	_, err = b.client.ImportKey(ctx, attrs.CN, params, nil)
	if err != nil {
		return fmt.Errorf("failed to import ECDSA key into Azure Key Vault: %w", err)
	}

	// Store metadata
	metadata := map[string]interface{}{
		"cn":          attrs.CN,
		"algorithm":   attrs.KeyAlgorithm.String(),
		"key_type":    string(attrs.KeyType),
		"imported":    true,
		"import_time": time.Now().Unix(),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	b.mu.Lock()
	b.metadata[attrs.CN] = metadataBytes
	b.mu.Unlock()

	// Clean up the temporary import token
	importTokenKey := fmt.Sprintf("import-token-%s", attrs.CN)
	b.mu.Lock()
	delete(b.metadata, importTokenKey)
	b.mu.Unlock()

	return nil
}

// ExportKey exports a key in wrapped form for secure transport.
// Azure Key Vault does not support exporting private keys directly.
// This method returns ErrNotSupported.
func (b *Backend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Check if backend supports export (it doesn't)
	if !b.Capabilities().Export {
		return nil, backend.ErrNotSupported
	}

	// This line is unreachable due to the check above, but included for completeness
	// Check if key is marked as exportable
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	return nil, backend.ErrNotSupported
}

// convertToAzureJWK converts a standard JWK to Azure's JSONWebKey format.
// Azure's JSONWebKey uses raw byte arrays instead of base64url-encoded strings.
func convertToAzureJWK(standardJWK *jwk.JWK, keyOps []*azkeys.KeyOperation) (*azkeys.JSONWebKey, error) {
	azureJWK := &azkeys.JSONWebKey{
		KeyOps: keyOps,
	}

	switch standardJWK.Kty {
	case string(jwk.KeyTypeRSA):
		keyType := azkeys.KeyTypeRSA
		azureJWK.Kty = &keyType

		// Decode base64url-encoded fields to raw bytes
		n, err := base64.RawURLEncoding.DecodeString(standardJWK.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode N: %w", err)
		}
		azureJWK.N = n

		e, err := base64.RawURLEncoding.DecodeString(standardJWK.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode E: %w", err)
		}
		azureJWK.E = e

		// Private key parameters (if present)
		if standardJWK.D != "" {
			d, err := base64.RawURLEncoding.DecodeString(standardJWK.D)
			if err != nil {
				return nil, fmt.Errorf("failed to decode D: %w", err)
			}
			azureJWK.D = d

			p, err := base64.RawURLEncoding.DecodeString(standardJWK.P)
			if err != nil {
				return nil, fmt.Errorf("failed to decode P: %w", err)
			}
			azureJWK.P = p

			q, err := base64.RawURLEncoding.DecodeString(standardJWK.Q)
			if err != nil {
				return nil, fmt.Errorf("failed to decode Q: %w", err)
			}
			azureJWK.Q = q

			dp, err := base64.RawURLEncoding.DecodeString(standardJWK.DP)
			if err != nil {
				return nil, fmt.Errorf("failed to decode DP: %w", err)
			}
			azureJWK.DP = dp

			dq, err := base64.RawURLEncoding.DecodeString(standardJWK.DQ)
			if err != nil {
				return nil, fmt.Errorf("failed to decode DQ: %w", err)
			}
			azureJWK.DQ = dq

			qi, err := base64.RawURLEncoding.DecodeString(standardJWK.QI)
			if err != nil {
				return nil, fmt.Errorf("failed to decode QI: %w", err)
			}
			azureJWK.QI = qi
		}

	case string(jwk.KeyTypeEC):
		keyType := azkeys.KeyTypeEC
		azureJWK.Kty = &keyType

		// Map curve name
		var curveName azkeys.CurveName
		switch standardJWK.Crv {
		case string(jwk.CurveP256):
			curveName = azkeys.CurveNameP256
		case string(jwk.CurveP384):
			curveName = azkeys.CurveNameP384
		case string(jwk.CurveP521):
			curveName = azkeys.CurveNameP521
		default:
			return nil, fmt.Errorf("unsupported curve: %s", standardJWK.Crv)
		}
		azureJWK.Crv = &curveName

		// Decode coordinates
		x, err := base64.RawURLEncoding.DecodeString(standardJWK.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode X: %w", err)
		}
		azureJWK.X = x

		y, err := base64.RawURLEncoding.DecodeString(standardJWK.Y)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Y: %w", err)
		}
		azureJWK.Y = y

		// Private key parameter (if present)
		if standardJWK.D != "" {
			d, err := base64.RawURLEncoding.DecodeString(standardJWK.D)
			if err != nil {
				return nil, fmt.Errorf("failed to decode D: %w", err)
			}
			azureJWK.D = d
		}

	default:
		return nil, fmt.Errorf("unsupported key type: %s", standardJWK.Kty)
	}

	return azureJWK, nil
}

// convertFromAzureJWK converts an Azure JSONWebKey to standard JWK format.
// This is useful for exporting keys from Azure Key Vault.
func convertFromAzureJWK(azureJWK *azkeys.JSONWebKey) (*jwk.JWK, error) {
	if azureJWK.Kty == nil {
		return nil, fmt.Errorf("key type is required")
	}

	standardJWK := &jwk.JWK{}

	switch *azureJWK.Kty {
	case azkeys.KeyTypeRSA:
		standardJWK.Kty = string(jwk.KeyTypeRSA)

		// Encode raw bytes to base64url strings
		if azureJWK.N != nil {
			standardJWK.N = base64.RawURLEncoding.EncodeToString(azureJWK.N)
		}
		if azureJWK.E != nil {
			standardJWK.E = base64.RawURLEncoding.EncodeToString(azureJWK.E)
		}

		// Private key parameters (if present)
		if azureJWK.D != nil {
			standardJWK.D = base64.RawURLEncoding.EncodeToString(azureJWK.D)
		}
		if azureJWK.P != nil {
			standardJWK.P = base64.RawURLEncoding.EncodeToString(azureJWK.P)
		}
		if azureJWK.Q != nil {
			standardJWK.Q = base64.RawURLEncoding.EncodeToString(azureJWK.Q)
		}
		if azureJWK.DP != nil {
			standardJWK.DP = base64.RawURLEncoding.EncodeToString(azureJWK.DP)
		}
		if azureJWK.DQ != nil {
			standardJWK.DQ = base64.RawURLEncoding.EncodeToString(azureJWK.DQ)
		}
		if azureJWK.QI != nil {
			standardJWK.QI = base64.RawURLEncoding.EncodeToString(azureJWK.QI)
		}

	case azkeys.KeyTypeEC:
		standardJWK.Kty = string(jwk.KeyTypeEC)

		// Map curve name
		if azureJWK.Crv != nil {
			switch *azureJWK.Crv {
			case azkeys.CurveNameP256:
				standardJWK.Crv = string(jwk.CurveP256)
			case azkeys.CurveNameP384:
				standardJWK.Crv = string(jwk.CurveP384)
			case azkeys.CurveNameP521:
				standardJWK.Crv = string(jwk.CurveP521)
			default:
				return nil, fmt.Errorf("unsupported curve: %v", *azureJWK.Crv)
			}
		}

		// Encode coordinates
		if azureJWK.X != nil {
			standardJWK.X = base64.RawURLEncoding.EncodeToString(azureJWK.X)
		}
		if azureJWK.Y != nil {
			standardJWK.Y = base64.RawURLEncoding.EncodeToString(azureJWK.Y)
		}

		// Private key parameter (if present)
		if azureJWK.D != nil {
			standardJWK.D = base64.RawURLEncoding.EncodeToString(azureJWK.D)
		}

	default:
		return nil, fmt.Errorf("unsupported key type: %v", *azureJWK.Kty)
	}

	return standardJWK, nil
}
