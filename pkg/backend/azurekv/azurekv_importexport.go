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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/encoding/jwk"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
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
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if attrs == nil {
		return nil, &errs.Message{Msg: "attributes cannot be nil"}
	}

	// Validate wrapping algorithm
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported
	default:
		return nil, &errs.Detail{Err: backend.ErrNotSupported, Detail: fmt.Sprintf("Azure Key Vault does not support wrapping algorithm %s", algorithm)}
	}

	// Generate a temporary RSA key pair for wrapping
	// Azure Key Vault expects 2048 or 4096 bit keys
	wrappingKeySize := 2048
	wrappingPrivateKey, err := rsa.GenerateKey(rand.Reader, wrappingKeySize)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to generate wrapping key pair", Err: err}
	}

	// Serialize the private key as the import token
	// This is stored temporarily until ImportKey is called
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(wrappingPrivateKey)

	// Store the private key temporarily with a unique ID based on CN. This
	// is transient wrapping-key material for the in-flight import ceremony,
	// never key metadata, so it stays in importTokens (process memory only)
	// rather than Config.KeyStorage; see the Backend.importTokens doc
	// comment in azurekv.go.
	importTokenKey := fmt.Sprintf("import-token-%s", attrs.CN)
	b.mu.Lock()
	b.importTokens[importTokenKey] = privateKeyBytes
	b.mu.Unlock()

	// Set expiration to 24 hours from now
	expiresAt := time.Now().Add(24 * time.Hour)

	// Determine key spec from attributes
	keySpec := ""
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
			keySpec = fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		} else {
			keySpec = "RSA_2048"
		}
	case x509.ECDSA:
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
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if len(keyMaterial) == 0 {
		return nil, &errs.Message{Msg: "key material cannot be empty"}
	}
	if params == nil {
		return nil, &errs.Message{Msg: "import parameters cannot be nil"}
	}
	if params.WrappingPublicKey == nil {
		return nil, &errs.Message{Msg: "wrapping public key cannot be nil"}
	}

	// Extract the RSA public key from the interface
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, &errs.Message{Msg: "wrapping public key must be an *rsa.PublicKey"}
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
		return nil, &errs.Detail{Err: ErrInvalidAlgorithm, Detail: params.Algorithm.String()}
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

// UnwrapKey unwraps key material that was previously wrapped with WrapKey.
// For Azure Key Vault, we perform unwrapping locally using the temporary private key
// that was generated during GetImportParameters.
//
// The returned byte slice contains plaintext key material; callers MUST
// move it into a *secure.Buffer immediately and wipe the returned slice
// once the data has been copied out. See importKeyMaterial for the
// canonical handling pattern.
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if wrapped == nil {
		return nil, &errs.Message{Msg: "wrapped key material cannot be nil"}
	}
	if params == nil {
		return nil, &errs.Message{Msg: "import parameters cannot be nil"}
	}
	if len(wrapped.ImportToken) == 0 {
		return nil, &errs.Message{Msg: "import token is required"}
	}

	// Parse the private key from the import token
	privateKey, err := x509.ParsePKCS1PrivateKey(wrapped.ImportToken)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse private key from import token", Err: err}
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
		return nil, &errs.Detail{Err: ErrInvalidAlgorithm, Detail: wrapped.Algorithm.String()}
	}

	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to unwrap key material", Err: err}
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
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return &errs.Message{Msg: "attributes cannot be nil"}
	}
	if wrapped == nil {
		return &errs.Message{Msg: "wrapped key material cannot be nil"}
	}
	if len(wrapped.ImportToken) == 0 {
		return &errs.Message{Msg: "import token is required"}
	}
	if len(wrapped.WrappedKey) == 0 {
		return &errs.Message{Msg: "wrapped key material is empty"}
	}

	if err := b.initClient(ctx); err != nil {
		return err
	}

	// Unwrap the key material into an ordinary slice (provided by the
	// shared wrapping library), then immediately stage the plaintext
	// into a memguard-backed Buffer and wipe the original slice. The
	// Buffer is destroyed by the deferred cleanup in importRSAKey /
	// importECDSAKey before those functions return.
	params := &backend.ImportParameters{
		ImportToken: wrapped.ImportToken,
		Algorithm:   wrapped.Algorithm,
	}
	keyMaterial, err := b.UnwrapKey(ctx, wrapped, params)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to unwrap key material", Err: err}
	}
	if len(keyMaterial) == 0 {
		return &errs.Message{Msg: "unwrapped key material is empty"}
	}
	keyBuf, err := secure.NewBuffer(len(keyMaterial))
	if err != nil {
		secure.Wipe(keyMaterial)
		return &errs.Wrapped{Msg: "failed to allocate secure buffer", Err: err}
	}
	copy(keyBuf.Bytes(), keyMaterial)
	secure.Wipe(keyMaterial)

	// Import the key based on its type. The callee owns keyBuf and
	// MUST destroy it before returning; no plaintext leaves this
	// scope on the ordinary heap.
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return b.importRSAKey(ctx, attrs, keyBuf)
	case x509.ECDSA:
		return b.importECDSAKey(ctx, attrs, keyBuf)
	default:
		keyBuf.Destroy()
		return &errs.Detail{Err: backend.ErrNotSupported, Detail: fmt.Sprintf("cannot import keys of type %s", attrs.KeyAlgorithm)}
	}
}

// importRSAKey imports an RSA private key into Azure Key Vault. The
// keyBuf argument holds the plaintext private key bytes inside a
// memguard enclave; the buffer is destroyed before this function
// returns so the plaintext never outlives the call.
func (b *Backend) importRSAKey(ctx context.Context, attrs *types.KeyAttributes, keyBuf *secure.Buffer) error {
	defer keyBuf.Destroy()

	// Parse the RSA private key directly from the enclaved bytes. The
	// crypto/x509 parser copies the material it needs into a
	// freshly-allocated *rsa.PrivateKey; that key still lives on the
	// ordinary heap but is unavoidable — Azure Key Vault's JWK import
	// path consumes a standard crypto/rsa type.
	keyMaterial := keyBuf.Bytes()
	privateKey, err := x509.ParsePKCS8PrivateKey(keyMaterial)
	if err != nil {
		// Try PKCS#1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(keyMaterial)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to parse RSA private key", Err: err}
		}
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return &errs.Message{Msg: "key material is not an RSA private key"}
	}

	// Convert to standard JWK format using the jwk package
	standardJWK, err := jwk.FromPrivateKey(rsaKey)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to convert RSA key to JWK", Err: err}
	}

	// Set key operations based on key type
	var keyOps []*azkeys.KeyOperation
	switch attrs.KeyType {
	case backend.KEY_TYPE_SIGNING:
		keyOps = []*azkeys.KeyOperation{
			ptrKeyOp(azkeys.KeyOperationSign),
			ptrKeyOp(azkeys.KeyOperationVerify),
		}
	case backend.KEY_TYPE_ENCRYPTION:
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
		return &errs.Wrapped{Msg: "failed to convert JWK to Azure format", Err: err}
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
		return &errs.Wrapped{Msg: "failed to import RSA key into Azure Key Vault", Err: err}
	}

	// Store metadata
	metadata := map[string]interface{}{
		"cn":          attrs.CN,
		"algorithm":   attrs.KeyAlgorithm.String(),
		"key_type":    attrs.KeyType.String(), // see the CreateKey comment in azurekv.go
		"imported":    true,
		"import_time": time.Now().Unix(),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
		return &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	// Clean up the temporary import token
	importTokenKey := fmt.Sprintf("import-token-%s", attrs.CN)
	b.mu.Lock()
	delete(b.importTokens, importTokenKey)
	b.mu.Unlock()

	return nil
}

// importECDSAKey imports an ECDSA private key into Azure Key Vault.
// The keyBuf argument holds the plaintext private key bytes inside a
// memguard enclave; the buffer is destroyed before this function
// returns so the plaintext never outlives the call.
func (b *Backend) importECDSAKey(ctx context.Context, attrs *types.KeyAttributes, keyBuf *secure.Buffer) error {
	defer keyBuf.Destroy()

	keyMaterial := keyBuf.Bytes()
	privateKey, err := x509.ParsePKCS8PrivateKey(keyMaterial)
	if err != nil {
		// Try EC private key format
		privateKey, err = x509.ParseECPrivateKey(keyMaterial)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to parse ECDSA private key", Err: err}
		}
	}

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return &errs.Message{Msg: "key material is not an ECDSA private key"}
	}

	// Convert to standard JWK format using the jwk package
	standardJWK, err := jwk.FromPrivateKey(ecKey)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to convert ECDSA key to JWK", Err: err}
	}

	// Set key operations
	keyOps := []*azkeys.KeyOperation{
		ptrKeyOp(azkeys.KeyOperationSign),
		ptrKeyOp(azkeys.KeyOperationVerify),
	}

	// Convert standard JWK to Azure's JWK format
	azureJWK, err := convertToAzureJWK(standardJWK, keyOps)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to convert JWK to Azure format", Err: err}
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
		return &errs.Wrapped{Msg: "failed to import ECDSA key into Azure Key Vault", Err: err}
	}

	// Store metadata
	metadata := map[string]interface{}{
		"cn":          attrs.CN,
		"algorithm":   attrs.KeyAlgorithm.String(),
		"key_type":    attrs.KeyType.String(), // see the CreateKey comment in azurekv.go
		"imported":    true,
		"import_time": time.Now().Unix(),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return &errs.Wrapped{Msg: "failed to marshal metadata", Err: err}
	}

	if err := storage.SaveKey(ctx, b.config.KeyStorage, attrs.CN, metadataBytes); err != nil {
		return &errs.Wrapped{Msg: "failed to store metadata", Err: err}
	}

	// Clean up the temporary import token
	importTokenKey := fmt.Sprintf("import-token-%s", attrs.CN)
	b.mu.Lock()
	delete(b.importTokens, importTokenKey)
	b.mu.Unlock()

	return nil
}

// ExportKey exports a key in wrapped form for secure transport.
// Azure Key Vault does not support exporting private keys directly.
// This method returns ErrNotSupported.
//
// Capabilities().Export is unconditionally false for this backend, so
// there is no attrs.Exportable branch to check here, matching the awskms
// and gcpkms ExportKey contracts.
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	return nil, backend.ErrNotSupported
}

// ExportKeyTo is not supported for the same reason ExportKey is not: Azure
// Key Vault does not expose an API to release private key material, so
// there is no plaintext for this backend to wrap for a destination's
// parameters in the first place.
func (b *Backend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if dstParams == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "destination import parameters cannot be nil"}
	}
	return nil, &errs.Detail{Err: backend.ErrExportToUnsupported, Detail: "Azure Key Vault does not support releasing private key material for re-wrapping"}
}

// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
// Azure Key Vault does not support exporting raw key material.
// This method returns ErrNotSupported.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Azure Key Vault does not support exporting raw key material
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
			return nil, &errs.Wrapped{Msg: "failed to decode N", Err: err}
		}
		azureJWK.N = n

		e, err := base64.RawURLEncoding.DecodeString(standardJWK.E)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to decode E", Err: err}
		}
		azureJWK.E = e

		// Private key parameters (if present)
		if standardJWK.D != "" {
			d, err := base64.RawURLEncoding.DecodeString(standardJWK.D)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode D", Err: err}
			}
			azureJWK.D = d

			p, err := base64.RawURLEncoding.DecodeString(standardJWK.P)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode P", Err: err}
			}
			azureJWK.P = p

			q, err := base64.RawURLEncoding.DecodeString(standardJWK.Q)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode Q", Err: err}
			}
			azureJWK.Q = q

			dp, err := base64.RawURLEncoding.DecodeString(standardJWK.DP)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode DP", Err: err}
			}
			azureJWK.DP = dp

			dq, err := base64.RawURLEncoding.DecodeString(standardJWK.DQ)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode DQ", Err: err}
			}
			azureJWK.DQ = dq

			qi, err := base64.RawURLEncoding.DecodeString(standardJWK.QI)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode QI", Err: err}
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
			return nil, &errs.Message{Msg: fmt.Sprintf("unsupported curve: %s", standardJWK.Crv)}
		}
		azureJWK.Crv = &curveName

		// Decode coordinates
		x, err := base64.RawURLEncoding.DecodeString(standardJWK.X)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to decode X", Err: err}
		}
		azureJWK.X = x

		y, err := base64.RawURLEncoding.DecodeString(standardJWK.Y)
		if err != nil {
			return nil, &errs.Wrapped{Msg: "failed to decode Y", Err: err}
		}
		azureJWK.Y = y

		// Private key parameter (if present)
		if standardJWK.D != "" {
			d, err := base64.RawURLEncoding.DecodeString(standardJWK.D)
			if err != nil {
				return nil, &errs.Wrapped{Msg: "failed to decode D", Err: err}
			}
			azureJWK.D = d
		}

	default:
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %s", standardJWK.Kty)}
	}

	return azureJWK, nil
}

// convertFromAzureJWK converts an Azure JSONWebKey to standard JWK format.
// This is useful for exporting keys from Azure Key Vault.
func convertFromAzureJWK(azureJWK *azkeys.JSONWebKey) (*jwk.JWK, error) {
	if azureJWK.Kty == nil {
		return nil, &errs.Message{Msg: "key type is required"}
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
				return nil, &errs.Message{Msg: fmt.Sprintf("unsupported curve: %v", *azureJWK.Crv)}
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
		return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %v", *azureJWK.Kty)}
	}

	return standardJWK, nil
}
