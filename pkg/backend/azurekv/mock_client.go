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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// MockKeyVaultClient is a mock implementation of the KeyVaultClient interface for testing.
type MockKeyVaultClient struct {
	keys       map[string]*mockKey
	mu         sync.RWMutex
	createErr  error
	getErr     error
	deleteErr  error
	signErr    error
	decryptErr error
	wrapErr    error
	unwrapErr  error
	rotateErr  error
}

// mockKey represents a stored key with its properties.
type mockKey struct {
	name       string
	keyType    azkeys.KeyType
	curve      *azkeys.CurveName
	keySize    *int32
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
	enabled    bool
	version    string
	// versions stores all key versions (version -> key pair)
	// This is needed to verify signatures created with old versions after rotation
	versions map[string]*keyVersion
}

type keyVersion struct {
	publicKey  crypto.PublicKey
	privateKey crypto.PrivateKey
}

// NewMockKeyVaultClient creates a new mock Azure Key Vault client for testing.
func NewMockKeyVaultClient() *MockKeyVaultClient {
	return &MockKeyVaultClient{
		keys: make(map[string]*mockKey),
	}
}

// SetCreateError sets an error to be returned by CreateKey operations.
func (m *MockKeyVaultClient) SetCreateError(err error) {
	m.createErr = err
}

// SetGetError sets an error to be returned by GetKey operations.
func (m *MockKeyVaultClient) SetGetError(err error) {
	m.getErr = err
}

// SetDeleteError sets an error to be returned by DeleteKey operations.
func (m *MockKeyVaultClient) SetDeleteError(err error) {
	m.deleteErr = err
}

// SetSignError sets an error to be returned by Sign operations.
func (m *MockKeyVaultClient) SetSignError(err error) {
	m.signErr = err
}

// SetDecryptError sets an error to be returned by Decrypt operations.
func (m *MockKeyVaultClient) SetDecryptError(err error) {
	m.decryptErr = err
}

// SetWrapError sets an error to be returned by WrapKey operations.
func (m *MockKeyVaultClient) SetWrapError(err error) {
	m.wrapErr = err
}

// SetUnwrapError sets an error to be returned by UnwrapKey operations.
func (m *MockKeyVaultClient) SetUnwrapError(err error) {
	m.unwrapErr = err
}

// SetRotateError sets an error to be returned by RotateKey operations.
func (m *MockKeyVaultClient) SetRotateError(err error) {
	m.rotateErr = err
}

// CreateKey creates a new key in the mock vault.
func (m *MockKeyVaultClient) CreateKey(ctx context.Context, name string, params azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error) {
	if m.createErr != nil {
		return azkeys.CreateKeyResponse{}, m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if key already exists
	if _, exists := m.keys[name]; exists {
		return azkeys.CreateKeyResponse{}, fmt.Errorf("key already exists: %s", name)
	}

	// Create the key based on type
	mock := &mockKey{
		name:     name,
		keyType:  *params.Kty,
		enabled:  true,
		version:  "1",
		versions: make(map[string]*keyVersion),
	}

	var err error
	switch *params.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		keySize := int32(2048)
		if params.KeySize != nil {
			keySize = *params.KeySize
		}
		mock.keySize = &keySize
		mock.privateKey, err = rsa.GenerateKey(rand.Reader, int(keySize))
		if err != nil {
			return azkeys.CreateKeyResponse{}, err
		}
		mock.publicKey = &mock.privateKey.(*rsa.PrivateKey).PublicKey
		// Store the initial version
		mock.versions["1"] = &keyVersion{
			publicKey:  mock.publicKey,
			privateKey: mock.privateKey,
		}

	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		var curve elliptic.Curve
		if params.Curve != nil {
			mock.curve = params.Curve
			switch *params.Curve {
			case azkeys.CurveNameP256:
				curve = elliptic.P256()
			case azkeys.CurveNameP384:
				curve = elliptic.P384()
			case azkeys.CurveNameP521:
				curve = elliptic.P521()
			default:
				return azkeys.CreateKeyResponse{}, fmt.Errorf("unsupported curve: %v", *params.Curve)
			}
		} else {
			// Default to P-256
			curve = elliptic.P256()
			p256 := azkeys.CurveNameP256
			mock.curve = &p256
		}

		mock.privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return azkeys.CreateKeyResponse{}, err
		}
		mock.publicKey = &mock.privateKey.(*ecdsa.PrivateKey).PublicKey
		// Store the initial version
		mock.versions["1"] = &keyVersion{
			publicKey:  mock.publicKey,
			privateKey: mock.privateKey,
		}

	case azkeys.KeyTypeOct, azkeys.KeyTypeOctHSM:
		// Symmetric key (octet sequence)
		keySize := int32(256) // Default to 256 bits (AES-256)
		if params.KeySize != nil {
			keySize = *params.KeySize
		}
		mock.keySize = &keySize
		// For symmetric keys, we store random bytes as the "private key"
		// The key size is in bits, convert to bytes
		secretBytes := make([]byte, keySize/8)
		if _, err := rand.Read(secretBytes); err != nil {
			return azkeys.CreateKeyResponse{}, err
		}
		mock.privateKey = secretBytes
		// Symmetric keys do not have a public key component
		mock.publicKey = nil

	default:
		return azkeys.CreateKeyResponse{}, fmt.Errorf("unsupported key type: %v", *params.Kty)

	}

	m.keys[name] = mock

	// Build response
	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, mock.version))
	enabled := true

	response := azkeys.CreateKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{
				KID: &keyID,
				Kty: params.Kty,
				Crv: mock.curve,
			},
			Attributes: &azkeys.KeyAttributes{
				Enabled: &enabled,
			},
		},
	}

	return response, nil
}

// GetKey retrieves a key from the mock vault.
func (m *MockKeyVaultClient) GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	if m.getErr != nil {
		return azkeys.GetKeyResponse{}, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[name]
	if !exists {
		return azkeys.GetKeyResponse{}, fmt.Errorf("key not found: %s", name)
	}

	// For symmetric keys, we skip public key encoding (oct keys have no public component)
	// Return the response with the key ID and type information
	if mock.publicKey == nil {
		// This is a symmetric key - build response without public key bytes
		keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, mock.version))
		enabled := true
		return azkeys.GetKeyResponse{
			KeyBundle: azkeys.KeyBundle{
				Key: &azkeys.JSONWebKey{
					KID: &keyID,
					Kty: &mock.keyType,
				},
				Attributes: &azkeys.KeyAttributes{
					Enabled: &enabled,
				},
			},
		}, nil
	}

	// Encode public key to PKIX format (simplified for mock)
	var pubKeyBytes []byte
	var err error

	switch pub := mock.publicKey.(type) {
	case *rsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
	case *ecdsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
	default:
		return azkeys.GetKeyResponse{}, fmt.Errorf("unsupported public key type")
	}

	if err != nil {
		return azkeys.GetKeyResponse{}, err
	}

	// Build response
	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, mock.version))
	enabled := true

	response := azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{
				KID: &keyID,
				Kty: &mock.keyType,
				Crv: mock.curve,
				N:   pubKeyBytes, // Simplified - stores PKIX bytes instead of proper JWK encoding
			},
			Attributes: &azkeys.KeyAttributes{
				Enabled: &enabled,
			},
		},
	}

	return response, nil
}

// DeleteKey deletes a key from the mock vault.
func (m *MockKeyVaultClient) DeleteKey(ctx context.Context, name string, options *azkeys.DeleteKeyOptions) (azkeys.DeleteKeyResponse, error) {
	if m.deleteErr != nil {
		return azkeys.DeleteKeyResponse{}, m.deleteErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	mock, exists := m.keys[name]
	if !exists {
		return azkeys.DeleteKeyResponse{}, fmt.Errorf("key not found: %s", name)
	}

	delete(m.keys, name)

	// Build response
	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, mock.version))
	enabled := true
	response := azkeys.DeleteKeyResponse{
		DeletedKey: azkeys.DeletedKey{
			Key: &azkeys.JSONWebKey{
				KID: &keyID,
				Kty: &mock.keyType,
			},
			Attributes: &azkeys.KeyAttributes{
				Enabled: &enabled,
			},
		},
	}

	return response, nil
}

// Sign signs a digest using a key from the mock vault.
func (m *MockKeyVaultClient) Sign(ctx context.Context, keyName, keyVersion string, params azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	if m.signErr != nil {
		return azkeys.SignResponse{}, m.signErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[keyName]
	if !exists {
		return azkeys.SignResponse{}, fmt.Errorf("key not found: %s", keyName)
	}

	// Perform signing based on key type
	var signature []byte
	var err error

	switch priv := mock.privateKey.(type) {
	case *rsa.PrivateKey:
		// Determine hash algorithm from digest size
		var hashType crypto.Hash
		switch len(params.Value) {
		case 32: // SHA-256
			hashType = crypto.SHA256
		case 48: // SHA-384
			hashType = crypto.SHA384
		case 64: // SHA-512
			hashType = crypto.SHA512
		default:
			return azkeys.SignResponse{}, fmt.Errorf("unsupported hash size: %d bytes", len(params.Value))
		}

		// Check if PSS algorithm is requested
		if params.Algorithm != nil {
			switch *params.Algorithm {
			case azkeys.SignatureAlgorithmPS256, azkeys.SignatureAlgorithmPS384, azkeys.SignatureAlgorithmPS512:
				// Use RSA-PSS signing
				pssOpts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       hashType,
				}
				signature, err = rsa.SignPSS(rand.Reader, priv, hashType, params.Value, pssOpts)
			default:
				// Use PKCS1v15 signing (RS256, RS384, RS512)
				signature, err = rsa.SignPKCS1v15(rand.Reader, priv, hashType, params.Value)
			}
		} else {
			// Default to PKCS1v15 signing
			signature, err = rsa.SignPKCS1v15(rand.Reader, priv, hashType, params.Value)
		}
	case *ecdsa.PrivateKey:
		// For ECDSA, use ASN.1 DER encoding
		r, s, signErr := ecdsa.Sign(rand.Reader, priv, params.Value)
		if signErr != nil {
			err = signErr
		} else {
			// Encode signature in ASN.1 DER format
			signature, err = encodeECDSASignature(r, s)
		}
	default:
		return azkeys.SignResponse{}, fmt.Errorf("unsupported private key type")
	}

	if err != nil {
		return azkeys.SignResponse{}, err
	}

	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", keyName, mock.version))
	response := azkeys.SignResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			KID:    &keyID,
			Result: signature,
		},
	}

	return response, nil
}

// Verify verifies a signature using a key from the mock vault.
func (m *MockKeyVaultClient) Verify(ctx context.Context, keyName, keyVersion string, params azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[keyName]
	if !exists {
		return azkeys.VerifyResponse{}, fmt.Errorf("key not found: %s", keyName)
	}

	// If a specific version is requested, use only that version
	// If no version is specified (empty string), try all versions (most recent first)
	var publicKeysToTry []crypto.PublicKey
	if keyVersion != "" {
		// Use specific version
		if mock.versions != nil {
			if ver, ok := mock.versions[keyVersion]; ok {
				publicKeysToTry = []crypto.PublicKey{ver.publicKey}
			}
		}
		if len(publicKeysToTry) == 0 {
			// Fallback to current if version not found
			publicKeysToTry = []crypto.PublicKey{mock.publicKey}
		}
	} else {
		// No version specified - try current version first, then all other versions
		// This allows verification of signatures created with old versions
		publicKeysToTry = []crypto.PublicKey{mock.publicKey}
		if mock.versions != nil {
			for _, ver := range mock.versions {
				// Skip if it's the same as current (already added)
				if ver.publicKey != mock.publicKey {
					publicKeysToTry = append(publicKeysToTry, ver.publicKey)
				}
			}
		}
	}

	// Try to verify with each public key
	var valid bool
	for _, pubKey := range publicKeysToTry {
		switch pub := pubKey.(type) {
		case *rsa.PublicKey:
			// Determine hash algorithm from digest size
			var hashType crypto.Hash
			switch len(params.Digest) {
			case 32: // SHA-256
				hashType = crypto.SHA256
			case 48: // SHA-384
				hashType = crypto.SHA384
			case 64: // SHA-512
				hashType = crypto.SHA512
			default:
				return azkeys.VerifyResponse{}, fmt.Errorf("unsupported hash size: %d bytes", len(params.Digest))
			}

			// Check if PSS algorithm is requested
			var err error
			if params.Algorithm != nil {
				switch *params.Algorithm {
				case azkeys.SignatureAlgorithmPS256, azkeys.SignatureAlgorithmPS384, azkeys.SignatureAlgorithmPS512:
					// Use RSA-PSS verification
					pssOpts := &rsa.PSSOptions{
						SaltLength: rsa.PSSSaltLengthAuto,
						Hash:       hashType,
					}
					err = rsa.VerifyPSS(pub, hashType, params.Digest, params.Signature, pssOpts)
				default:
					// Use PKCS1v15 verification (RS256, RS384, RS512)
					err = rsa.VerifyPKCS1v15(pub, hashType, params.Digest, params.Signature)
				}
			} else {
				// Default to PKCS1v15 verification
				err = rsa.VerifyPKCS1v15(pub, hashType, params.Digest, params.Signature)
			}
			if err == nil {
				valid = true
				break // Verification succeeded with this version
			}
		case *ecdsa.PublicKey:
			// Decode ECDSA signature from ASN.1 DER format
			r, s, err := decodeECDSASignature(params.Signature)
			if err != nil {
				return azkeys.VerifyResponse{}, err
			}
			if ecdsa.Verify(pub, params.Digest, r, s) {
				valid = true
				break // Verification succeeded with this version
			}
		default:
			return azkeys.VerifyResponse{}, fmt.Errorf("unsupported public key type")
		}
	}

	response := azkeys.VerifyResponse{
		KeyVerifyResult: azkeys.KeyVerifyResult{
			Value: &valid,
		},
	}

	return response, nil
}

// GetPublicKey retrieves the public key in PEM format.
func (m *MockKeyVaultClient) GetPublicKey(ctx context.Context, name, version string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[name]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", name)
	}

	// Symmetric keys do not have a public key component
	if mock.publicKey == nil {
		return nil, fmt.Errorf("symmetric keys do not have public keys: %s", name)
	}

	// Marshal public key to PKIX format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(mock.publicKey)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// Close closes the mock client (no-op for mock).
func (m *MockKeyVaultClient) Close() error {
	return nil
}

// ecdsaSignature represents an ECDSA signature in ASN.1 DER format.
type ecdsaSignature struct {
	R, S *big.Int
}

// encodeECDSASignature encodes r and s values into ASN.1 DER format.
func encodeECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{R: r, S: s})
}

// decodeECDSASignature decodes ASN.1 DER format signature into r and s values.
func decodeECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	var sig ecdsaSignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, nil, err
	}
	return sig.R, sig.S, nil
}

// Decrypt decrypts ciphertext using a key from the mock vault.
func (m *MockKeyVaultClient) Decrypt(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	if m.decryptErr != nil {
		return azkeys.DecryptResponse{}, m.decryptErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[keyName]
	if !exists {
		return azkeys.DecryptResponse{}, fmt.Errorf("key not found: %s", keyName)
	}

	// Perform decryption based on key type and algorithm
	var plaintext []byte
	var err error

	switch priv := mock.privateKey.(type) {
	case *rsa.PrivateKey:
		// Determine decryption algorithm from params
		if params.Algorithm == nil {
			return azkeys.DecryptResponse{}, fmt.Errorf("algorithm must be specified")
		}

		switch *params.Algorithm {
		case azkeys.EncryptionAlgorithmRSA15:
			// PKCS#1 v1.5 padding
			plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, priv, params.Value)
		case azkeys.EncryptionAlgorithmRSAOAEP:
			// OAEP with SHA1
			plaintext, err = rsa.DecryptOAEP(crypto.SHA1.New(), rand.Reader, priv, params.Value, nil)
		case azkeys.EncryptionAlgorithmRSAOAEP256:
			// OAEP with SHA256
			plaintext, err = rsa.DecryptOAEP(crypto.SHA256.New(), rand.Reader, priv, params.Value, nil)
		default:
			return azkeys.DecryptResponse{}, fmt.Errorf("unsupported encryption algorithm: %v", *params.Algorithm)
		}
	default:
		return azkeys.DecryptResponse{}, fmt.Errorf("unsupported private key type for decryption")
	}

	if err != nil {
		return azkeys.DecryptResponse{}, err
	}

	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", keyName, mock.version))
	response := azkeys.DecryptResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			KID:    &keyID,
			Result: plaintext,
		},
	}

	return response, nil
}

// WrapKey wraps (encrypts) a key using a key from the mock vault.
func (m *MockKeyVaultClient) WrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	if m.wrapErr != nil {
		return azkeys.WrapKeyResponse{}, m.wrapErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[keyName]
	if !exists {
		return azkeys.WrapKeyResponse{}, fmt.Errorf("key not found: %s", keyName)
	}

	// For symmetric keys (oct type), perform AES key wrapping
	// For simplicity in the mock, we'll just XOR the value with a fixed pattern
	// In production, this would use proper AES-KW algorithm
	wrappedKey := make([]byte, len(params.Value))
	copy(wrappedKey, params.Value)

	// Simple obfuscation for mock (not cryptographically secure)
	if secretBytes, ok := mock.privateKey.([]byte); ok {
		for i := range wrappedKey {
			wrappedKey[i] ^= secretBytes[i%len(secretBytes)]
		}
	}

	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", keyName, mock.version))
	response := azkeys.WrapKeyResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			KID:    &keyID,
			Result: wrappedKey,
		},
	}

	return response, nil
}

// UnwrapKey unwraps (decrypts) a key using a key from the mock vault.
func (m *MockKeyVaultClient) UnwrapKey(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	if m.unwrapErr != nil {
		return azkeys.UnwrapKeyResponse{}, m.unwrapErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[keyName]
	if !exists {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("key not found: %s", keyName)
	}

	// For symmetric keys (oct type), perform AES key unwrapping
	// This is the reverse of WrapKey - apply same XOR to decrypt
	unwrappedKey := make([]byte, len(params.Value))
	copy(unwrappedKey, params.Value)

	// Simple deobfuscation for mock (not cryptographically secure)
	if secretBytes, ok := mock.privateKey.([]byte); ok {
		for i := range unwrappedKey {
			unwrappedKey[i] ^= secretBytes[i%len(secretBytes)]
		}
	}

	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", keyName, mock.version))
	response := azkeys.UnwrapKeyResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			KID:    &keyID,
			Result: unwrappedKey,
		},
	}

	return response, nil
}

// NewListKeyPropertiesPager returns a pager for listing key properties.
// For the mock, we return nil as pagination is not implemented.
func (m *MockKeyVaultClient) NewListKeyPropertiesPager(options *azkeys.ListKeyPropertiesOptions) *runtime.Pager[azkeys.ListKeyPropertiesResponse] {
	// Mock implementation - return nil pager
	// In a real implementation, this would return an actual pager
	return nil
}

// RotateKey rotates a key in the mock vault by creating a new version.
func (m *MockKeyVaultClient) RotateKey(ctx context.Context, name string, options *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error) {
	if m.rotateErr != nil {
		return azkeys.RotateKeyResponse{}, m.rotateErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	mock, exists := m.keys[name]
	if !exists {
		return azkeys.RotateKeyResponse{}, fmt.Errorf("key not found: %s", name)
	}

	// Initialize versions map if not present (for keys created before this fix)
	if mock.versions == nil {
		mock.versions = make(map[string]*keyVersion)
		// Store current version if it exists
		if mock.version != "" && mock.privateKey != nil {
			mock.versions[mock.version] = &keyVersion{
				publicKey:  mock.publicKey,
				privateKey: mock.privateKey,
			}
		}
	}

	// Increment version to simulate rotation
	version := "2" // Simplified - in real implementation, parse and increment
	if mock.version != "" {
		v := 1
		fmt.Sscanf(mock.version, "%d", &v)
		version = fmt.Sprintf("%d", v+1)
	}
	mock.version = version

	// Generate a new key pair (simulating rotation)
	var newPrivateKey crypto.PrivateKey
	var newPublicKey crypto.PublicKey
	var err error
	switch mock.keyType {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		keySize := int(2048)
		if mock.keySize != nil {
			keySize = int(*mock.keySize)
		}
		newPrivateKey, err = rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return azkeys.RotateKeyResponse{}, err
		}
		newPublicKey = &newPrivateKey.(*rsa.PrivateKey).PublicKey

	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		var curve elliptic.Curve
		if mock.curve != nil {
			switch *mock.curve {
			case azkeys.CurveNameP256:
				curve = elliptic.P256()
			case azkeys.CurveNameP384:
				curve = elliptic.P384()
			case azkeys.CurveNameP521:
				curve = elliptic.P521()
			default:
				return azkeys.RotateKeyResponse{}, fmt.Errorf("unsupported curve: %v", *mock.curve)
			}
		} else {
			curve = elliptic.P256()
		}

		newPrivateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return azkeys.RotateKeyResponse{}, err
		}
		newPublicKey = &newPrivateKey.(*ecdsa.PrivateKey).PublicKey

	default:
		return azkeys.RotateKeyResponse{}, fmt.Errorf("key rotation not supported for key type: %v", mock.keyType)
	}

	// Store the new version
	mock.versions[version] = &keyVersion{
		publicKey:  newPublicKey,
		privateKey: newPrivateKey,
	}

	// Update current keys to the new version
	mock.privateKey = newPrivateKey
	mock.publicKey = newPublicKey

	// Build response
	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, mock.version))
	enabled := true

	response := azkeys.RotateKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{
				KID: &keyID,
				Kty: &mock.keyType,
				Crv: mock.curve,
			},
			Attributes: &azkeys.KeyAttributes{
				Enabled: &enabled,
			},
		},
	}

	return response, nil
}

// ImportKey imports a key into the mock vault.
func (m *MockKeyVaultClient) ImportKey(ctx context.Context, name string, params azkeys.ImportKeyParameters, options *azkeys.ImportKeyOptions) (azkeys.ImportKeyResponse, error) {
	if m.createErr != nil {
		return azkeys.ImportKeyResponse{}, m.createErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if key already exists
	if _, exists := m.keys[name]; exists {
		return azkeys.ImportKeyResponse{}, fmt.Errorf("key already exists: %s", name)
	}

	// Import the key from JWK format
	jwk := params.Key
	if jwk == nil {
		return azkeys.ImportKeyResponse{}, fmt.Errorf("key cannot be nil")
	}

	mock := &mockKey{
		name:     name,
		keyType:  *jwk.Kty,
		enabled:  true,
		version:  "1",
		versions: make(map[string]*keyVersion),
	}

	// For import, we don't actually reconstruct the private key from JWK
	// We just store placeholder keys for the mock (since we can't verify actual import in tests)
	var err error
	switch *jwk.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		// Generate a placeholder RSA key
		keySize := int32(2048)
		mock.keySize = &keySize
		mock.privateKey, err = rsa.GenerateKey(rand.Reader, int(keySize))
		if err != nil {
			return azkeys.ImportKeyResponse{}, err
		}
		mock.publicKey = &mock.privateKey.(*rsa.PrivateKey).PublicKey
		// Store the initial version
		mock.versions["1"] = &keyVersion{
			publicKey:  mock.publicKey,
			privateKey: mock.privateKey,
		}

	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		// Generate a placeholder ECDSA key
		var curve elliptic.Curve
		if jwk.Crv != nil {
			mock.curve = jwk.Crv
			switch *jwk.Crv {
			case azkeys.CurveNameP256:
				curve = elliptic.P256()
			case azkeys.CurveNameP384:
				curve = elliptic.P384()
			case azkeys.CurveNameP521:
				curve = elliptic.P521()
			default:
				return azkeys.ImportKeyResponse{}, fmt.Errorf("unsupported curve: %v", *jwk.Crv)
			}
		} else {
			curve = elliptic.P256()
			p256 := azkeys.CurveNameP256
			mock.curve = &p256
		}

		mock.privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return azkeys.ImportKeyResponse{}, err
		}
		mock.publicKey = &mock.privateKey.(*ecdsa.PrivateKey).PublicKey
		// Store the initial version
		mock.versions["1"] = &keyVersion{
			publicKey:  mock.publicKey,
			privateKey: mock.privateKey,
		}

	default:
		return azkeys.ImportKeyResponse{}, fmt.Errorf("unsupported key type for import: %v", *jwk.Kty)
	}

	m.keys[name] = mock

	// Build response
	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, mock.version))
	enabled := true

	response := azkeys.ImportKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: &azkeys.JSONWebKey{
				KID: &keyID,
				Kty: jwk.Kty,
				Crv: mock.curve,
			},
			Attributes: &azkeys.KeyAttributes{
				Enabled: &enabled,
			},
		},
	}

	return response, nil
}
