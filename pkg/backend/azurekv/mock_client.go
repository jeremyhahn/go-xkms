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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
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
		return azkeys.CreateKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("key already exists: %s", name)}
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
				return azkeys.CreateKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported curve: %v", *params.Curve)}
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
		return azkeys.CreateKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported key type: %v", *params.Kty)}

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

// GetKey retrieves a key from the mock vault. When version is non-empty, the
// response reports that specific version's public key and KID instead of
// the current one, mirroring how Azure Key Vault serves historical versions
// so tests can verify a Signer/Decrypter stays pinned across a rotation.
func (m *MockKeyVaultClient) GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	if m.getErr != nil {
		return azkeys.GetKeyResponse{}, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[name]
	if !exists {
		return azkeys.GetKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("key not found: %s", name)}
	}

	resolvedVersion := mock.version
	publicKey := mock.publicKey
	if version != "" {
		ver, ok := mock.versions[version]
		if !ok {
			return azkeys.GetKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("key version not found: %s/%s", name, version)}
		}
		resolvedVersion = version
		publicKey = ver.publicKey
	}

	// For symmetric keys, we skip public key encoding (oct keys have no public component)
	// Return the response with the key ID and type information
	if publicKey == nil {
		// This is a symmetric key - build response without public key bytes
		keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, resolvedVersion))
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

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
	case *ecdsa.PublicKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
	default:
		return azkeys.GetKeyResponse{}, &errs.Message{Msg: "unsupported public key type"}
	}

	if err != nil {
		return azkeys.GetKeyResponse{}, err
	}

	// Build response
	keyID := azkeys.ID(fmt.Sprintf("https://mock-vault.vault.azure.net/keys/%s/%s", name, resolvedVersion))
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
		return azkeys.DeleteKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("key not found: %s", name)}
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

// Sign signs a digest using a key from the mock vault. When keyVersion is
// non-empty, signing uses that specific version's private key instead of
// the current one, mirroring how Azure Key Vault serves historical versions
// so tests can verify a Signer stays pinned across a rotation.
func (m *MockKeyVaultClient) Sign(ctx context.Context, keyName, keyVersion string, params azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error) {
	if m.signErr != nil {
		return azkeys.SignResponse{}, m.signErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[keyName]
	if !exists {
		return azkeys.SignResponse{}, &errs.Message{Msg: fmt.Sprintf("key not found: %s", keyName)}
	}

	signingKey := mock.privateKey
	if keyVersion != "" {
		ver, ok := mock.versions[keyVersion]
		if !ok {
			return azkeys.SignResponse{}, &errs.Message{Msg: fmt.Sprintf("key version not found: %s/%s", keyName, keyVersion)}
		}
		signingKey = ver.privateKey
	}

	// Perform signing based on key type
	var signature []byte
	var err error

	switch priv := signingKey.(type) {
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
			return azkeys.SignResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported hash size: %d bytes", len(params.Value))}
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
		return azkeys.SignResponse{}, &errs.Message{Msg: "unsupported private key type"}
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
		return azkeys.VerifyResponse{}, &errs.Message{Msg: fmt.Sprintf("key not found: %s", keyName)}
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
				return azkeys.VerifyResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported hash size: %d bytes", len(params.Digest))}
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
			return azkeys.VerifyResponse{}, &errs.Message{Msg: "unsupported public key type"}
		}
	}

	response := azkeys.VerifyResponse{
		KeyVerifyResult: azkeys.KeyVerifyResult{
			Value: &valid,
		},
	}

	return response, nil
}

// GetPublicKey retrieves the public key in PEM format. When version is
// non-empty, it returns that specific version's public key instead of the
// current one, mirroring how Azure Key Vault serves historical versions.
func (m *MockKeyVaultClient) GetPublicKey(ctx context.Context, name, version string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[name]
	if !exists {
		return nil, &errs.Message{Msg: fmt.Sprintf("key not found: %s", name)}
	}

	publicKey := mock.publicKey
	if version != "" {
		ver, ok := mock.versions[version]
		if !ok {
			return nil, &errs.Message{Msg: fmt.Sprintf("key version not found: %s/%s", name, version)}
		}
		publicKey = ver.publicKey
	}

	// Symmetric keys do not have a public key component
	if publicKey == nil {
		return nil, &errs.Message{Msg: fmt.Sprintf("symmetric keys do not have public keys: %s", name)}
	}

	// Marshal public key to PKIX format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
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

// Decrypt decrypts ciphertext using a key from the mock vault. When
// keyVersion is non-empty, decryption uses that specific version's private
// key instead of the current one, mirroring how Azure Key Vault serves
// historical versions so tests can verify a Decrypter stays pinned across a
// rotation.
func (m *MockKeyVaultClient) Decrypt(ctx context.Context, keyName, keyVersion string, params azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	if m.decryptErr != nil {
		return azkeys.DecryptResponse{}, m.decryptErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	mock, exists := m.keys[keyName]
	if !exists {
		return azkeys.DecryptResponse{}, &errs.Message{Msg: fmt.Sprintf("key not found: %s", keyName)}
	}

	decryptKey := mock.privateKey
	if keyVersion != "" {
		ver, ok := mock.versions[keyVersion]
		if !ok {
			return azkeys.DecryptResponse{}, &errs.Message{Msg: fmt.Sprintf("key version not found: %s/%s", keyName, keyVersion)}
		}
		decryptKey = ver.privateKey
	}

	// Perform decryption based on key type and algorithm
	var plaintext []byte
	var err error

	switch priv := decryptKey.(type) {
	case *rsa.PrivateKey:
		// Determine decryption algorithm from params
		if params.Algorithm == nil {
			return azkeys.DecryptResponse{}, &errs.Message{Msg: "algorithm must be specified"}
		}

		switch *params.Algorithm {
		case azkeys.EncryptionAlgorithmRSA15:
			// PKCS#1 v1.5 padding
			plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, priv, params.Value) //nolint:staticcheck // SA1019: mocking Azure Key Vault's EncryptionAlgorithmRSA15, which azurekvDecrypter.Decrypt (azurekv.go) exposes for legacy/compatibility mode
		case azkeys.EncryptionAlgorithmRSAOAEP:
			// OAEP with SHA1
			plaintext, err = rsa.DecryptOAEP(crypto.SHA1.New(), rand.Reader, priv, params.Value, nil)
		case azkeys.EncryptionAlgorithmRSAOAEP256:
			// OAEP with SHA256
			plaintext, err = rsa.DecryptOAEP(crypto.SHA256.New(), rand.Reader, priv, params.Value, nil)
		default:
			return azkeys.DecryptResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported encryption algorithm: %v", *params.Algorithm)}
		}
	default:
		return azkeys.DecryptResponse{}, &errs.Message{Msg: "unsupported private key type for decryption"}
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

// RotateKey rotates a key in the mock vault by creating a new version.
func (m *MockKeyVaultClient) RotateKey(ctx context.Context, name string, options *azkeys.RotateKeyOptions) (azkeys.RotateKeyResponse, error) {
	if m.rotateErr != nil {
		return azkeys.RotateKeyResponse{}, m.rotateErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	mock, exists := m.keys[name]
	if !exists {
		return azkeys.RotateKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("key not found: %s", name)}
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
		_, _ = fmt.Sscanf(mock.version, "%d", &v) // best-effort parse; v keeps its default of 1 on failure
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
				return azkeys.RotateKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported curve: %v", *mock.curve)}
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
		return azkeys.RotateKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("key rotation not supported for key type: %v", mock.keyType)}
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
		return azkeys.ImportKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("key already exists: %s", name)}
	}

	// Import the key from JWK format
	jwk := params.Key
	if jwk == nil {
		return azkeys.ImportKeyResponse{}, &errs.Message{Msg: "key cannot be nil"}
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
				return azkeys.ImportKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported curve: %v", *jwk.Crv)}
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
		return azkeys.ImportKeyResponse{}, &errs.Message{Msg: fmt.Sprintf("unsupported key type for import: %v", *jwk.Kty)}
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

// MockSecretsClient is a mock implementation of the SecretsClient interface
// for testing. It mirrors MockKeyVaultClient's shape (in-memory storage,
// SetXError error injection) so GenerateSymmetricKey/GetSymmetricKey --
// which call SecretsClient rather than KeyVaultClient -- can be exercised
// the same way CreateKey/GetKey already are, without a live Azure Key
// Vault. It lives here rather than in a _test.go file so it can be shared
// across package boundaries (e.g. pkg/seal's cloud-seal-strategy tests)
// exactly as MockKeyVaultClient already is.
type MockSecretsClient struct {
	secrets  map[string]*string // name -> stored value; a present key with a nil value simulates a secret Azure reports with no Value
	setCalls int
	setErr   error
	getErr   error
	mu       sync.RWMutex
}

// NewMockSecretsClient creates a new mock Azure Key Vault secrets client for testing.
func NewMockSecretsClient() *MockSecretsClient {
	return &MockSecretsClient{
		secrets: make(map[string]*string),
	}
}

// SetSetError sets an error to be returned by SetSecret operations.
func (m *MockSecretsClient) SetSetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setErr = err
}

// SetGetError sets an error to be returned by GetSecret operations.
func (m *MockSecretsClient) SetGetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getErr = err
}

// SetSecretValue directly stores value under name, bypassing SetSecret. This
// lets tests simulate secret data GenerateSymmetricKey itself would never
// produce -- a nil value, or content that is not valid base64 -- so
// GetSymmetricKey's handling of malformed Key Vault data can be exercised.
func (m *MockSecretsClient) SetSecretValue(name string, value *string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[name] = value
}

// DeleteSecretValue removes name, simulating a secret deleted directly in
// Key Vault out of band from this backend's in-memory metadata (which
// still records the key from an earlier GenerateSymmetricKey call).
func (m *MockSecretsClient) DeleteSecretValue(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, name)
}

// SetSecretCallCount returns the number of times SetSecret has succeeded
// (i.e. was called while no setErr was configured), letting tests assert a
// symmetric key is generated exactly once even when a caller such as
// seal.EnsureSealKey provisions idempotently across multiple calls.
func (m *MockSecretsClient) SetSecretCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.setCalls
}

// SetSecret stores a secret in the mock vault.
func (m *MockSecretsClient) SetSecret(ctx context.Context, name string, params azsecrets.SetSecretParameters, options *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.setErr != nil {
		return azsecrets.SetSecretResponse{}, m.setErr
	}

	m.secrets[name] = params.Value
	m.setCalls++

	return azsecrets.SetSecretResponse{
		Secret: azsecrets.Secret{Value: params.Value},
	}, nil
}

// GetSecret retrieves a secret from the mock vault. A name with no stored
// entry returns a "not found" error, mirroring how MockKeyVaultClient.GetKey
// reports a missing key.
func (m *MockSecretsClient) GetSecret(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getErr != nil {
		return azsecrets.GetSecretResponse{}, m.getErr
	}

	value, exists := m.secrets[name]
	if !exists {
		return azsecrets.GetSecretResponse{}, &errs.Message{Msg: fmt.Sprintf("secret not found: %s", name)}
	}

	return azsecrets.GetSecretResponse{
		Secret: azsecrets.Secret{Value: value},
	}, nil
}
