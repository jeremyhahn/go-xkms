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

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	client "github.com/jeremyhahn/go-keychain/sdk/go"
)

// APIServiceAdapter adapts the global keychain service to the SDK's KeychainServicer interface.
// This enables embedded mode where the CLI operates directly against the keychain
// without network communication.
type APIServiceAdapter struct{}

// NewAPIServiceAdapter creates a new API service adapter.
// The global keychain service must be initialized before calling this.
func NewAPIServiceAdapter() (*APIServiceAdapter, error) {
	if !keychain.IsInitialized() {
		return nil, fmt.Errorf("keychain service not initialized")
	}
	return &APIServiceAdapter{}, nil
}

// Health returns the health status of the service.
func (a *APIServiceAdapter) Health(ctx context.Context) (string, string, error) {
	return "healthy", keychain.Version(), nil
}

// ListBackends returns a list of available backends.
func (a *APIServiceAdapter) ListBackends(ctx context.Context) ([]client.BackendInfo, error) {
	backendNames := keychain.Backends()
	backends := make([]client.BackendInfo, 0, len(backendNames))

	for _, name := range backendNames {
		ks, err := keychain.Backend(name)
		if err != nil {
			continue
		}

		be := ks.Backend()
		caps := be.Capabilities()

		backends = append(backends, client.BackendInfo{
			ID:             name,
			Type:           string(be.Type()),
			HardwareBacked: caps.HardwareBacked,
			Capabilities: map[string]interface{}{
				"signing":    caps.Signing,
				"decryption": caps.Decryption,
				"rotation":   caps.KeyRotation,
			},
		})
	}

	return backends, nil
}

// GetBackend returns information about a specific backend.
func (a *APIServiceAdapter) GetBackend(ctx context.Context, backendID string) (*client.BackendInfo, error) {
	ks, err := keychain.Backend(backendID)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	be := ks.Backend()
	caps := be.Capabilities()

	return &client.BackendInfo{
		ID:             backendID,
		Type:           string(be.Type()),
		HardwareBacked: caps.HardwareBacked,
		Capabilities: map[string]interface{}{
			"signing":    caps.Signing,
			"decryption": caps.Decryption,
			"rotation":   caps.KeyRotation,
		},
	}, nil
}

// GenerateKey generates a new key.
func (a *APIServiceAdapter) GenerateKey(ctx context.Context, req *client.GenerateKeyRequest) (*client.GenerateKeyResponse, error) {
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	// Build key attributes
	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreType(req.Backend),
	}

	var privKey crypto.PrivateKey
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = req.KeyType
	}

	switch {
	case types.AlgorithmRSA.Equals(algorithm):
		keySize := req.KeySize
		if keySize == 0 {
			keySize = types.RSAKeySize2048
		}
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}
		privKey, err = ks.GenerateRSA(attrs)

	case types.AlgorithmECDSA.Equals(algorithm):
		curve := req.Curve
		if curve == "" {
			curve = string(types.CurveP256)
		}
		attrs.KeyAlgorithm = x509.ECDSA
		parsedCurve, curveErr := types.ParseCurve(curve)
		if curveErr != nil {
			return nil, fmt.Errorf("invalid curve: %w", curveErr)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}
		privKey, err = ks.GenerateECDSA(attrs)

	case types.AlgorithmEd25519.Equals(algorithm):
		attrs.KeyAlgorithm = x509.Ed25519
		privKey, err = ks.GenerateEd25519(attrs)

	case types.AlgorithmSymmetric.Equals(algorithm):
		symBackend, ok := ks.Backend().(types.SymmetricBackend)
		if !ok {
			return nil, fmt.Errorf("backend does not support symmetric key generation")
		}

		keySize := req.KeySize
		symAlgorithm := req.Algorithm
		if symAlgorithm == "" || symAlgorithm == "symmetric" {
			switch keySize {
			case 128:
				symAlgorithm = "aes128-gcm"
			case 192:
				symAlgorithm = "aes192-gcm"
			case 256, 0:
				symAlgorithm = "aes256-gcm"
			default:
				return nil, fmt.Errorf("invalid key size for symmetric key: %d", keySize)
			}
		}

		attrs.SymmetricAlgorithm = types.SymmetricAlgorithm(symAlgorithm)
		attrs.KeyType = types.KeyTypeSecret

		_, err = symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
		}

		return &client.GenerateKeyResponse{
			KeyID:   req.KeyID,
			KeyType: req.KeyType,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	pubKeyPEM, err := extractPublicKeyPEM(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return &client.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: pubKeyPEM,
	}, nil
}

// ListKeys returns a list of keys in the specified backend.
func (a *APIServiceAdapter) ListKeys(ctx context.Context, backendName string) (*client.ListKeysResponse, error) {
	if backendName == "" {
		return nil, fmt.Errorf("backend is required")
	}

	ks, err := keychain.Backend(backendName)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	keys := make([]client.KeyInfo, len(attrs))
	for i, attr := range attrs {
		keys[i] = client.KeyInfo{
			KeyID:     attr.CN,
			Backend:   backendName,
			KeyType:   string(attr.KeyType),
			Algorithm: getAlgorithmString(attr),
		}
	}

	return &client.ListKeysResponse{
		Keys: keys,
	}, nil
}

// GetKey returns information about a specific key.
func (a *APIServiceAdapter) GetKey(ctx context.Context, backendName, keyID string) (*client.GetKeyResponse, error) {
	if backendName == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	ks, err := keychain.Backend(backendName)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, keyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	return &client.GetKeyResponse{
		KeyInfo: client.KeyInfo{
			KeyID:     attrs.CN,
			Backend:   backendName,
			KeyType:   string(attrs.KeyType),
			Algorithm: getAlgorithmString(attrs),
		},
	}, nil
}

// DeleteKey deletes a key.
func (a *APIServiceAdapter) DeleteKey(ctx context.Context, backendName, keyID string) error {
	if backendName == "" {
		return fmt.Errorf("backend is required")
	}
	if keyID == "" {
		return fmt.Errorf("key_id is required")
	}

	ks, err := keychain.Backend(backendName)
	if err != nil {
		return fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, keyID)
	if err != nil {
		return fmt.Errorf("key not found: %w", err)
	}

	return ks.DeleteKey(attrs)
}

// Sign signs data with the specified key.
func (a *APIServiceAdapter) Sign(ctx context.Context, req *client.SignRequest) (*client.SignResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer: %w", err)
	}

	// Ed25519 uses pure signing (no prehashing)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		signature, err := signer.Sign(nil, req.Data, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("failed to sign: %w", err)
		}
		return &client.SignResponse{
			Signature: signature,
		}, nil
	}

	// Determine hash algorithm
	hashAlg := parseHashAlgorithm(req.Hash)
	hasher := hashAlg.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	signature, err := signer.Sign(nil, digest, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return &client.SignResponse{
		Signature: signature,
	}, nil
}

// Verify verifies a signature.
func (a *APIServiceAdapter) Verify(ctx context.Context, req *client.VerifyRequest) (*client.VerifyResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data is required")
	}
	if len(req.Signature) == 0 {
		return nil, fmt.Errorf("signature is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	privKey, err := ks.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	var pubKey crypto.PublicKey
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		pubKey = k.Public()
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	hashAlg := parseHashAlgorithm(req.Hash)
	hasher := hashAlg.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	valid := false
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, hashAlg, digest, req.Signature)
		valid = (err == nil)
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(pub, digest, req.Signature)
	case ed25519.PublicKey:
		valid = ed25519.Verify(pub, req.Data, req.Signature)
	}

	return &client.VerifyResponse{
		Valid: valid,
	}, nil
}

// Encrypt encrypts data with the specified key.
func (a *APIServiceAdapter) Encrypt(ctx context.Context, req *client.EncryptRequest) (*client.EncryptResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(req.Plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	symBackend, ok := ks.Backend().(types.SymmetricBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support symmetric encryption")
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
	}

	opts := &types.EncryptOptions{
		AdditionalData: req.AdditionalData,
	}

	encryptedData, err := encrypter.Encrypt(req.Plaintext, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return &client.EncryptResponse{
		Ciphertext: encryptedData.Ciphertext,
		Nonce:      encryptedData.Nonce,
		Tag:        encryptedData.Tag,
	}, nil
}

// Decrypt decrypts data with the specified key.
func (a *APIServiceAdapter) Decrypt(ctx context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	var plaintext []byte

	if attrs.IsSymmetric() {
		symBackend, ok := ks.Backend().(types.SymmetricBackend)
		if !ok {
			return nil, fmt.Errorf("backend does not support symmetric decryption")
		}

		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to get symmetric encrypter: %w", err)
		}

		encryptedData := &types.EncryptedData{
			Ciphertext: req.Ciphertext,
			Nonce:      req.Nonce,
			Tag:        req.Tag,
		}

		decryptOpts := &types.DecryptOptions{
			AdditionalData: req.AdditionalData,
		}

		plaintext, err = encrypter.Decrypt(encryptedData, decryptOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
	} else {
		decrypter, err := ks.Decrypter(attrs)
		if err != nil {
			return nil, fmt.Errorf("failed to get decrypter: %w", err)
		}

		plaintext, err = decrypter.Decrypt(nil, req.Ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt: %w", err)
		}
	}

	return &client.DecryptResponse{
		Plaintext: plaintext,
	}, nil
}

// EncryptAsym encrypts data with RSA public key (asymmetric encryption).
func (a *APIServiceAdapter) EncryptAsym(ctx context.Context, req *client.EncryptAsymRequest) (*client.EncryptAsymResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(req.Plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	key, err := ks.GetKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	var publicKey crypto.PublicKey
	switch k := key.(type) {
	case crypto.Signer:
		publicKey = k.Public()
	default:
		return nil, fmt.Errorf("key does not support public key extraction")
	}

	rsaPub, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("asymmetric encryption only supported for RSA keys")
	}

	hashFunc := parseHashAlgorithm(req.Hash)
	ciphertext, err := rsa.EncryptOAEP(
		hashFunc.New(),
		rand.Reader,
		rsaPub,
		req.Plaintext,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return &client.EncryptAsymResponse{
		Ciphertext: ciphertext,
	}, nil
}

// GetCertificate returns the certificate for a key.
func (a *APIServiceAdapter) GetCertificate(ctx context.Context, backendName, keyID string) (*client.GetCertificateResponse, error) {
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get backend: %w", err)
	}

	cert, err := ks.GetCert(keyID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	certPEM := encodeCertToPEM(cert)

	return &client.GetCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: certPEM,
	}, nil
}

// SaveCertificate saves a certificate for a key.
func (a *APIServiceAdapter) SaveCertificate(ctx context.Context, req *client.SaveCertificateRequest) error {
	if req.KeyID == "" {
		return fmt.Errorf("key_id is required")
	}
	if req.CertificatePEM == "" {
		return fmt.Errorf("certificate_pem is required")
	}

	cert, err := parseCertFromPEM(req.CertificatePEM)
	if err != nil {
		return fmt.Errorf("invalid certificate PEM: %w", err)
	}

	backends := keychain.Backends()
	if len(backends) == 0 {
		return fmt.Errorf("no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	return ks.SaveCert(req.KeyID, cert)
}

// DeleteCertificate deletes a certificate.
func (a *APIServiceAdapter) DeleteCertificate(ctx context.Context, backendName, keyID string) error {
	backends := keychain.Backends()
	if len(backends) == 0 {
		return fmt.Errorf("no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	return ks.DeleteCert(keyID)
}

// CertificateExists checks if a certificate exists for a key.
func (a *APIServiceAdapter) CertificateExists(ctx context.Context, backendName, keyID string) (bool, error) {
	backends := keychain.Backends()
	if len(backends) == 0 {
		return false, fmt.Errorf("no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return false, fmt.Errorf("failed to get backend: %w", err)
	}

	return ks.CertExists(keyID)
}

// ImportKey imports a key.
func (a *APIServiceAdapter) ImportKey(ctx context.Context, req *client.ImportKeyRequest) (*client.ImportKeyResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(req.WrappedKeyMaterial) == 0 {
		return nil, fmt.Errorf("wrapped_key_material is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import operations")
	}

	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		StoreType: types.StoreType(req.Backend),
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: req.WrappedKeyMaterial,
		Algorithm:  backend.WrappingAlgorithm(req.Algorithm),
	}

	err = importExportBackend.ImportKey(attrs, wrapped)
	if err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	return &client.ImportKeyResponse{
		Success: true,
		KeyID:   req.KeyID,
	}, nil
}

// ExportKey exports a key.
func (a *APIServiceAdapter) ExportKey(ctx context.Context, req *client.ExportKeyRequest) (*client.ExportKeyResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support export operations")
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	wrapped, err := importExportBackend.ExportKey(attrs, backend.WrappingAlgorithm(req.Algorithm))
	if err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	return &client.ExportKeyResponse{
		KeyID:              req.KeyID,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
	}, nil
}

// RotateKey rotates a key.
func (a *APIServiceAdapter) RotateKey(ctx context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	newKey, err := ks.RotateKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}

	pubKeyPEM, err := extractPublicKeyPEM(newKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return &client.RotateKeyResponse{
		Success:      true,
		KeyID:        req.KeyID,
		PublicKeyPEM: pubKeyPEM,
	}, nil
}

// ListKeyVersions lists all versions of a key.
func (a *APIServiceAdapter) ListKeyVersions(ctx context.Context, req *client.ListKeyVersionsRequest) (*client.ListKeyVersionsResponse, error) {
	return nil, fmt.Errorf("key versioning is not yet supported")
}

// EnableKeyVersion enables a specific version of a key.
func (a *APIServiceAdapter) EnableKeyVersion(ctx context.Context, req *client.EnableKeyVersionRequest) (*client.EnableKeyVersionResponse, error) {
	return nil, fmt.Errorf("key versioning is not yet supported")
}

// DisableKeyVersion disables a specific version of a key.
func (a *APIServiceAdapter) DisableKeyVersion(ctx context.Context, req *client.DisableKeyVersionRequest) (*client.DisableKeyVersionResponse, error) {
	return nil, fmt.Errorf("key versioning is not yet supported")
}

// EnableAllKeyVersions enables all versions of a key.
func (a *APIServiceAdapter) EnableAllKeyVersions(ctx context.Context, req *client.EnableAllKeyVersionsRequest) (*client.EnableAllKeyVersionsResponse, error) {
	return nil, fmt.Errorf("key versioning is not yet supported")
}

// DisableAllKeyVersions disables all versions of a key.
func (a *APIServiceAdapter) DisableAllKeyVersions(ctx context.Context, req *client.DisableAllKeyVersionsRequest) (*client.DisableAllKeyVersionsResponse, error) {
	return nil, fmt.Errorf("key versioning is not yet supported")
}

// GetImportParameters gets the parameters needed to import a key.
func (a *APIServiceAdapter) GetImportParameters(ctx context.Context, req *client.GetImportParametersRequest) (*client.GetImportParametersResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend does not support import operations")
	}

	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		StoreType: types.StoreType(req.Backend),
	}

	params, err := importExportBackend.GetImportParameters(attrs, backend.WrappingAlgorithm(req.Algorithm))
	if err != nil {
		return nil, fmt.Errorf("failed to get import parameters: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return &client.GetImportParametersResponse{
		WrappingPublicKey: pubKeyDER,
		ImportToken:       params.ImportToken,
		Algorithm:         string(params.Algorithm),
	}, nil
}

// WrapKey wraps key material for secure transport.
func (a *APIServiceAdapter) WrapKey(ctx context.Context, req *client.WrapKeyRequest) (*client.WrapKeyResponse, error) {
	if len(req.KeyMaterial) == 0 {
		return nil, fmt.Errorf("key_material is required")
	}
	if len(req.WrappingPublicKey) == 0 {
		return nil, fmt.Errorf("wrapping_public_key is required")
	}

	pubKey, err := x509.ParsePKIXPublicKey(req.WrappingPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wrapping public key: %w", err)
	}

	params := &backend.ImportParameters{
		WrappingPublicKey: pubKey,
		ImportToken:       req.ImportToken,
		Algorithm:         backend.WrappingAlgorithm(req.Algorithm),
	}

	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	var wrapped *backend.WrappedKeyMaterial
	for _, backendName := range backends {
		ks, err := keychain.Backend(backendName)
		if err != nil {
			continue
		}

		importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
		if ok {
			wrapped, err = importExportBackend.WrapKey(req.KeyMaterial, params)
			if err == nil {
				break
			}
		}
	}

	if wrapped == nil {
		return nil, fmt.Errorf("failed to wrap key: no suitable backend found")
	}

	return &client.WrapKeyResponse{
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
	}, nil
}

// UnwrapKey unwraps key material.
func (a *APIServiceAdapter) UnwrapKey(ctx context.Context, req *client.UnwrapKeyRequest) (*client.UnwrapKeyResponse, error) {
	if len(req.WrappedKeyMaterial) == 0 {
		return nil, fmt.Errorf("wrapped_key_material is required")
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: req.WrappedKeyMaterial,
		Algorithm:  backend.WrappingAlgorithm(req.Algorithm),
	}

	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	var keyMaterial []byte
	for _, backendName := range backends {
		ks, err := keychain.Backend(backendName)
		if err != nil {
			continue
		}

		importExportBackend, ok := ks.Backend().(backend.ImportExportBackend)
		if ok {
			// Create minimal import parameters for unwrapping
			params := &backend.ImportParameters{
				Algorithm: backend.WrappingAlgorithm(req.Algorithm),
			}
			keyMaterial, err = importExportBackend.UnwrapKey(wrapped, params)
			if err == nil {
				break
			}
		}
	}

	if keyMaterial == nil {
		return nil, fmt.Errorf("failed to unwrap key: no suitable backend found")
	}

	return &client.UnwrapKeyResponse{
		KeyMaterial: keyMaterial,
	}, nil
}

// CopyKey copies a key from one backend to another.
func (a *APIServiceAdapter) CopyKey(ctx context.Context, req *client.CopyKeyRequest) (*client.CopyKeyResponse, error) {
	if req.SourceBackend == "" {
		return nil, fmt.Errorf("source_backend is required")
	}
	if req.SourceKeyID == "" {
		return nil, fmt.Errorf("source_key_id is required")
	}
	if req.DestBackend == "" {
		return nil, fmt.Errorf("dest_backend is required")
	}
	if req.DestKeyID == "" {
		return nil, fmt.Errorf("dest_key_id is required")
	}

	sourceKs, err := keychain.Backend(req.SourceBackend)
	if err != nil {
		return nil, fmt.Errorf("source backend not found: %w", err)
	}

	destKs, err := keychain.Backend(req.DestBackend)
	if err != nil {
		return nil, fmt.Errorf("destination backend not found: %w", err)
	}

	sourceImportExport, ok := sourceKs.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("source backend does not support export")
	}

	destImportExport, ok := destKs.Backend().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("destination backend does not support import")
	}

	sourceAttrs, err := findKeyAttributes(sourceKs, req.SourceKeyID)
	if err != nil {
		return nil, fmt.Errorf("source key not found: %w", err)
	}

	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)

	wrapped, err := sourceImportExport.ExportKey(sourceAttrs, wrappingAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to export key: %w", err)
	}

	destAttrs := &types.KeyAttributes{
		CN:                 req.DestKeyID,
		KeyType:            sourceAttrs.KeyType,
		KeyAlgorithm:       sourceAttrs.KeyAlgorithm,
		Hash:               sourceAttrs.Hash,
		StoreType:          types.StoreType(req.DestBackend),
		Partition:          sourceAttrs.Partition,
		RSAAttributes:      sourceAttrs.RSAAttributes,
		ECCAttributes:      sourceAttrs.ECCAttributes,
		SymmetricAlgorithm: sourceAttrs.SymmetricAlgorithm,
	}

	err = destImportExport.ImportKey(destAttrs, wrapped)
	if err != nil {
		return nil, fmt.Errorf("failed to import key: %w", err)
	}

	return &client.CopyKeyResponse{
		Success: true,
		KeyID:   req.DestKeyID,
	}, nil
}

// ListCertificates lists all certificates in the specified backend.
func (a *APIServiceAdapter) ListCertificates(ctx context.Context, backendName string) (*client.ListCertificatesResponse, error) {
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get backend: %w", err)
	}

	keyIDs, err := ks.ListCerts()
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	certs := make([]client.CertificateInfo, len(keyIDs))
	for i, keyID := range keyIDs {
		certs[i] = client.CertificateInfo{
			KeyID: keyID,
		}
	}

	return &client.ListCertificatesResponse{
		Certificates: certs,
	}, nil
}

// SaveCertificateChain saves a certificate chain for a key.
func (a *APIServiceAdapter) SaveCertificateChain(ctx context.Context, req *client.SaveCertificateChainRequest) error {
	if req.KeyID == "" {
		return fmt.Errorf("key_id is required")
	}
	if len(req.ChainPEM) == 0 {
		return fmt.Errorf("chain_pem is required")
	}

	chain := make([]*x509.Certificate, len(req.ChainPEM))
	for i, certPEM := range req.ChainPEM {
		cert, err := parseCertFromPEM(certPEM)
		if err != nil {
			return fmt.Errorf("invalid certificate PEM at index %d: %w", i, err)
		}
		chain[i] = cert
	}

	backends := keychain.Backends()
	if len(backends) == 0 {
		return fmt.Errorf("no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return fmt.Errorf("failed to get backend: %w", err)
	}

	return ks.SaveCertChain(req.KeyID, chain)
}

// GetCertificateChain returns the certificate chain for a key.
func (a *APIServiceAdapter) GetCertificateChain(ctx context.Context, backendName, keyID string) (*client.GetCertificateChainResponse, error) {
	backends := keychain.Backends()
	if len(backends) == 0 {
		return nil, fmt.Errorf("no backends available")
	}

	ks, err := keychain.Backend(backends[0])
	if err != nil {
		return nil, fmt.Errorf("failed to get backend: %w", err)
	}

	chain, err := ks.GetCertChain(keyID)
	if err != nil {
		return nil, fmt.Errorf("certificate chain not found: %w", err)
	}

	chainPEM := make([]string, len(chain))
	for i, cert := range chain {
		chainPEM[i] = encodeCertToPEM(cert)
	}

	return &client.GetCertificateChainResponse{
		KeyID:    keyID,
		ChainPEM: chainPEM,
	}, nil
}

// GetTLSCertificate returns the TLS certificate bundle for a key.
func (a *APIServiceAdapter) GetTLSCertificate(ctx context.Context, backendName, keyID string) (*client.GetTLSCertificateResponse, error) {
	if backendName == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}

	ks, err := keychain.Backend(backendName)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	attrs, err := findKeyAttributes(ks, keyID)
	if err != nil {
		return nil, fmt.Errorf("key not found: %w", err)
	}

	tlsCert, err := ks.GetTLSCertificate(keyID, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS certificate: %w", err)
	}

	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("TLS certificate has no data")
	}

	leafCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	certPEM := encodeCertToPEM(leafCert)

	var chainPEM string
	for i := 1; i < len(tlsCert.Certificate); i++ {
		cert, err := x509.ParseCertificate(tlsCert.Certificate[i])
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}
		chainPEM += encodeCertToPEM(cert)
	}

	return &client.GetTLSCertificateResponse{
		KeyID:          keyID,
		CertificatePEM: certPEM,
		ChainPEM:       chainPEM,
	}, nil
}

// Seal seals data using the backend's sealing mechanism.
func (a *APIServiceAdapter) Seal(ctx context.Context, req *client.SealRequest) (*client.SealResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data is required")
	}

	opts := &types.SealOptions{
		AAD: req.AAD,
	}

	if req.KeyID != "" {
		attrs, err := keychain.ParseKeyIDToAttributes(req.KeyID)
		if err != nil {
			return nil, fmt.Errorf("invalid key ID format: %w", err)
		}
		opts.KeyAttributes = attrs
	}

	sealed, err := keychain.SealWithBackend(ctx, req.Backend, req.Data, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to seal data: %w", err)
	}

	return &client.SealResponse{
		Backend:    string(sealed.Backend),
		Ciphertext: sealed.Ciphertext,
		Nonce:      sealed.Nonce,
		Tag:        sealed.Tag,
	}, nil
}

// Unseal unseals previously sealed data.
func (a *APIServiceAdapter) Unseal(ctx context.Context, req *client.UnsealRequest) (*client.UnsealResponse, error) {
	if req.Backend == "" {
		return nil, fmt.Errorf("backend is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}

	ks, err := keychain.Backend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend not found: %w", err)
	}

	sealed := &types.SealedData{
		Backend:    ks.Backend().Type(),
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
	}

	opts := &types.UnsealOptions{
		AAD: req.AAD,
	}

	if req.KeyID != "" {
		attrs, err := keychain.ParseKeyIDToAttributes(req.KeyID)
		if err != nil {
			return nil, fmt.Errorf("invalid key ID format: %w", err)
		}
		opts.KeyAttributes = attrs
		sealed.KeyID = attrs.ID()
	}

	plaintext, err := keychain.UnsealWithBackend(ctx, req.Backend, sealed, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal data: %w", err)
	}

	return &client.UnsealResponse{
		Plaintext: plaintext,
	}, nil
}

// CanSeal checks if the backend supports sealing operations.
func (a *APIServiceAdapter) CanSeal(ctx context.Context, backendName string) (*client.CanSealResponse, error) {
	var canSeal bool

	if backendName != "" {
		canSeal = keychain.CanSeal(backendName)
	} else {
		canSeal = keychain.CanSeal()
	}

	return &client.CanSealResponse{
		CanSeal: canSeal,
		Backend: backendName,
	}, nil
}

// User Management Operations - Stub implementations

// ListUsers returns a list of all users.
func (a *APIServiceAdapter) ListUsers(ctx context.Context) (*client.ListUsersResponse, error) {
	return nil, client.ErrNotSupported
}

// GetUser returns information about a specific user.
func (a *APIServiceAdapter) GetUser(ctx context.Context, username string) (*client.GetUserResponse, error) {
	return nil, client.ErrNotSupported
}

// DeleteUser deletes a user.
func (a *APIServiceAdapter) DeleteUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

// EnableUser enables a user account.
func (a *APIServiceAdapter) EnableUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

// DisableUser disables a user account.
func (a *APIServiceAdapter) DisableUser(ctx context.Context, username string) error {
	return client.ErrNotSupported
}

// ListUserCredentials returns a list of credentials for a user.
func (a *APIServiceAdapter) ListUserCredentials(ctx context.Context, username string) (*client.ListUserCredentialsResponse, error) {
	return nil, client.ErrNotSupported
}

// Authentication Flow Operations - Stub implementations

// BeginRegistration begins a WebAuthn registration flow.
func (a *APIServiceAdapter) BeginRegistration(ctx context.Context, req *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

// FinishRegistration completes a WebAuthn registration flow.
func (a *APIServiceAdapter) FinishRegistration(ctx context.Context, req *client.FinishRegistrationRequest) (*client.FinishRegistrationResponse, error) {
	return nil, client.ErrNotSupported
}

// BeginAuthentication begins a WebAuthn authentication flow.
func (a *APIServiceAdapter) BeginAuthentication(ctx context.Context, req *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

// FinishAuthentication completes a WebAuthn authentication flow.
func (a *APIServiceAdapter) FinishAuthentication(ctx context.Context, req *client.FinishAuthenticationRequest) (*client.FinishAuthenticationResponse, error) {
	return nil, client.ErrNotSupported
}

// Helper functions

func findKeyAttributes(ks keychain.KeyStore, keyID string) (*types.KeyAttributes, error) {
	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, fmt.Errorf("key %s not found", keyID)
}

func getAlgorithmString(attrs *types.KeyAttributes) string {
	if attrs.SymmetricAlgorithm != "" {
		return string(attrs.SymmetricAlgorithm)
	}
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return attrs.KeyAlgorithm.String()
	}
	return ""
}

func parseHashAlgorithm(hash string) crypto.Hash {
	if hash == "" {
		return crypto.SHA256
	}
	h := types.ParseHash(hash)
	if h == 0 {
		return crypto.SHA256
	}
	return h
}

func extractPublicKeyPEM(privKey crypto.PrivateKey) (string, error) {
	var pubKey crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case crypto.Signer:
		pubKey = k.Public()
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

func parseCertFromPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM type: %s (expected CERTIFICATE)", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

func encodeCertToPEM(cert *x509.Certificate) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

// Verify interface compliance at compile time
var _ client.KeychainServicer = (*APIServiceAdapter)(nil)

// Unused import for base64 (needed for future metadata encoding)
var _ = base64.StdEncoding
