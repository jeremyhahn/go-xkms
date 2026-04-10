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

// Package pkcs11 provides an EmbeddedTransport implementation of
// module.PKCS11Transport. It delegates all 20 transport operations to the
// go-xkms singleton, enabling the PKCS#11 module to operate without a
// remote daemon connection.
package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// EmbeddedTransport implements module.PKCS11Transport by delegating all
// operations to the go-xkms package singleton. This enables the PKCS#11
// module to use an in-process xkms without network overhead.
type EmbeddedTransport struct{}

// Compile-time interface compliance check.
var _ module.PKCS11Transport = (*EmbeddedTransport)(nil)

// NewEmbeddedTransport creates a new embedded transport for the PKCS#11 module.
// The xkms package must be initialized before calling this.
func NewEmbeddedTransport() (*EmbeddedTransport, error) {
	if !xkms.IsInitialized() {
		return nil, ErrServiceNotInitialized
	}
	return &EmbeddedTransport{}, nil
}

// Connect is a no-op for the embedded transport (in-process, no network).
func (t *EmbeddedTransport) Connect(_ context.Context) error {
	return nil
}

// Close is a no-op for the embedded transport (in-process, no network).
func (t *EmbeddedTransport) Close() error {
	return nil
}

// GenerateKey generates a new key in the specified backend.
func (t *EmbeddedTransport) GenerateKey(_ context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
	}

	attrs := &types.KeyAttributes{
		CN:        req.KeyID,
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreType(req.Backend),
	}

	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = req.KeyType
	}

	var privKey crypto.PrivateKey

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

	return &transport.GenerateKeyResponse{
		KeyID:        req.KeyID,
		KeyType:      req.KeyType,
		PublicKeyPEM: pubKeyPEM,
	}, nil
}

// Sign signs data with the specified key.
func (t *EmbeddedTransport) Sign(_ context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, req.KeyID)
	}

	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	// Ed25519 uses pure signing (no prehashing)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		signature, signErr := signer.Sign(nil, req.Data, crypto.Hash(0))
		if signErr != nil {
			return nil, fmt.Errorf("%w: %v", ErrSigningFailed, signErr)
		}
		return &transport.SignResponse{
			Signature: signature,
		}, nil
	}

	hashAlg := parseHashAlgorithm(req.Hash)
	hasher := hashAlg.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	signature, err := signer.Sign(nil, digest, hashAlg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	return &transport.SignResponse{
		Signature: signature,
	}, nil
}

// Verify verifies a signature with the specified key.
func (t *EmbeddedTransport) Verify(_ context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, req.KeyID)
	}

	// Get the signer to extract the public key
	signer, err := ks.Signer(attrs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}

	pubKey := signer.Public()
	valid := verifySignature(pubKey, req.Data, req.Signature, req.Hash, attrs.KeyAlgorithm)

	return &transport.VerifyResponse{
		Valid: valid,
	}, nil
}

// Encrypt encrypts data with the specified symmetric key.
func (t *EmbeddedTransport) Encrypt(_ context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
	}

	symBackend, ok := ks.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, fmt.Errorf("%w: backend does not support symmetric encryption", ErrEncryptionFailed)
	}

	encrypter, err := symBackend.SymmetricEncrypter(&types.KeyAttributes{
		CN:        req.KeyID,
		StoreType: types.StoreType(req.Backend),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	encrypted, err := encrypter.Encrypt(req.Plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	return &transport.EncryptResponse{
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
	}, nil
}

// Decrypt decrypts data with the specified symmetric key.
func (t *EmbeddedTransport) Decrypt(_ context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
	}

	symBackend, ok := ks.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, fmt.Errorf("%w: backend does not support symmetric decryption", ErrDecryptionFailed)
	}

	encrypter, err := symBackend.SymmetricEncrypter(&types.KeyAttributes{
		CN:        req.KeyID,
		StoreType: types.StoreType(req.Backend),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	plaintext, err := encrypter.Decrypt(&types.EncryptedData{
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Tag:        req.Tag,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return &transport.DecryptResponse{
		Plaintext: plaintext,
	}, nil
}

// DeriveKey derives a key using the HKDF algorithm and the provided parameters.
func (t *EmbeddedTransport) DeriveKey(_ context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	hashAlg := parseHashAlgorithm(req.Hash)
	adapter := &kdf.HKDFAdapter{}
	params := &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Salt:      req.Salt,
		Info:      req.Info,
		KeyLength: req.KeyLength,
		Hash:      hashAlg,
	}
	if params.KeyLength <= 0 {
		params.KeyLength = 32
	}

	// Use InputKeyMaterial if provided, otherwise derive from the backend key.
	ikm := req.InputKeyMaterial
	if len(ikm) == 0 && req.KeyID != "" {
		ks, err := xkms.GetBackend(req.Backend)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
		}
		ieBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
		if !ok {
			return nil, fmt.Errorf("%w: backend does not support key material export for derivation", ErrDerivationFailed)
		}
		attrs, err := findKeyAttributes(ks, req.KeyID)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, req.KeyID)
		}
		ikm, err = ieBackend.ExportKeyMaterial(attrs)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to export key material: %v", ErrDerivationFailed, err)
		}
	}

	if len(ikm) == 0 {
		return nil, fmt.Errorf("%w: no input key material provided", ErrDerivationFailed)
	}

	derived, err := adapter.DeriveKey(ikm, params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDerivationFailed, err)
	}

	return &transport.DeriveKeyResponse{
		DerivedKey: derived,
	}, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
func (t *EmbeddedTransport) DeriveKeyECDH(_ context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
	}

	kap, ok := ks.KeyProvider().(types.KeyAgreementProvider)
	if !ok {
		return nil, fmt.Errorf("%w: backend does not support key agreement", ErrDerivationFailed)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, req.KeyID)
	}

	kdfHash := req.KDFHash
	if kdfHash == "" {
		kdfHash = "SHA-256"
	}
	keyLength := req.KeyLength
	if keyLength <= 0 {
		keyLength = 32
	}

	kdfParams := &types.KDFParams{
		Hash:      kdfHash,
		Salt:      req.KDFSalt,
		Info:      req.KDFInfo,
		KeyLength: keyLength,
	}

	derived, err := kap.DeriveKeyECDH(context.Background(), attrs, req.PeerPublicKey, kdfParams)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDerivationFailed, err)
	}

	return &transport.DeriveKeyECDHResponse{
		DerivedKey: derived,
	}, nil
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
func (t *EmbeddedTransport) WrapKeyByID(_ context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	// Export the target key material (unwrapped) for wrapping.
	targetBackend := req.TargetKeyBackend
	if targetBackend == "" {
		targetBackend = req.WrappingKeyBackend
	}
	targetKID := targetBackend + ":" + req.TargetKeyID

	exported, err := xkms.ExportKey(targetKID, backend.WrappingAlgorithm(""))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to export target key: %v", ErrWrappingFailed, err)
	}

	// Get the import parameters from the wrapping key's backend.
	wrappingAlg := backend.WrappingAlgorithm(req.Algorithm)
	params, err := getImportParams(req.WrappingKeyBackend, req.WrappingKeyID, wrappingAlg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrappingFailed, err)
	}

	// Wrap using the wrapping key's backend.
	wrapped, err := xkms.WrapKey(req.WrappingKeyBackend, exported.WrappedKey, params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrappingFailed, err)
	}

	return &transport.WrapKeyByIDResponse{
		WrappedKey: wrapped.WrappedKey,
		Algorithm:  string(wrapped.Algorithm),
	}, nil
}

// UnwrapKeyByID unwraps key material and imports it as a new key.
func (t *EmbeddedTransport) UnwrapKeyByID(_ context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	unwrappingAlg := backend.WrappingAlgorithm(req.Algorithm)
	params, err := getImportParams(req.UnwrappingKeyBackend, req.UnwrappingKeyID, unwrappingAlg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrappingFailed, err)
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: req.WrappedKey,
		Algorithm:  unwrappingAlg,
	}

	keyMaterial, err := xkms.UnwrapKey(req.UnwrappingKeyBackend, wrapped, params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrappingFailed, err)
	}

	return &transport.UnwrapKeyByIDResponse{
		KeyID:   req.TargetKeyID,
		Success: true,
		Message: fmt.Sprintf("unwrapped %d bytes", len(keyMaterial)),
	}, nil
}

// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
func (t *EmbeddedTransport) ExportKeyMaterial(_ context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	ks, err := xkms.GetBackend(req.Backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, req.Backend)
	}

	ieBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("%w: backend does not support key material export", ErrExportFailed)
	}

	attrs, err := findKeyAttributes(ks, req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, req.KeyID)
	}

	keyMaterial, err := ieBackend.ExportKeyMaterial(attrs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExportFailed, err)
	}

	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: keyMaterial,
		KeyType:     getAlgorithmString(attrs),
		KeySize:     len(keyMaterial) * 8,
	}, nil
}

// ListPIVSlots returns the status of all PIV slots in the specified backend.
func (t *EmbeddedTransport) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return xkms.ListPIVSlots(ctx, req)
}

// GetPIVCertificate retrieves the certificate from a PIV slot.
func (t *EmbeddedTransport) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return xkms.GetPIVCertificate(ctx, req)
}

// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
func (t *EmbeddedTransport) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return xkms.GeneratePIVKey(ctx, req)
}

// StorePIVCertificate stores a certificate in a PIV slot.
func (t *EmbeddedTransport) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return xkms.StorePIVCertificate(ctx, req)
}

// DeletePIVCertificate removes the certificate from a PIV slot.
func (t *EmbeddedTransport) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return xkms.DeletePIVCertificate(ctx, req)
}

// ImportPIVCertificate imports an externally issued certificate into a PIV slot.
func (t *EmbeddedTransport) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return xkms.ImportPIVCertificate(ctx, req)
}

// ExportPIVCertificate exports the certificate from a PIV slot in the requested format.
func (t *EmbeddedTransport) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return xkms.ExportPIVCertificate(ctx, req)
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
func (t *EmbeddedTransport) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return xkms.GeneratePIVCSR(ctx, req)
}

// ========================================================================
// Helper Functions
// ========================================================================

// findKeyAttributes searches for a key by ID in the given keystore.
func findKeyAttributes(ks xkms.Backend, keyID string) (*types.KeyAttributes, error) {
	attrs, err := ks.ListKeys()
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		if attr.CN == keyID {
			return attr, nil
		}
	}

	return nil, ErrKeyNotFound
}

// getAlgorithmString returns a human-readable algorithm string for key attributes.
func getAlgorithmString(attr *types.KeyAttributes) string {
	switch attr.KeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		if attr.KeyType == types.KeyTypeSecret {
			return string(attr.SymmetricAlgorithm)
		}
		return "unknown"
	}
}

// parseHashAlgorithm parses a hash algorithm name into a crypto.Hash value.
// Uses map-based dispatch for O(1) constant-time lookup.
var hashAlgorithms = map[string]crypto.Hash{
	"sha256":  crypto.SHA256,
	"SHA256":  crypto.SHA256,
	"sha384":  crypto.SHA384,
	"SHA384":  crypto.SHA384,
	"sha512":  crypto.SHA512,
	"SHA512":  crypto.SHA512,
	"sha1":    crypto.SHA1,
	"SHA1":    crypto.SHA1,
	"sha-256": crypto.SHA256,
	"sha-384": crypto.SHA384,
	"sha-512": crypto.SHA512,
	"SHA-256": crypto.SHA256,
	"SHA-384": crypto.SHA384,
	"SHA-512": crypto.SHA512,
}

func parseHashAlgorithm(name string) crypto.Hash {
	if h, ok := hashAlgorithms[name]; ok {
		return h
	}
	return crypto.SHA256
}

// extractPublicKeyPEM extracts the public key from a private key and returns it as PEM.
func extractPublicKeyPEM(privKey crypto.PrivateKey) (string, error) {
	var pubKey crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	default:
		return "", fmt.Errorf("unsupported key type: %T", privKey)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// verifySignature verifies a signature against the given public key.
func verifySignature(pubKey crypto.PublicKey, data, signature []byte, hashName string, keyAlg x509.PublicKeyAlgorithm) bool {
	switch keyAlg {
	case x509.Ed25519:
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(edKey, data, signature)

	case x509.ECDSA:
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		hashAlg := parseHashAlgorithm(hashName)
		hasher := hashAlg.New()
		hasher.Write(data)
		digest := hasher.Sum(nil)
		return ecdsa.VerifyASN1(ecKey, digest, signature)

	case x509.RSA:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		hashAlg := parseHashAlgorithm(hashName)
		hasher := hashAlg.New()
		hasher.Write(data)
		digest := hasher.Sum(nil)
		return rsa.VerifyPKCS1v15(rsaKey, hashAlg, digest, signature) == nil

	default:
		return false
	}
}

// getImportParams retrieves import parameters from a backend for key wrapping operations.
func getImportParams(backendName, keyID string, alg backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	ks, err := xkms.GetBackend(backendName)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBackendNotFound, backendName)
	}

	ieBackend, ok := ks.KeyProvider().(backend.ImportExportBackend)
	if !ok {
		return nil, fmt.Errorf("backend %s does not support import/export", backendName)
	}

	attrs, err := findKeyAttributes(ks, keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}

	return ieBackend.GetImportParameters(attrs, alg)
}
