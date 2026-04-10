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

// Package pkcs11test provides shared test utilities for the PKCS#11
// conformance test suite. CryptoMockClient implements module.PKCS11Transport
// with real Go stdlib cryptographic operations for sign/verify/encrypt/decrypt,
// key derivation, key wrapping, key export, and sensible no-op defaults for
// PIV operations.
package pkcs11test

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// Compile-time check: CryptoMockClient satisfies module.PKCS11Transport.
var _ module.PKCS11Transport = (*CryptoMockClient)(nil)

// Typed errors for CryptoMockClient operations.
var (
	ErrUnsupportedKeyType = errors.New("pkcs11test: unsupported key type")
	ErrKeyNotFound        = errors.New("pkcs11test: key not found")
	ErrInvalidCiphertext  = errors.New("pkcs11test: invalid ciphertext")
	ErrHKDFRead           = errors.New("pkcs11test: HKDF read failed")
	ErrKeyGeneration      = errors.New("pkcs11test: key generation failed")
)

// hashDispatch maps hash algorithm names to crypto.Hash values.
var hashDispatch = map[string]crypto.Hash{
	"sha256":  crypto.SHA256,
	"sha-256": crypto.SHA256,
	"sha384":  crypto.SHA384,
	"sha-384": crypto.SHA384,
	"sha512":  crypto.SHA512,
	"sha-512": crypto.SHA512,
	"sha1":    crypto.SHA1,
	"sha-1":   crypto.SHA1,
}

// CryptoMockClient implements module.PKCS11Transport with real Go stdlib
// cryptographic operations for the 20 transport methods the PKCS#11 module
// requires: Connect, Close, GenerateKey, Sign, Verify, Encrypt, Decrypt,
// DeriveKey, DeriveKeyECDH, WrapKeyByID, UnwrapKeyByID, ExportKeyMaterial,
// ListPIVSlots, GetPIVCertificate, GeneratePIVKey, StorePIVCertificate,
// DeletePIVCertificate, ImportPIVCertificate, ExportPIVCertificate, and
// GeneratePIVCSR.
//
// Keys are lazily generated on first use, allowing PKCS#11 objects created via
// CreateObject (which have KeyID="") to still work with real sign/verify/
// encrypt/decrypt operations.
type CryptoMockClient struct {
	mu             sync.RWMutex
	asymmetricKeys map[string]crypto.PrivateKey
	symmetricKeys  map[string][]byte
}

// NewCryptoMockClient returns a new CryptoMockClient that satisfies
// module.PKCS11Transport with real cryptographic operations.
func NewCryptoMockClient() *CryptoMockClient {
	return &CryptoMockClient{
		asymmetricKeys: make(map[string]crypto.PrivateKey),
		symmetricKeys:  make(map[string][]byte),
	}
}

// NewModuleFactory creates a fresh Module backed by the CryptoMockClient.
// Use this factory for conformance suites that require real cryptographic
// operations.
func NewModuleFactory(t *testing.T) (*module.Module, func()) {
	t.Helper()
	module.ResetGlobalModule()

	m, err := module.New(module.WithClient(NewCryptoMockClient()), module.WithConfig(module.DefaultConfig()))
	if err != nil {
		t.Fatalf("failed to create module: %v", err)
	}

	return m, func() {
		m.Finalize()
	}
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

// Connect establishes a (no-op) connection.
func (c *CryptoMockClient) Connect(ctx context.Context) error { return nil }

// Close releases resources (no-op).
func (c *CryptoMockClient) Close() error { return nil }

// ---------------------------------------------------------------------------
// Real cryptographic operations
// ---------------------------------------------------------------------------

// GenerateKey generates a real cryptographic key and stores it in the internal maps.
func (c *CryptoMockClient) GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	keyType := strings.ToLower(req.KeyType)
	keyID := req.KeyID

	switch keyType {
	case "rsa", "rsa-2048", "rsa-4096":
		bits := 2048
		if req.KeySize > 0 {
			bits = req.KeySize
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, ErrKeyGeneration
		}
		c.mu.Lock()
		c.asymmetricKeys[keyID] = key
		c.mu.Unlock()
		return &transport.GenerateKeyResponse{KeyID: keyID, KeyType: "RSA"}, nil

	case "ecdsa", "ec", "ecdsa-p256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, ErrKeyGeneration
		}
		c.mu.Lock()
		c.asymmetricKeys[keyID] = key
		c.mu.Unlock()
		return &transport.GenerateKeyResponse{KeyID: keyID, KeyType: "ECDSA"}, nil

	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, ErrKeyGeneration
		}
		c.mu.Lock()
		c.asymmetricKeys[keyID] = priv
		c.mu.Unlock()
		return &transport.GenerateKeyResponse{KeyID: keyID, KeyType: "Ed25519"}, nil

	case "aes", "aes-256", "aes256-gcm", "symmetric":
		keyBytes := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
			return nil, ErrKeyGeneration
		}
		c.mu.Lock()
		c.symmetricKeys[keyID] = keyBytes
		c.mu.Unlock()
		return &transport.GenerateKeyResponse{KeyID: keyID, KeyType: "AES"}, nil

	default:
		// Default to RSA-2048 for unknown types
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, ErrKeyGeneration
		}
		c.mu.Lock()
		c.asymmetricKeys[keyID] = key
		c.mu.Unlock()
		return &transport.GenerateKeyResponse{KeyID: keyID, KeyType: "RSA"}, nil
	}
}

// Sign performs a real signature using the stored or lazily-generated private key.
func (c *CryptoMockClient) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	key, err := c.getOrCreateAsymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	hashAlg := c.parseHash(req.Hash)
	digest := computeDigest(hashAlg, req.Data)

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrUnsupportedKeyType
	}

	var sigOpts crypto.SignerOpts
	switch key.(type) {
	case ed25519.PrivateKey:
		// Ed25519 signs the raw message, not a digest
		sigOpts = crypto.Hash(0)
		digest = req.Data
	default:
		sigOpts = hashAlg
	}

	sig, err := signer.Sign(rand.Reader, digest, sigOpts)
	if err != nil {
		return nil, err
	}

	return &transport.SignResponse{Signature: sig, Algorithm: "RSA-PKCS"}, nil
}

// Verify performs real signature verification using the stored or lazily-generated key.
func (c *CryptoMockClient) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	key, err := c.getOrCreateAsymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	hashAlg := c.parseHash(req.Hash)
	digest := computeDigest(hashAlg, req.Data)

	var valid bool
	switch k := key.(type) {
	case *rsa.PrivateKey:
		verifyErr := rsa.VerifyPKCS1v15(&k.PublicKey, hashAlg, digest, req.Signature)
		valid = verifyErr == nil
	case *ecdsa.PrivateKey:
		valid = ecdsa.VerifyASN1(&k.PublicKey, digest, req.Signature)
	case ed25519.PrivateKey:
		valid = ed25519.Verify(k.Public().(ed25519.PublicKey), req.Data, req.Signature)
	default:
		return nil, ErrUnsupportedKeyType
	}

	return &transport.VerifyResponse{Valid: valid}, nil
}

// Encrypt performs real AES-GCM encryption using the stored or lazily-generated key.
// Returns Nonce, Tag, and Ciphertext separately per the transport.EncryptResponse contract.
func (c *CryptoMockClient) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	key, err := c.getOrCreateSymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// gcm.Seal appends ciphertext+tag to dst
	sealed := gcm.Seal(nil, nonce, req.Plaintext, req.AdditionalData)

	// Split ciphertext and tag: sealed = ciphertext || tag
	tagStart := len(sealed) - gcm.Overhead()
	ciphertext := sealed[:tagStart]
	tag := sealed[tagStart:]

	return &transport.EncryptResponse{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Tag:        tag,
	}, nil
}

// Decrypt performs real AES-GCM decryption using the stored or lazily-generated key.
func (c *CryptoMockClient) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	key, err := c.getOrCreateSymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Reconstruct the sealed blob: ciphertext || tag
	sealed := make([]byte, 0, len(req.Ciphertext)+len(req.Tag))
	sealed = append(sealed, req.Ciphertext...)
	sealed = append(sealed, req.Tag...)

	plaintext, err := gcm.Open(nil, req.Nonce, sealed, req.AdditionalData)
	if err != nil {
		return nil, err
	}

	return &transport.DecryptResponse{Plaintext: plaintext}, nil
}

// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
func (c *CryptoMockClient) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	wrappingKey, err := c.getOrCreateSymKey(req.WrappingKeyID)
	if err != nil {
		return nil, err
	}

	// Get the target key material
	targetKey, err := c.getSymKey(req.TargetKeyID)
	if err != nil {
		return nil, err
	}

	// Encrypt the target key with the wrapping key using AES-GCM
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to the sealed blob for self-contained wrapping
	sealed := gcm.Seal(nil, nonce, targetKey, nil)
	wrappedKey := make([]byte, 0, len(nonce)+len(sealed))
	wrappedKey = append(wrappedKey, nonce...)
	wrappedKey = append(wrappedKey, sealed...)

	return &transport.WrapKeyByIDResponse{
		WrappedKey: wrappedKey,
		Algorithm:  req.Algorithm,
	}, nil
}

// UnwrapKeyByID unwraps key material and stores it as a new key.
func (c *CryptoMockClient) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	unwrappingKey, err := c.getOrCreateSymKey(req.UnwrappingKeyID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(unwrappingKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(req.WrappedKey) < gcm.NonceSize() {
		return nil, ErrInvalidCiphertext
	}

	nonce := req.WrappedKey[:gcm.NonceSize()]
	sealed := req.WrappedKey[gcm.NonceSize():]

	keyMaterial, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, err
	}

	// Store the unwrapped key
	c.mu.Lock()
	c.symmetricKeys[req.TargetKeyID] = keyMaterial
	c.mu.Unlock()

	return &transport.UnwrapKeyByIDResponse{
		KeyID:   req.TargetKeyID,
		Backend: req.TargetKeyBackend,
		Success: true,
	}, nil
}

// DeriveKey performs real HKDF-based key derivation.
func (c *CryptoMockClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	keyLength := req.KeyLength
	if keyLength <= 0 {
		keyLength = 32
	}

	salt := req.Salt
	info := req.Info

	hkdfReader := hkdf.New(sha256.New, req.InputKeyMaterial, salt, info)
	derivedKey := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, ErrHKDFRead
	}

	return &transport.DeriveKeyResponse{
		DerivedKey: derivedKey,
		Algorithm:  req.Algorithm,
		KeyLength:  keyLength,
	}, nil
}

// DeriveKeyECDH performs real ECDH key agreement and HKDF derivation.
func (c *CryptoMockClient) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	keyLength := req.KeyLength
	if keyLength <= 0 {
		keyLength = 32
	}

	// Generate an ephemeral ECDH key pair to simulate shared secret
	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrKeyGeneration
	}

	// Use the ephemeral private key bytes as "shared secret" material
	sharedSecret := ephemeral.D.Bytes() //nolint:staticcheck // mock ECDH needs raw private scalar

	// Derive key from shared secret using HKDF
	hkdfReader := hkdf.New(sha256.New, sharedSecret, req.KDFSalt, req.KDFInfo)
	derivedKey := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, ErrHKDFRead
	}

	return &transport.DeriveKeyECDHResponse{DerivedKey: derivedKey}, nil
}

// ExportKeyMaterial returns the raw symmetric key bytes for extractable keys.
func (c *CryptoMockClient) ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	key, err := c.getOrCreateSymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	return &transport.ExportKeyMaterialResponse{
		KeyMaterial: key,
		KeyType:     "aes256-gcm",
		KeySize:     256,
	}, nil
}

// ---------------------------------------------------------------------------
// PIV operations (no-op defaults appropriate for tests without hardware)
// ---------------------------------------------------------------------------

// ListPIVSlots returns an empty PIV slot list.
func (c *CryptoMockClient) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return &transport.ListPIVSlotsResponse{}, nil
}

// GetPIVCertificate returns an empty PIV certificate response.
func (c *CryptoMockClient) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}

// GeneratePIVKey returns an empty PIV key generation response.
func (c *CryptoMockClient) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return &transport.GeneratePIVKeyResponse{}, nil
}

// StorePIVCertificate stores a certificate in a PIV slot (no-op for tests).
func (c *CryptoMockClient) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return nil
}

// DeletePIVCertificate removes the certificate from a PIV slot (no-op for tests).
func (c *CryptoMockClient) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return nil
}

// ImportPIVCertificate imports a certificate into a PIV slot (no-op for tests).
func (c *CryptoMockClient) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return nil
}

// ExportPIVCertificate exports the certificate from a PIV slot.
func (c *CryptoMockClient) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return &transport.GetPIVCertificateResponse{}, nil
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
func (c *CryptoMockClient) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return &transport.GeneratePIVCSRResponse{}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// getOrCreateAsymKey returns the asymmetric key for the given ID, generating
// an RSA-2048 key if none exists. Uses double-checked locking for thread safety.
func (c *CryptoMockClient) getOrCreateAsymKey(keyID string) (crypto.PrivateKey, error) {
	c.mu.RLock()
	key, ok := c.asymmetricKeys[keyID]
	c.mu.RUnlock()
	if ok {
		return key, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if key, ok := c.asymmetricKeys[keyID]; ok {
		return key, nil
	}

	// Generate RSA-2048 by default
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, ErrKeyGeneration
	}
	c.asymmetricKeys[keyID] = rsaKey
	return rsaKey, nil
}

// getOrCreateSymKey returns the symmetric key for the given ID, generating
// a 32-byte AES key if none exists. Uses double-checked locking for thread safety.
func (c *CryptoMockClient) getOrCreateSymKey(keyID string) ([]byte, error) {
	c.mu.RLock()
	key, ok := c.symmetricKeys[keyID]
	c.mu.RUnlock()
	if ok {
		return key, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if key, ok := c.symmetricKeys[keyID]; ok {
		return key, nil
	}

	// Generate 32-byte AES-256 key
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, ErrKeyGeneration
	}
	c.symmetricKeys[keyID] = key
	return key, nil
}

// getSymKey returns an existing symmetric key without lazy creation.
func (c *CryptoMockClient) getSymKey(keyID string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.symmetricKeys[keyID]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

// parseHash converts a hash algorithm name to crypto.Hash using map-based dispatch.
func (c *CryptoMockClient) parseHash(hashName string) crypto.Hash {
	if h, ok := hashDispatch[strings.ToLower(hashName)]; ok {
		return h
	}
	return crypto.SHA256
}

// computeDigest hashes the given data with the specified algorithm.
func computeDigest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		return d[:]
	default:
		d := sha256.Sum256(data)
		return d[:]
	}
}
