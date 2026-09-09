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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time check: CryptoMockClient satisfies module.PKCS11Transport.
var _ module.PKCS11Transport = (*CryptoMockClient)(nil)

// Typed errors for CryptoMockClient operations.
var (
	ErrUnsupportedKeyType = errors.New("pkcs11test: unsupported key type")
	ErrKeyNotFound        = errors.New("pkcs11test: key not found")
	ErrInvalidCiphertext  = errors.New("pkcs11test: invalid ciphertext")
	ErrInvalidNonceSize   = errors.New("pkcs11test: invalid nonce size")
	ErrHKDFRead           = errors.New("pkcs11test: HKDF read failed")
	ErrKeyGeneration      = errors.New("pkcs11test: key generation failed")
	ErrPublicKeyEncode    = errors.New("pkcs11test: public key encoding failed")

	// ErrPSSRequiresRSA is returned when a request selects RSASSA-PSS padding
	// for a key that is not RSA. PSS has no ECDSA or Ed25519 analogue, so
	// falling back to the key's native scheme would sign under something the
	// caller did not ask for.
	ErrPSSRequiresRSA = errors.New("pkcs11test: RSA-PSS padding requires an RSA key")

	// ErrUnsupportedPadding is returned for a padding name that is neither
	// the PKCS#1 v1.5 default nor "pss".
	ErrUnsupportedPadding = errors.New("pkcs11test: unsupported signature padding")

	// ErrPSSRequiresHash is returned when RSASSA-PSS is requested with the
	// "NONE" hash sentinel. PSS needs a digest identity for MGF1 and the salt
	// length (RFC 8017 section 9.1), which "NONE" does not carry.
	ErrPSSRequiresHash = errors.New("pkcs11test: RSA-PSS requires a hash algorithm")

	// ErrInvalidTagSize is returned when a requested AES-GCM tag length is
	// not one NIST SP 800-38D section 5.2.1.2 approves.
	ErrInvalidTagSize = errors.New("pkcs11test: invalid AES-GCM authentication tag size")

	// ErrInvalidTagLength is returned when the tag on a decrypt request is
	// not the length the request's TagSize selected.
	ErrInvalidTagLength = errors.New("pkcs11test: invalid AES-GCM authentication tag length")
)

// hashNone is the wire sentinel the PKCS#11 module sends for mechanisms that
// carry no hash of their own -- CKM_RSA_PKCS and CKM_ECDSA, whose caller has
// already produced the exact bytes to be signed (see mechanismToHashMap in
// pkg/pkcs11/module/crypto.go). A backend that hashes them again signs the
// wrong message: for CKM_RSA_PKCS it also destroys the recoverability that
// C_SignRecover / C_VerifyRecover depend on, because the recovered block then
// holds a DigestInfo instead of the caller's data (v3.2 §6.1.3).
const hashNone = "none"

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

	// importKeys holds the ephemeral RSA key pair issued to each pending key
	// import, keyed by the key id the import will create. GetImportParameters
	// publishes the public half and ImportKey unwraps with the private half, so
	// the ceremony this mock presents is the real one: material that was not
	// wrapped under the key this mock handed out will not decrypt, and a module
	// that sent plaintext instead would fail here rather than pass.
	importKeys map[string]*rsa.PrivateKey
}

// NewCryptoMockClient returns a new CryptoMockClient that satisfies
// module.PKCS11Transport with real cryptographic operations.
func NewCryptoMockClient() *CryptoMockClient {
	return &CryptoMockClient{
		asymmetricKeys: make(map[string]crypto.PrivateKey),
		symmetricKeys:  make(map[string][]byte),
		importKeys:     make(map[string]*rsa.PrivateKey),
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
		return c.storeAsymKey(keyID, key, "RSA")

	case "ecdsa", "ec", "ecdsa-p256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, ErrKeyGeneration
		}
		return c.storeAsymKey(keyID, key, "ECDSA")

	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, ErrKeyGeneration
		}
		return c.storeAsymKey(keyID, priv, "Ed25519")

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
		return c.storeAsymKey(keyID, key, "RSA")
	}
}

// storeAsymKey records a freshly generated asymmetric key and builds the
// response, which always carries the PKIX public key the way a real backend
// does so the module can publish CKA_MODULUS, CKA_PUBLIC_EXPONENT and
// CKA_EC_POINT on the public key object.
func (c *CryptoMockClient) storeAsymKey(keyID string, key crypto.PrivateKey, keyType string) (*transport.GenerateKeyResponse, error) {
	pubPEM, err := publicKeyPEM(key)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.asymmetricKeys[keyID] = key
	c.mu.Unlock()

	return &transport.GenerateKeyResponse{
		KeyID:        keyID,
		KeyType:      keyType,
		PublicKeyPEM: pubPEM,
	}, nil
}

// Sign performs a real signature using the stored or lazily-generated private key.
func (c *CryptoMockClient) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	key, err := c.getOrCreateAsymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	hashAlg := c.parseHash(req.Hash)
	digest := signingInput(hashAlg, req.Data, req.DataIsDigest)

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrUnsupportedKeyType
	}

	isPSS, err := parseSignaturePadding(req.Padding, key)
	if err != nil {
		return nil, err
	}
	if isPSS && hashAlg == crypto.Hash(0) {
		return nil, ErrPSSRequiresHash
	}
	// Under GODEBUG=fips140=only crypto/rsa panics on a PKCS#1 v1.5 signature
	// with no named digest instead of returning an error; the real service
	// makes the same check before the same call (go-xkms#486).
	if err := types.CheckRawPKCS1v15(key, hashAlg); err != nil {
		return nil, err
	}

	var sigOpts crypto.SignerOpts
	switch key.(type) {
	case ed25519.PrivateKey:
		// Ed25519 signs the raw message, not a digest
		sigOpts = crypto.Hash(0)
		digest = req.Data
	default:
		sigOpts = hashAlg
		if isPSS {
			sigOpts = &rsa.PSSOptions{Hash: hashAlg, SaltLength: req.SaltLength}
		}
	}

	sig, err := signer.Sign(rand.Reader, digest, sigOpts)
	if err != nil {
		return nil, err
	}

	return &transport.SignResponse{Signature: sig, Algorithm: "RSA-PKCS"}, nil
}

// parseSignaturePadding resolves a request's padding name for the given key,
// mirroring xkms.parseSignaturePadding so the mock backend and the real
// service answer a request the same way.
func parseSignaturePadding(padding string, key crypto.PrivateKey) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(padding)) {
	case "", "pkcs1v15":
		return false, nil
	case "pss":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return false, ErrPSSRequiresRSA
		}
		return true, nil
	default:
		return false, ErrUnsupportedPadding
	}
}

// Verify performs real signature verification using the stored or lazily-generated key.
func (c *CryptoMockClient) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	key, err := c.getOrCreateAsymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	hashAlg := c.parseHash(req.Hash)
	digest := signingInput(hashAlg, req.Data, req.DataIsDigest)

	isPSS, err := parseSignaturePadding(req.Padding, key)
	if err != nil {
		return nil, err
	}
	if isPSS && hashAlg == crypto.Hash(0) {
		return nil, ErrPSSRequiresHash
	}
	// rsa.VerifyPKCS1v15 has the same fips140=only panic as the signing side.
	if err := types.CheckRawPKCS1v15(key, hashAlg); err != nil {
		return nil, err
	}

	var valid bool
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if isPSS {
			verifyErr := rsa.VerifyPSS(&k.PublicKey, hashAlg, digest, req.Signature,
				&rsa.PSSOptions{Hash: hashAlg, SaltLength: req.SaltLength})
			valid = verifyErr == nil
			break
		}
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

	// Honor the requested tag length, as a real backend must. NIST SP 800-38D
	// section 5.2.1.2 defines a t-bit tag as the leading t bits of the full
	// tag; returning 128 bits to a caller that asked for 96 hands back a
	// ciphertext its peer cannot authenticate.
	gcm, err := newGCMWithTagSize(block, req.TagSize)
	if err != nil {
		return nil, err
	}

	// Honor a caller-supplied nonce, as a real backend must: the module sends
	// the IV from CK_GCM_PARAMS in EncryptRequest.Nonce, and encrypting under a
	// different one would make the ciphertext undecryptable with the IV the
	// caller specified. Only generate one when the caller supplied none.
	nonce := req.Nonce
	if len(nonce) == 0 {
		nonce = make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrInvalidNonceSize
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

	// The tag length comes from the request, never from the tag that arrived:
	// SP 800-38D section 5.2.2 verifies a t-bit tag by recomputing it at t
	// bits, so a full-length verifier rejects every truncated tag.
	gcm, err := newGCMWithTagSize(block, req.TagSize)
	if err != nil {
		return nil, err
	}
	if len(req.Tag) != gcm.Overhead() {
		return nil, ErrInvalidTagLength
	}

	// crypto/cipher panics rather than returning an error when the nonce is
	// not exactly NonceSize bytes. The nonce arrives from the caller, so
	// without this check any request carrying a short nonce panics the
	// process (mirrors the real PKCS#11 module's C_Decrypt path).
	if len(req.Nonce) != gcm.NonceSize() {
		return nil, ErrInvalidNonceSize
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

// EncryptAsym performs real RSA-OAEP encryption using the stored or
// lazily-generated asymmetric key's public half. This backs
// CryptoManager.encryptRSAOAEP's CKM_RSA_PKCS_OAEP dispatch, so the
// conformance suite exercises the same request the real service handles.
func (c *CryptoMockClient) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	key, err := c.getOrCreateAsymKey(req.KeyID)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrUnsupportedKeyType
	}

	hashAlg := c.parseHash(req.Hash)
	ciphertext, err := rsa.EncryptOAEP(hashAlg.New(), rand.Reader, &rsaKey.PublicKey, req.Plaintext, nil)
	if err != nil {
		return nil, err
	}

	return &transport.EncryptAsymResponse{Ciphertext: ciphertext}, nil
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

// GetImportParameters issues the ephemeral RSA wrapping key for a key import,
// mirroring the ceremony pkg/xkms runs against a real backend.
func (c *CryptoMockClient) GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	if req == nil || req.KeyID == "" {
		return nil, ErrKeyNotFound
	}

	importKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, ErrKeyGeneration
	}

	c.mu.Lock()
	c.importKeys[req.KeyID] = importKey
	c.mu.Unlock()

	// The real service marshals the wrapping key with x509.MarshalPKIXPublicKey,
	// so a module that parsed any other encoding would work here and fail
	// against the daemon.
	publicDER, err := x509.MarshalPKIXPublicKey(&importKey.PublicKey)
	if err != nil {
		return nil, ErrPublicKeyEncode
	}

	return &transport.GetImportParametersResponse{
		WrappingPublicKey: publicDER,
		ImportToken:       []byte(req.KeyID),
		Algorithm:         "RSAES_OAEP_SHA_256",
	}, nil
}

// ImportKey unwraps material produced by the key GetImportParameters issued and
// records it under the requested key id, so a key imported through this mock is
// afterwards usable by every operation that resolves a key by id.
func (c *CryptoMockClient) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	if req == nil || req.KeyID == "" {
		return nil, ErrKeyNotFound
	}

	c.mu.RLock()
	importKey, ok := c.importKeys[req.KeyID]
	c.mu.RUnlock()
	if !ok {
		// Importing without first obtaining parameters is a protocol error, not
		// an unknown key: answering anything else would let a module skip the
		// ceremony and still appear to work.
		return nil, ErrKeyNotFound
	}

	keyMaterial, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, importKey, req.WrappedKeyMaterial, nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	c.mu.Lock()
	c.symmetricKeys[req.KeyID] = keyMaterial
	delete(c.importKeys, req.KeyID)
	c.mu.Unlock()

	return &transport.ImportKeyResponse{Success: true, KeyID: req.KeyID}, nil
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

// newGCMWithTagSize builds an AES-GCM AEAD producing a tagSize-byte
// authentication tag, with zero selecting the full 16-byte tag. It refuses a
// length outside the set NIST SP 800-38D section 5.2.1.2 approves, as a real
// backend must: substituting the nearest permitted length would hand back a
// tag the caller's peer cannot verify.
func newGCMWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	if tagSize == 0 {
		return cipher.NewGCM(block)
	}
	if tagSize < 12 || tagSize > 16 {
		return nil, ErrInvalidTagSize
	}
	return cipher.NewGCMWithTagSize(block, tagSize)
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

// parseHash converts a hash algorithm name to crypto.Hash using map-based
// dispatch. The "NONE" sentinel maps to crypto.Hash(0), meaning "the request
// already carries the bytes to sign; do not hash them".
func (c *CryptoMockClient) parseHash(hashName string) crypto.Hash {
	name := strings.ToLower(hashName)
	if name == hashNone {
		return crypto.Hash(0)
	}
	if h, ok := hashDispatch[name]; ok {
		return h
	}
	return crypto.SHA256
}

// signingInput returns the bytes a signature is computed over.
//
// The data is hashed only when a hash function was named AND the request did
// not declare the data to already be that digest. Those are two separate
// questions: RSASSA-PSS names its digest for MGF1 and the salt length while
// taking an already-hashed input (PKCS#11 v3.2 section 6.1.10), so a backend
// that treats "hash named" as "hash it" digests the caller's digest again and
// produces a signature that verifies against nothing else.
func signingInput(h crypto.Hash, data []byte, dataIsDigest bool) []byte {
	if h == crypto.Hash(0) || dataIsDigest {
		return data
	}
	return computeDigest(h, data)
}

// publicKeyPEM encodes a private key's public half as a PKIX PEM block.
//
// A real backend returns this on every asymmetric C_GenerateKeyPair, and the
// module parses it into CKA_MODULUS / CKA_PUBLIC_EXPONENT / CKA_EC_POINT.
// Without it those attributes are absent, C_VerifyRecover has no public key to
// work with, and no conformance test can check a signature against an oracle
// outside the module.
func publicKeyPEM(key crypto.PrivateKey) (string, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", ErrUnsupportedKeyType
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", ErrPublicKeyEncode
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
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
