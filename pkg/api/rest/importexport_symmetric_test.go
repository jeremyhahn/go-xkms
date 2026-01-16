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

package rest

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	localwebauthn "github.com/jeremyhahn/go-keychain/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSymmetricKey implements types.SymmetricKey for testing
type mockSymmetricKey struct {
	algorithm string
	keySize   int
	rawKey    []byte
}

func (k *mockSymmetricKey) Algorithm() string {
	return k.algorithm
}

func (k *mockSymmetricKey) KeySize() int {
	return k.keySize
}

func (k *mockSymmetricKey) Raw() ([]byte, error) {
	return k.rawKey, nil
}

// mockSymmetricEncrypter implements types.SymmetricEncrypter for testing
type mockSymmetricEncrypter struct {
	key       []byte
	algorithm string
}

func (e *mockSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if opts != nil && opts.Nonce != nil {
		nonce = opts.Nonce
	} else {
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}

	var aad []byte
	if opts != nil {
		aad = opts.AdditionalData
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Split ciphertext and tag (tag is last 16 bytes for GCM)
	tagSize := gcm.Overhead()
	tag := ciphertext[len(ciphertext)-tagSize:]
	ciphertextOnly := ciphertext[:len(ciphertext)-tagSize]

	return &types.EncryptedData{
		Ciphertext: ciphertextOnly,
		Nonce:      nonce,
		Tag:        tag,
		Algorithm:  e.algorithm,
	}, nil
}

func (e *mockSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var aad []byte
	if opts != nil {
		aad = opts.AdditionalData
	}

	// Combine ciphertext and tag for GCM
	ciphertext := append(data.Ciphertext, data.Tag...)

	return gcm.Open(nil, data.Nonce, ciphertext, aad)
}

// mockImportExportSymmetricBackend implements both ImportExportBackend and SymmetricBackend
type mockImportExportSymmetricBackend struct {
	mu            sync.RWMutex
	keys          map[string]crypto.PrivateKey
	symmetricKeys map[string]*mockSymmetricKey
	wrappingKey   *rsa.PrivateKey

	// Configurable error functions
	GetImportParametersFunc func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error)
	WrapKeyFunc             func(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)
	UnwrapKeyFunc           func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error)
	ImportKeyFunc           func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error
	ExportKeyFunc           func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error)
	CopyKeyFunc             func(srcAttrs *types.KeyAttributes, dstAttrs *types.KeyAttributes, srcBackend, dstBackend backend.ImportExportBackend) error

	GenerateSymmetricKeyFunc func(attrs *types.KeyAttributes) (types.SymmetricKey, error)
	GetSymmetricKeyFunc      func(attrs *types.KeyAttributes) (types.SymmetricKey, error)
	SymmetricEncrypterFunc   func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error)
}

func newMockImportExportSymmetricBackend() *mockImportExportSymmetricBackend {
	wrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &mockImportExportSymmetricBackend{
		keys:          make(map[string]crypto.PrivateKey),
		symmetricKeys: make(map[string]*mockSymmetricKey),
		wrappingKey:   wrappingKey,
	}
}

// Backend interface implementation
func (m *mockImportExportSymmetricBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (m *mockImportExportSymmetricBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true,
		HardwareBacked:      false,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,
		Import:              true,
		Export:              true,
	}
}

func (m *mockImportExportSymmetricBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var key crypto.PrivateKey
	var err error

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		keySize := 2048
		if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
			keySize = attrs.RSAAttributes.KeySize
		}
		key, err = rsa.GenerateKey(rand.Reader, keySize)
	case x509.ECDSA:
		curve := elliptic.P256()
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			curve = attrs.ECCAttributes.Curve
		}
		key, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", attrs.KeyAlgorithm)
	}

	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockImportExportSymmetricBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}
	return key, nil
}

func (m *mockImportExportSymmetricBackend) DeleteKey(attrs *types.KeyAttributes) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.keys[attrs.CN]; !ok {
		if _, ok := m.symmetricKeys[attrs.CN]; !ok {
			return fmt.Errorf("key not found: %s", attrs.CN)
		}
		delete(m.symmetricKeys, attrs.CN)
		return nil
	}
	delete(m.keys, attrs.CN)
	return nil
}

func (m *mockImportExportSymmetricBackend) ListKeys() ([]*types.KeyAttributes, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	attrs := make([]*types.KeyAttributes, 0, len(m.keys)+len(m.symmetricKeys))
	for cn := range m.keys {
		attrs = append(attrs, &types.KeyAttributes{
			CN:           cn,
			KeyType:      types.KeyTypeSigning,
			StoreType:    types.StoreSoftware,
			KeyAlgorithm: x509.RSA,
		})
	}
	for cn, key := range m.symmetricKeys {
		attrs = append(attrs, &types.KeyAttributes{
			CN:                 cn,
			KeyType:            types.KeyTypeSecret,
			StoreType:          types.StoreSoftware,
			SymmetricAlgorithm: types.SymmetricAlgorithm(key.algorithm),
		})
	}
	return attrs, nil
}

func (m *mockImportExportSymmetricBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Signer")
	}
	return signer, nil
}

func (m *mockImportExportSymmetricBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", attrs.CN)
	}

	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("key does not implement crypto.Decrypter")
	}
	return decrypter, nil
}

func (m *mockImportExportSymmetricBackend) RotateKey(attrs *types.KeyAttributes) error {
	return nil
}

func (m *mockImportExportSymmetricBackend) Close() error {
	return nil
}

// ImportExportBackend interface implementation
func (m *mockImportExportSymmetricBackend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if m.GetImportParametersFunc != nil {
		return m.GetImportParametersFunc(attrs, algorithm)
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	return &backend.ImportParameters{
		WrappingPublicKey: &m.wrappingKey.PublicKey,
		Algorithm:         algorithm,
		ImportToken:       []byte("mock-import-token"),
		ExpiresAt:         &expiresAt,
		KeySpec:           "RSA_2048",
	}, nil
}

func (m *mockImportExportSymmetricBackend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if m.WrapKeyFunc != nil {
		return m.WrapKeyFunc(keyMaterial, params)
	}

	// Simple RSA-OAEP wrapping for testing
	pubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrapping public key is not RSA")
	}

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, keyMaterial, nil)
	if err != nil {
		return nil, err
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
	}, nil
}

func (m *mockImportExportSymmetricBackend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if m.UnwrapKeyFunc != nil {
		return m.UnwrapKeyFunc(wrapped, params)
	}

	// Simple RSA-OAEP unwrapping for testing
	unwrapped, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, m.wrappingKey, wrapped.WrappedKey, nil)
	if err != nil {
		return nil, err
	}

	return unwrapped, nil
}

func (m *mockImportExportSymmetricBackend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if m.ImportKeyFunc != nil {
		return m.ImportKeyFunc(attrs, wrapped)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// For testing, we just store a placeholder key
	if attrs.SymmetricAlgorithm != "" {
		m.symmetricKeys[attrs.CN] = &mockSymmetricKey{
			algorithm: string(attrs.SymmetricAlgorithm),
			keySize:   256,
			rawKey:    make([]byte, 32),
		}
	} else {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		m.keys[attrs.CN] = key
	}

	return nil
}

func (m *mockImportExportSymmetricBackend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if m.ExportKeyFunc != nil {
		return m.ExportKeyFunc(attrs, algorithm)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if key exists
	if _, ok := m.keys[attrs.CN]; !ok {
		if _, ok := m.symmetricKeys[attrs.CN]; !ok {
			return nil, fmt.Errorf("key not found: %s", attrs.CN)
		}
	}

	// Return mock wrapped key material
	return &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("mock-wrapped-key-material"),
		Algorithm:   algorithm,
		ImportToken: []byte("mock-export-token"),
	}, nil
}

// SymmetricBackend interface implementation
func (m *mockImportExportSymmetricBackend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if m.GenerateSymmetricKeyFunc != nil {
		return m.GenerateSymmetricKeyFunc(attrs)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	keySize := 32 // AES-256 by default
	switch attrs.SymmetricAlgorithm {
	case types.SymmetricAES128GCM:
		keySize = 16
	case types.SymmetricAES192GCM:
		keySize = 24
	case types.SymmetricAES256GCM:
		keySize = 32
	}

	rawKey := make([]byte, keySize)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, err
	}

	key := &mockSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   keySize * 8,
		rawKey:    rawKey,
	}
	m.symmetricKeys[attrs.CN] = key

	return key, nil
}

func (m *mockImportExportSymmetricBackend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if m.GetSymmetricKeyFunc != nil {
		return m.GetSymmetricKeyFunc(attrs)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.symmetricKeys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("symmetric key not found: %s", attrs.CN)
	}
	return key, nil
}

func (m *mockImportExportSymmetricBackend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	if m.SymmetricEncrypterFunc != nil {
		return m.SymmetricEncrypterFunc(attrs)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.symmetricKeys[attrs.CN]
	if !ok {
		return nil, fmt.Errorf("symmetric key not found: %s", attrs.CN)
	}

	return &mockSymmetricEncrypter{
		key:       key.rawKey,
		algorithm: key.algorithm,
	}, nil
}

// SetKey allows tests to directly set a key in storage
func (m *mockImportExportSymmetricBackend) SetKey(keyID string, key crypto.PrivateKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[keyID] = key
}

// SetSymmetricKey allows tests to directly set a symmetric key
func (m *mockImportExportSymmetricBackend) SetSymmetricKey(keyID string, rawKey []byte, algorithm string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.symmetricKeys[keyID] = &mockSymmetricKey{
		algorithm: algorithm,
		keySize:   len(rawKey) * 8,
		rawKey:    rawKey,
	}
}

// Verify interface compliance
var _ types.Backend = (*mockImportExportSymmetricBackend)(nil)
var _ backend.ImportExportBackend = (*mockImportExportSymmetricBackend)(nil)
var _ types.SymmetricBackend = (*mockImportExportSymmetricBackend)(nil)

// mockKeyStoreWithImportExport wraps the mock backend to implement keychain.KeyStore
type mockKeyStoreWithImportExport struct {
	backend *mockImportExportSymmetricBackend
}

func newMockKeyStoreWithImportExport() *mockKeyStoreWithImportExport {
	return &mockKeyStoreWithImportExport{
		backend: newMockImportExportSymmetricBackend(),
	}
}

func (m *mockKeyStoreWithImportExport) Backend() types.Backend {
	return m.backend
}

func (m *mockKeyStoreWithImportExport) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}

func (m *mockKeyStoreWithImportExport) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.RSA
	return m.backend.GenerateKey(attrs)
}

func (m *mockKeyStoreWithImportExport) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.ECDSA
	return m.backend.GenerateKey(attrs)
}

func (m *mockKeyStoreWithImportExport) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("ed25519 not supported")
}

func (m *mockKeyStoreWithImportExport) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return m.backend.GetKey(attrs)
}

func (m *mockKeyStoreWithImportExport) DeleteKey(attrs *types.KeyAttributes) error {
	return m.backend.DeleteKey(attrs)
}

func (m *mockKeyStoreWithImportExport) ListKeys() ([]*types.KeyAttributes, error) {
	return m.backend.ListKeys()
}

func (m *mockKeyStoreWithImportExport) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return m.backend.GenerateKey(attrs)
}

func (m *mockKeyStoreWithImportExport) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return m.backend.Signer(attrs)
}

func (m *mockKeyStoreWithImportExport) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return m.backend.Decrypter(attrs)
}

func (m *mockKeyStoreWithImportExport) SaveCert(keyID string, cert *x509.Certificate) error {
	return nil
}

func (m *mockKeyStoreWithImportExport) GetCert(keyID string) (*x509.Certificate, error) {
	return nil, fmt.Errorf("cert not found")
}

func (m *mockKeyStoreWithImportExport) DeleteCert(keyID string) error {
	return nil
}

func (m *mockKeyStoreWithImportExport) ListCerts() ([]string, error) {
	return nil, nil
}

func (m *mockKeyStoreWithImportExport) CertExists(keyID string) (bool, error) {
	return false, nil
}

func (m *mockKeyStoreWithImportExport) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	return nil
}

func (m *mockKeyStoreWithImportExport) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	return nil, nil
}

func (m *mockKeyStoreWithImportExport) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, fmt.Errorf("not implemented")
}

func (m *mockKeyStoreWithImportExport) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	return m.backend.GetKey(&types.KeyAttributes{CN: keyID})
}

func (m *mockKeyStoreWithImportExport) GetSignerByID(keyID string) (crypto.Signer, error) {
	return m.backend.Signer(&types.KeyAttributes{CN: keyID})
}

func (m *mockKeyStoreWithImportExport) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	return m.backend.Decrypter(&types.KeyAttributes{CN: keyID})
}

func (m *mockKeyStoreWithImportExport) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	return nil, fmt.Errorf("not supported")
}

func (m *mockKeyStoreWithImportExport) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	return nil, fmt.Errorf("not supported")
}

func (m *mockKeyStoreWithImportExport) CanSeal() bool {
	return false
}

func (m *mockKeyStoreWithImportExport) Close() error {
	return m.backend.Close()
}

// setupImportExportTestService sets up a test service with import/export and symmetric support
func setupImportExportTestService(t *testing.T, backendName string) *mockKeyStoreWithImportExport {
	t.Helper()
	ks := newMockKeyStoreWithImportExport()

	keychain.Reset()

	err := keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			backendName: ks,
		},
		DefaultBackend: backendName,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		keychain.Reset()
	})

	return ks
}

// ============================================================================
// Tests for EncryptHandler success path
// ============================================================================

func TestEncryptHandler_SymmetricSuccessPath(t *testing.T) {
	t.Run("encrypts data with symmetric key successfully", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Create a symmetric key
		rawKey := make([]byte, 32) // AES-256
		_, err := rand.Read(rawKey)
		require.NoError(t, err)

		ks.backend.SetSymmetricKey("sym-key", rawKey, string(types.SymmetricAES256GCM))

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdCBwbGFpbnRleHQ="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sym-key/encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp EncryptResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Ciphertext)
		assert.NotEmpty(t, resp.Nonce)
		assert.NotEmpty(t, resp.Tag)
	})

	t.Run("encrypts data with additional data", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		rawKey := make([]byte, 32)
		_, err := rand.Read(rawKey)
		require.NoError(t, err)

		ks.backend.SetSymmetricKey("sym-key-aad", rawKey, string(types.SymmetricAES256GCM))

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA==", "additional_data": "YXNzb2NpYXRlZCBkYXRh"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sym-key-aad/encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestEncryptHandler_SymmetricEncrypterError(t *testing.T) {
	t.Run("returns error when encrypter fails", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		rawKey := make([]byte, 32)
		_, _ = rand.Read(rawKey)
		ks.backend.SetSymmetricKey("sym-key-error", rawKey, string(types.SymmetricAES256GCM))

		ks.backend.SymmetricEncrypterFunc = func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
			return nil, fmt.Errorf("encrypter error")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sym-key-error/encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ============================================================================
// Tests for GetImportParametersHandler success path
// ============================================================================

func TestGetImportParametersHandler_ImportExportSuccessPath(t *testing.T) {
	t.Run("returns import parameters successfully", func(t *testing.T) {
		setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "test-key", "key_type": "rsa", "algorithm": "RSAES_OAEP_SHA_256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp GetImportParametersResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.WrappingPublicKeyPEM)
		assert.Equal(t, "RSAES_OAEP_SHA_256", resp.Algorithm)
		assert.NotEmpty(t, resp.ImportToken)
		assert.NotEmpty(t, resp.ExpiresAt)
	})
}

func TestGetImportParametersHandler_ImportExportError(t *testing.T) {
	t.Run("returns error when GetImportParameters fails", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.backend.GetImportParametersFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
			return nil, fmt.Errorf("get import parameters failed")
		}

		body := `{"backend": "test-backend", "key_id": "test-key", "key_type": "rsa", "algorithm": "RSAES_OAEP_SHA_256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ============================================================================
// Tests for WrapKeyHandler success path
// ============================================================================

func TestWrapKeyHandler_ImportExportSuccessPath(t *testing.T) {
	t.Run("wraps key material successfully", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Get wrapping public key PEM
		wrappingKeyPEM := getWrappingPublicKeyPEM(t, ks.backend.wrappingKey)

		keyMaterial := "dGVzdCBrZXkgbWF0ZXJpYWw=" // base64 encoded
		body := fmt.Sprintf(`{"key_material": "%s", "wrapping_public_key_pem": %q, "algorithm": "RSAES_OAEP_SHA_256"}`, keyMaterial, wrappingKeyPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp WrapKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.WrappedKey)
		assert.Equal(t, "RSAES_OAEP_SHA_256", resp.Algorithm)
	})
}

func TestWrapKeyHandler_ImportExportError(t *testing.T) {
	t.Run("returns error when WrapKey fails", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.backend.WrapKeyFunc = func(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
			return nil, fmt.Errorf("wrap key failed")
		}

		wrappingKeyPEM := getWrappingPublicKeyPEM(t, ks.backend.wrappingKey)

		body := fmt.Sprintf(`{"key_material": "dGVzdA==", "wrapping_public_key_pem": %q, "algorithm": "RSAES_OAEP_SHA_256"}`, wrappingKeyPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ============================================================================
// Tests for UnwrapKeyHandler success path
// ============================================================================

func TestUnwrapKeyHandler_ImportExportSuccessPath(t *testing.T) {
	t.Run("unwraps key material successfully", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// First wrap some key material
		keyMaterial := []byte("test key material")
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &ks.backend.wrappingKey.PublicKey, keyMaterial, nil)
		require.NoError(t, err)

		wrappingKeyPEM := getWrappingPublicKeyPEM(t, ks.backend.wrappingKey)

		body := fmt.Sprintf(`{"wrapped_key": "%s", "wrapping_public_key_pem": %q, "algorithm": "RSAES_OAEP_SHA_256"}`,
			base64.StdEncoding.EncodeToString(wrapped), wrappingKeyPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UnwrapKeyResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.KeyMaterial)
	})
}

func TestUnwrapKeyHandler_ImportExportError(t *testing.T) {
	t.Run("returns error when UnwrapKey fails", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.backend.UnwrapKeyFunc = func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
			return nil, fmt.Errorf("unwrap key failed")
		}

		wrappingKeyPEM := getWrappingPublicKeyPEM(t, ks.backend.wrappingKey)

		body := fmt.Sprintf(`{"wrapped_key": "dGVzdA==", "wrapping_public_key_pem": %q, "algorithm": "RSAES_OAEP_SHA_256"}`, wrappingKeyPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ============================================================================
// Tests for ImportKeyHandler success path
// ============================================================================

func TestImportKeyHandler_ImportExportSuccessPath(t *testing.T) {
	t.Run("imports key successfully", func(t *testing.T) {
		setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "imported-key", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSAES_OAEP_SHA_256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp ImportKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Equal(t, "imported-key", resp.KeyID)
		assert.Contains(t, resp.Message, "imported successfully")
	})

	t.Run("imports symmetric key successfully", func(t *testing.T) {
		setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"backend": "test-backend", "key_id": "imported-sym-key", "key_type": "symmetric", "wrapped_key": "dGVzdA==", "algorithm": "RSAES_OAEP_SHA_256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestImportKeyHandler_ImportExportError(t *testing.T) {
	t.Run("returns error when ImportKey fails", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		ks.backend.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
			return fmt.Errorf("import key failed")
		}

		body := `{"backend": "test-backend", "key_id": "import-error-key", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSAES_OAEP_SHA_256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ============================================================================
// Tests for ExportKeyHandler success path
// ============================================================================

func TestExportKeyHandler_ImportExportSuccessPath(t *testing.T) {
	t.Run("exports key successfully", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Create a key to export
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.backend.SetKey("export-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSAES_OAEP_SHA_256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/export-key/export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ExportKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "export-key", resp.KeyID)
		assert.NotEmpty(t, resp.WrappedKey)
		assert.Equal(t, "RSAES_OAEP_SHA_256", resp.Algorithm)
	})
}

func TestExportKeyHandler_ImportExportError(t *testing.T) {
	t.Run("returns error when ExportKey fails", func(t *testing.T) {
		ks := setupImportExportTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.backend.SetKey("export-error-key", key)

		ks.backend.ExportKeyFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
			return nil, fmt.Errorf("export key failed")
		}

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSAES_OAEP_SHA_256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/export-error-key/export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ============================================================================
// Tests for CopyKeyHandler success path
// ============================================================================

func TestCopyKeyHandler_ImportExportSuccessPath(t *testing.T) {
	t.Run("copies key successfully between backends", func(t *testing.T) {
		// Setup two backends
		srcKs := newMockKeyStoreWithImportExport()
		dstKs := newMockKeyStoreWithImportExport()

		keychain.Reset()

		err := keychain.Initialize(&keychain.ServiceConfig{
			Backends: map[string]keychain.KeyStore{
				"src-backend": srcKs,
				"dst-backend": dstKs,
			},
			DefaultBackend: "src-backend",
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			keychain.Reset()
		})

		// Create a key in source backend
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		srcKs.backend.SetKey("source-key", key)

		ctx := newTestHandlerContext()

		body := `{
			"source_backend": "src-backend",
			"source_key_id": "source-key",
			"dest_backend": "dst-backend",
			"dest_key_id": "dest-key",
			"key_type": "rsa",
			"algorithm": "RSAES_OAEP_SHA_256"
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CopyKeyResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "copied successfully")
	})
}

func TestCopyKeyHandler_SourceKeyNotFoundError(t *testing.T) {
	t.Run("returns error when source key not found", func(t *testing.T) {
		srcKs := newMockKeyStoreWithImportExport()
		dstKs := newMockKeyStoreWithImportExport()

		keychain.Reset()

		err := keychain.Initialize(&keychain.ServiceConfig{
			Backends: map[string]keychain.KeyStore{
				"src-backend": srcKs,
				"dst-backend": dstKs,
			},
			DefaultBackend: "src-backend",
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			keychain.Reset()
		})

		ctx := newTestHandlerContext()

		body := `{
			"source_backend": "src-backend",
			"source_key_id": "nonexistent-key",
			"dest_backend": "dst-backend",
			"dest_key_id": "dest-key",
			"key_type": "rsa",
			"algorithm": "RSAES_OAEP_SHA_256"
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestCopyKeyHandler_ExportError(t *testing.T) {
	t.Run("returns error when export fails during copy", func(t *testing.T) {
		srcKs := newMockKeyStoreWithImportExport()
		dstKs := newMockKeyStoreWithImportExport()

		keychain.Reset()

		err := keychain.Initialize(&keychain.ServiceConfig{
			Backends: map[string]keychain.KeyStore{
				"src-backend": srcKs,
				"dst-backend": dstKs,
			},
			DefaultBackend: "src-backend",
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			keychain.Reset()
		})

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		srcKs.backend.SetKey("source-key", key)

		srcKs.backend.ExportKeyFunc = func(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
			return nil, fmt.Errorf("export key failed during copy")
		}

		ctx := newTestHandlerContext()

		body := `{
			"source_backend": "src-backend",
			"source_key_id": "source-key",
			"dest_backend": "dst-backend",
			"dest_key_id": "dest-key",
			"key_type": "rsa",
			"algorithm": "RSAES_OAEP_SHA_256"
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestCopyKeyHandler_ImportError(t *testing.T) {
	t.Run("returns error when ImportKey fails", func(t *testing.T) {
		srcKs := newMockKeyStoreWithImportExport()
		dstKs := newMockKeyStoreWithImportExport()

		keychain.Reset()

		err := keychain.Initialize(&keychain.ServiceConfig{
			Backends: map[string]keychain.KeyStore{
				"src-backend": srcKs,
				"dst-backend": dstKs,
			},
			DefaultBackend: "src-backend",
		})
		require.NoError(t, err)

		t.Cleanup(func() {
			keychain.Reset()
		})

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		srcKs.backend.SetKey("source-key", key)

		dstKs.backend.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
			return fmt.Errorf("import key failed during copy")
		}

		ctx := newTestHandlerContext()

		body := `{
			"source_backend": "src-backend",
			"source_key_id": "source-key",
			"dest_backend": "dst-backend",
			"dest_key_id": "dest-key",
			"key_type": "rsa",
			"algorithm": "RSAES_OAEP_SHA_256"
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// ============================================================================
// Tests for CleanupSessions with non-MemorySessionStore
// ============================================================================

// mockNonMemorySessionStore implements localwebauthn.SessionStore but is not a MemorySessionStore
type mockNonMemorySessionStore struct{}

func (m *mockNonMemorySessionStore) Save(ctx context.Context, session *webauthn.SessionData) (string, error) {
	return "mock-session-id", nil
}

func (m *mockNonMemorySessionStore) Get(ctx context.Context, sessionID string) (*webauthn.SessionData, error) {
	return nil, fmt.Errorf("session not found")
}

func (m *mockNonMemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	return nil
}

// Verify interface compliance
var _ localwebauthn.SessionStore = (*mockNonMemorySessionStore)(nil)

func TestCleanupSessions_NonMemorySessionStore(t *testing.T) {
	t.Run("returns 0 for non-memory session store", func(t *testing.T) {
		stores := NewWebAuthnStores(nil)
		// Replace with non-memory store
		stores.sessions = &mockNonMemorySessionStore{}

		removed := stores.CleanupSessions()
		assert.Equal(t, 0, removed)
	})
}

// ============================================================================
// Helper functions
// ============================================================================

func getWrappingPublicKeyPEM(t *testing.T, privateKey *rsa.PrivateKey) string {
	t.Helper()
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}
