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

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKeyStore is a mock implementation of KeyStore for testing
type mockKeyStore struct {
	name        string
	keys        map[string]crypto.PrivateKey
	certs       map[string]*x509.Certificate
	backend     types.Backend
	closeError  error
	listKeysErr error
}

func newMockKeyStore(name string) *mockKeyStore {
	return &mockKeyStore{
		name:  name,
		keys:  make(map[string]crypto.PrivateKey),
		certs: make(map[string]*x509.Certificate),
	}
}

func (m *mockKeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockKeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockKeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func (m *mockKeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	if _, ok := m.keys[attrs.CN]; !ok {
		return errors.New("key not found")
	}
	delete(m.keys, attrs.CN)
	return nil
}

func (m *mockKeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	if m.listKeysErr != nil {
		return nil, m.listKeysErr
	}
	attrs := make([]*types.KeyAttributes, 0, len(m.keys))
	for cn := range m.keys {
		attrs = append(attrs, &types.KeyAttributes{CN: cn})
	}
	return attrs, nil
}

func (m *mockKeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	if signer, ok := key.(crypto.Signer); ok {
		return signer, nil
	}
	return nil, errors.New("key does not implement crypto.Signer")
}

func (m *mockKeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	if decrypter, ok := key.(crypto.Decrypter); ok {
		return decrypter, nil
	}
	return nil, errors.New("key does not implement crypto.Decrypter")
}

func (m *mockKeyStore) SaveCert(keyID string, cert *x509.Certificate) error {
	m.certs[keyID] = cert
	return nil
}

func (m *mockKeyStore) GetCert(keyID string) (*x509.Certificate, error) {
	cert, ok := m.certs[keyID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cert, nil
}

func (m *mockKeyStore) DeleteCert(keyID string) error {
	if _, ok := m.certs[keyID]; !ok {
		return errors.New("certificate not found")
	}
	delete(m.certs, keyID)
	return nil
}

func (m *mockKeyStore) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	return errors.New("not implemented")
}

func (m *mockKeyStore) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKeyStore) ListCerts() ([]string, error) {
	certIDs := make([]string, 0, len(m.certs))
	for id := range m.certs {
		certIDs = append(certIDs, id)
	}
	return certIDs, nil
}

func (m *mockKeyStore) CertExists(keyID string) (bool, error) {
	_, ok := m.certs[keyID]
	return ok, nil
}

func (m *mockKeyStore) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("not implemented")
}

func (m *mockKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	return m.GetKey(&types.KeyAttributes{CN: keyID})
}

func (m *mockKeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	return m.Signer(&types.KeyAttributes{CN: keyID})
}

func (m *mockKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	return m.Decrypter(&types.KeyAttributes{CN: keyID})
}

func (m *mockKeyStore) Backend() types.Backend {
	return m.backend
}

func (m *mockKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}

func (m *mockKeyStore) Close() error {
	return m.closeError
}

// Test helpers

func setupFacade(t *testing.T) (*mockKeyStore, *mockKeyStore) {
	t.Helper()
	Reset() // Ensure clean state

	backend1 := newMockKeyStore("backend1")
	backend2 := newMockKeyStore("backend2")

	config := &FacadeConfig{
		Backends: map[string]KeyStore{
			"backend1": backend1,
			"backend2": backend2,
		},
		DefaultBackend: "backend1",
	}

	err := Initialize(config)
	require.NoError(t, err)

	return backend1, backend2
}

func createTestCert(t *testing.T, cn string, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// Test Initialize

func TestInitialize_Success(t *testing.T) {
	Reset()

	backend1 := newMockKeyStore("backend1")
	config := &FacadeConfig{
		Backends: map[string]KeyStore{
			"backend1": backend1,
		},
		DefaultBackend: "backend1",
	}

	err := Initialize(config)
	assert.NoError(t, err)
	assert.True(t, IsInitialized())
}

func TestInitialize_NilConfig(t *testing.T) {
	Reset()

	err := Initialize(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

func TestInitialize_EmptyBackends(t *testing.T) {
	Reset()

	config := &FacadeConfig{
		Backends:       map[string]KeyStore{},
		DefaultBackend: "backend1",
	}

	err := Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one backend must be configured")
}

func TestInitialize_InvalidDefaultBackend(t *testing.T) {
	Reset()

	backend1 := newMockKeyStore("backend1")
	config := &FacadeConfig{
		Backends: map[string]KeyStore{
			"backend1": backend1,
		},
		DefaultBackend: "nonexistent",
	}

	err := Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "default backend nonexistent not found")
}

func TestInitialize_DefaultToFirstBackend(t *testing.T) {
	Reset()

	backend1 := newMockKeyStore("backend1")
	config := &FacadeConfig{
		Backends: map[string]KeyStore{
			"backend1": backend1,
		},
		// No default specified
	}

	err := Initialize(config)
	assert.NoError(t, err)

	// Should default to first available backend
	defaultKS, err := DefaultBackend()
	assert.NoError(t, err)
	assert.NotNil(t, defaultKS)
}

func TestInitialize_OnlyOnce(t *testing.T) {
	Reset()

	backend1 := newMockKeyStore("backend1")
	config1 := &FacadeConfig{
		Backends: map[string]KeyStore{
			"backend1": backend1,
		},
		DefaultBackend: "backend1",
	}

	err := Initialize(config1)
	assert.NoError(t, err)

	// Second initialization should succeed (idempotent)
	backend2 := newMockKeyStore("backend2")
	config2 := &FacadeConfig{
		Backends: map[string]KeyStore{
			"backend2": backend2,
		},
		DefaultBackend: "backend2",
	}

	err = Initialize(config2)
	assert.NoError(t, err)

	// Should still have original backends
	backends := Backends()
	assert.Contains(t, backends, "backend1")
	assert.NotContains(t, backends, "backend2")
}

// Test Backend

func TestBackend_Success(t *testing.T) {
	backend1, _ := setupFacade(t)

	ks, err := Backend("backend1")
	assert.NoError(t, err)
	assert.Equal(t, backend1, ks)
}

func TestBackend_NotFound(t *testing.T) {
	setupFacade(t)

	_, err := Backend("nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestBackend_NotInitialized(t *testing.T) {
	Reset()

	_, err := Backend("backend1")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// Test DefaultBackend

func TestDefaultBackend_Success(t *testing.T) {
	backend1, _ := setupFacade(t)

	ks, err := DefaultBackend()
	assert.NoError(t, err)
	assert.Equal(t, backend1, ks)
}

func TestDefaultBackend_NotInitialized(t *testing.T) {
	Reset()

	_, err := DefaultBackend()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// Test Backends

func TestBackends_Success(t *testing.T) {
	setupFacade(t)

	backends := Backends()
	assert.Len(t, backends, 2)
	assert.Contains(t, backends, "backend1")
	assert.Contains(t, backends, "backend2")
}

func TestBackends_NotInitialized(t *testing.T) {
	Reset()

	backends := Backends()
	assert.Empty(t, backends)
}

// Test KeyByID

func TestKeyByID_WithBackendPrefix(t *testing.T) {
	backend1, _ := setupFacade(t)

	// Generate a key in backend1
	attrs := &types.KeyAttributes{CN: "test-key"}
	expectedKey, err := backend1.GenerateRSA(attrs)
	require.NoError(t, err)

	// Retrieve using backend:key-id format
	key, err := KeyByID("backend1:test-key")
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, key)
}

func TestKeyByID_WithoutBackendPrefix(t *testing.T) {
	backend1, _ := setupFacade(t)

	// Generate a key in default backend
	attrs := &types.KeyAttributes{CN: "test-key"}
	expectedKey, err := backend1.GenerateRSA(attrs)
	require.NoError(t, err)

	// Retrieve using just key-id (uses default backend)
	key, err := KeyByID("test-key")
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, key)
}

func TestKeyByID_InvalidBackend(t *testing.T) {
	setupFacade(t)

	_, err := KeyByID("nonexistent:test-key")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestKeyByID_KeyNotFound(t *testing.T) {
	setupFacade(t)

	_, err := KeyByID("backend1:nonexistent-key")
	assert.Error(t, err)
}

func TestKeyByID_NotInitialized(t *testing.T) {
	Reset()

	_, err := KeyByID("test-key")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// Test Signer

func TestSigner_Success(t *testing.T) {
	backend1, _ := setupFacade(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := backend1.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, err := Signer("backend1:test-key")
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

// Test Decrypter

func TestDecrypter_Success(t *testing.T) {
	backend1, _ := setupFacade(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := backend1.GenerateRSA(attrs)
	require.NoError(t, err)

	decrypter, err := Decrypter("backend1:test-key")
	assert.NoError(t, err)
	assert.NotNil(t, decrypter)
}

// Test DeleteKey

func TestDeleteKey_WithBackendPrefix(t *testing.T) {
	backend1, _ := setupFacade(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := backend1.GenerateRSA(attrs)
	require.NoError(t, err)

	err = DeleteKey("backend1:test-key")
	assert.NoError(t, err)

	// Verify key is deleted
	_, err = backend1.GetKey(attrs)
	assert.Error(t, err)
}

func TestDeleteKey_WithoutBackendPrefix(t *testing.T) {
	backend1, _ := setupFacade(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := backend1.GenerateRSA(attrs)
	require.NoError(t, err)

	err = DeleteKey("test-key")
	assert.NoError(t, err)

	// Verify key is deleted
	_, err = backend1.GetKey(attrs)
	assert.Error(t, err)
}

// Test ListKeys

func TestListKeys_AllBackends(t *testing.T) {
	backend1, backend2 := setupFacade(t)

	// Create keys in both backends
	_, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "key1"})
	require.NoError(t, err)
	_, err = backend2.GenerateRSA(&types.KeyAttributes{CN: "key2"})
	require.NoError(t, err)

	keys, err := ListKeys()
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestListKeys_SpecificBackend(t *testing.T) {
	backend1, backend2 := setupFacade(t)

	// Create keys in both backends
	_, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "key1"})
	require.NoError(t, err)
	_, err = backend2.GenerateRSA(&types.KeyAttributes{CN: "key2"})
	require.NoError(t, err)

	keys, err := ListKeys("backend1")
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "key1", keys[0].CN)
}

func TestListKeys_NonexistentBackend(t *testing.T) {
	setupFacade(t)

	_, err := ListKeys("nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestListKeys_ContinueOnError(t *testing.T) {
	backend1, backend2 := setupFacade(t)

	// Make backend1 return an error
	backend1.listKeysErr = errors.New("backend error")

	// Create a key in backend2
	_, err := backend2.GenerateRSA(&types.KeyAttributes{CN: "key2"})
	require.NoError(t, err)

	// Should still return keys from backend2
	keys, err := ListKeys()
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "key2", keys[0].CN)
}

// Test SaveCertificate and Certificate

func TestSaveCertificate_Success(t *testing.T) {
	backend1, _ := setupFacade(t)

	// Generate a key and create a cert
	key, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = SaveCertificate("test-key", cert)
	assert.NoError(t, err)

	// Verify cert was saved
	retrievedCert, err := backend1.GetCert("test-key")
	assert.NoError(t, err)
	assert.Equal(t, cert, retrievedCert)
}

func TestCertificate_Success(t *testing.T) {
	backend1, _ := setupFacade(t)

	// Generate a key and create a cert
	key, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = backend1.SaveCert("test-key", cert)
	require.NoError(t, err)

	// Retrieve via facade
	retrievedCert, err := Certificate("test-key")
	assert.NoError(t, err)
	assert.Equal(t, cert, retrievedCert)
}

// Test DeleteCertificate

func TestDeleteCertificate_WithBackendPrefix(t *testing.T) {
	backend1, _ := setupFacade(t)

	// Generate a key and create a cert
	key, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = backend1.SaveCert("test-key", cert)
	require.NoError(t, err)

	err = DeleteCertificate("backend1:test-key")
	assert.NoError(t, err)

	// Verify cert is deleted
	_, err = backend1.GetCert("test-key")
	assert.Error(t, err)
}

func TestDeleteCertificate_WithoutBackendPrefix(t *testing.T) {
	backend1, _ := setupFacade(t)

	// Generate a key and create a cert
	key, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = backend1.SaveCert("test-key", cert)
	require.NoError(t, err)

	err = DeleteCertificate("test-key")
	assert.NoError(t, err)

	// Verify cert is deleted
	_, err = backend1.GetCert("test-key")
	assert.Error(t, err)
}

// Test ListCertificates

func TestListCertificates_AllBackends(t *testing.T) {
	backend1, backend2 := setupFacade(t)

	// Create certs in both backends
	key1, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "cert1"})
	require.NoError(t, err)
	cert1 := createTestCert(t, "cert1", key1.(crypto.Signer))
	err = backend1.SaveCert("cert1", cert1)
	require.NoError(t, err)

	key2, err := backend2.GenerateRSA(&types.KeyAttributes{CN: "cert2"})
	require.NoError(t, err)
	cert2 := createTestCert(t, "cert2", key2.(crypto.Signer))
	err = backend2.SaveCert("cert2", cert2)
	require.NoError(t, err)

	certs, err := ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Contains(t, certs, "cert1")
	assert.Contains(t, certs, "cert2")
}

func TestListCertificates_SpecificBackend(t *testing.T) {
	backend1, backend2 := setupFacade(t)

	// Create certs in both backends
	key1, err := backend1.GenerateRSA(&types.KeyAttributes{CN: "cert1"})
	require.NoError(t, err)
	cert1 := createTestCert(t, "cert1", key1.(crypto.Signer))
	err = backend1.SaveCert("cert1", cert1)
	require.NoError(t, err)

	key2, err := backend2.GenerateRSA(&types.KeyAttributes{CN: "cert2"})
	require.NoError(t, err)
	cert2 := createTestCert(t, "cert2", key2.(crypto.Signer))
	err = backend2.SaveCert("cert2", cert2)
	require.NoError(t, err)

	certs, err := ListCertificates("backend1")
	assert.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Contains(t, certs, "cert1")
}

func TestListCertificates_NonexistentBackend(t *testing.T) {
	setupFacade(t)

	_, err := ListCertificates("nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestListCertificates_NotInitialized(t *testing.T) {
	Reset()

	_, err := ListCertificates()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// Test Close

func TestClose_Success(t *testing.T) {
	setupFacade(t)

	err := Close()
	assert.NoError(t, err)

	// Note: Close() doesn't reset the facade, so it's still considered initialized
	// Reset() is used for testing to completely clear the facade
}

func TestClose_PropagatesErrors(t *testing.T) {
	backend1, _ := setupFacade(t)

	// Make backend1 return an error on close
	backend1.closeError = errors.New("close error")

	err := Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to close")
	assert.Contains(t, err.Error(), "backend1")
}

func TestClose_NotInitialized(t *testing.T) {
	Reset()

	err := Close()
	// Close() returns nil when not initialized
	assert.NoError(t, err)
}

// Test Reset

func TestReset_Success(t *testing.T) {
	setupFacade(t)

	assert.True(t, IsInitialized())
	Reset()
	assert.False(t, IsInitialized())
}

// Test IsInitialized

func TestIsInitialized_BeforeInit(t *testing.T) {
	Reset()
	assert.False(t, IsInitialized())
}

func TestIsInitialized_AfterInit(t *testing.T) {
	setupFacade(t)
	assert.True(t, IsInitialized())
}

// Test concurrent access

func TestConcurrentAccess(t *testing.T) {
	setupFacade(t)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			backends := Backends()
			assert.Len(t, backends, 2)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test concurrent access
