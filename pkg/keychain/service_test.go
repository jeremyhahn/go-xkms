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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
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

func (m *mockKeyStore) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if m.backend == nil {
		return nil, errors.New("no backend configured")
	}
	sealer, ok := m.backend.(types.Sealer)
	if !ok {
		return nil, errors.New("backend does not implement Sealer")
	}
	return sealer.Seal(ctx, data, opts)
}

func (m *mockKeyStore) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if m.backend == nil {
		return nil, errors.New("no backend configured")
	}
	sealer, ok := m.backend.(types.Sealer)
	if !ok {
		return nil, errors.New("backend does not implement Sealer")
	}
	return sealer.Unseal(ctx, sealed, opts)
}

func (m *mockKeyStore) CanSeal() bool {
	if m.backend == nil {
		return false
	}
	sealer, ok := m.backend.(types.Sealer)
	if !ok {
		return false
	}
	return sealer.CanSeal()
}

// Test helpers

func setupService(t *testing.T) (*mockKeyStore, *mockKeyStore) {
	t.Helper()
	Reset() // Ensure clean state

	pkcs8 := newMockKeyStore("pkcs8")
	pkcs11 := newMockKeyStore("pkcs11")

	config := &ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs8":  pkcs8,
			"pkcs11": pkcs11,
		},
		DefaultBackend: "pkcs8",
	}

	err := Initialize(config)
	require.NoError(t, err)

	return pkcs8, pkcs11
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

	pkcs8 := newMockKeyStore("pkcs8")
	config := &ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs8": pkcs8,
		},
		DefaultBackend: "pkcs8",
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

	config := &ServiceConfig{
		Backends:       map[string]KeyStore{},
		DefaultBackend: "pkcs8",
	}

	err := Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one backend must be configured")
}

func TestInitialize_InvalidDefaultBackend(t *testing.T) {
	Reset()

	pkcs8 := newMockKeyStore("pkcs8")
	config := &ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs8": pkcs8,
		},
		DefaultBackend: "nonexistent",
	}

	err := Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "default backend nonexistent not found")
}

func TestInitialize_DefaultToFirstBackend(t *testing.T) {
	Reset()

	pkcs8 := newMockKeyStore("pkcs8")
	config := &ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs8": pkcs8,
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

	pkcs8 := newMockKeyStore("pkcs8")
	config1 := &ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs8": pkcs8,
		},
		DefaultBackend: "pkcs8",
	}

	err := Initialize(config1)
	assert.NoError(t, err)

	// Second initialization should succeed (idempotent)
	pkcs11 := newMockKeyStore("pkcs11")
	config2 := &ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs11": pkcs11,
		},
		DefaultBackend: "pkcs11",
	}

	err = Initialize(config2)
	assert.NoError(t, err)

	// Should still have original backends
	backends := Backends()
	assert.Contains(t, backends, "pkcs8")
	assert.NotContains(t, backends, "pkcs11")
}

// Test Backend

func TestBackend_Success(t *testing.T) {
	pkcs8, _ := setupService(t)

	ks, err := Backend("pkcs8")
	assert.NoError(t, err)
	assert.Equal(t, pkcs8, ks)
}

func TestBackend_NotFound(t *testing.T) {
	setupService(t)

	_, err := Backend("nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestBackend_NotInitialized(t *testing.T) {
	Reset()

	_, err := Backend("pkcs8")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// Test DefaultBackend

func TestDefaultBackend_Success(t *testing.T) {
	pkcs8, _ := setupService(t)

	ks, err := DefaultBackend()
	assert.NoError(t, err)
	assert.Equal(t, pkcs8, ks)
}

func TestDefaultBackend_NotInitialized(t *testing.T) {
	Reset()

	_, err := DefaultBackend()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// Test Backends

func TestBackends_Success(t *testing.T) {
	setupService(t)

	backends := Backends()
	assert.Len(t, backends, 2)
	assert.Contains(t, backends, "pkcs8")
	assert.Contains(t, backends, "pkcs11")
}

func TestBackends_NotInitialized(t *testing.T) {
	Reset()

	backends := Backends()
	assert.Empty(t, backends)
}

// Test KeyByID

func TestKeyByID_WithBackendPrefix(t *testing.T) {
	pkcs8, _ := setupService(t)

	// Generate a key in pkcs8
	attrs := &types.KeyAttributes{CN: "test-key"}
	expectedKey, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Retrieve using 4-part format: backend:::keyname
	key, err := KeyByID("pkcs8:::test-key")
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, key)
}

func TestKeyByID_WithoutBackendPrefix(t *testing.T) {
	pkcs8, _ := setupService(t)

	// Generate a key in default backend
	attrs := &types.KeyAttributes{CN: "test-key"}
	expectedKey, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Retrieve using shorthand (just keyname, uses default backend)
	key, err := KeyByID("test-key")
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, key)
}

func TestKeyByID_InvalidBackend(t *testing.T) {
	setupService(t)

	// Use 4-part format with invalid backend
	_, err := KeyByID("nonexistent:::test-key")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidBackendType)
}

func TestKeyByID_KeyNotFound(t *testing.T) {
	setupService(t)

	// Use 4-part format
	_, err := KeyByID("pkcs8:::nonexistent-key")
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
	pkcs8, _ := setupService(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, err := SignerByID("pkcs8:::test-key")
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

// Test Decrypter

func TestDecrypter_Success(t *testing.T) {
	pkcs8, _ := setupService(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	decrypter, err := DecrypterByID("pkcs8:::test-key")
	assert.NoError(t, err)
	assert.NotNil(t, decrypter)
}

// Test DeleteKey

func TestDeleteKey_WithBackendPrefix(t *testing.T) {
	pkcs8, _ := setupService(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	err = DeleteKeyByID("pkcs8:::test-key")
	assert.NoError(t, err)

	// Verify key is deleted
	_, err = pkcs8.GetKey(attrs)
	assert.Error(t, err)
}

func TestDeleteKey_WithoutBackendPrefix(t *testing.T) {
	pkcs8, _ := setupService(t)

	attrs := &types.KeyAttributes{CN: "test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	err = DeleteKeyByID("test-key")
	assert.NoError(t, err)

	// Verify key is deleted
	_, err = pkcs8.GetKey(attrs)
	assert.Error(t, err)
}

// Test ListKeys

func TestListKeys_AllBackends(t *testing.T) {
	pkcs8, pkcs11 := setupService(t)

	// Create keys in both backends
	_, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "key1"})
	require.NoError(t, err)
	_, err = pkcs11.GenerateRSA(&types.KeyAttributes{CN: "key2"})
	require.NoError(t, err)

	keys, err := ListKeys()
	assert.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestListKeys_SpecificBackend(t *testing.T) {
	pkcs8, pkcs11 := setupService(t)

	// Create keys in both backends
	_, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "key1"})
	require.NoError(t, err)
	_, err = pkcs11.GenerateRSA(&types.KeyAttributes{CN: "key2"})
	require.NoError(t, err)

	keys, err := ListKeys("pkcs8")
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "key1", keys[0].CN)
}

func TestListKeys_NonexistentBackend(t *testing.T) {
	setupService(t)

	_, err := ListKeys("nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestListKeys_ContinueOnError(t *testing.T) {
	pkcs8, pkcs11 := setupService(t)

	// Make pkcs8 return an error
	pkcs8.listKeysErr = errors.New("backend error")

	// Create a key in pkcs11
	_, err := pkcs11.GenerateRSA(&types.KeyAttributes{CN: "key2"})
	require.NoError(t, err)

	// Should still return keys from pkcs11
	keys, err := ListKeys()
	assert.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, "key2", keys[0].CN)
}

// Test SaveCertificate and Certificate

func TestSaveCertificate_Success(t *testing.T) {
	pkcs8, _ := setupService(t)

	// Generate a key and create a cert
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = SaveCertificateByID("test-key", cert)
	assert.NoError(t, err)

	// Verify cert was saved
	retrievedCert, err := pkcs8.GetCert("test-key")
	assert.NoError(t, err)
	assert.Equal(t, cert, retrievedCert)
}

func TestCertificate_Success(t *testing.T) {
	pkcs8, _ := setupService(t)

	// Generate a key and create a cert
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = pkcs8.SaveCert("test-key", cert)
	require.NoError(t, err)

	// Retrieve via service
	retrievedCert, err := CertificateByID("test-key")
	assert.NoError(t, err)
	assert.Equal(t, cert, retrievedCert)
}

// Test DeleteCertificate

func TestDeleteCertificate_WithBackendPrefix(t *testing.T) {
	pkcs8, _ := setupService(t)

	// Generate a key and create a cert
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = pkcs8.SaveCert("test-key", cert)
	require.NoError(t, err)

	err = DeleteCertificateByID("pkcs8:::test-key")
	assert.NoError(t, err)

	// Verify cert is deleted
	_, err = pkcs8.GetCert("test-key")
	assert.Error(t, err)
}

func TestDeleteCertificate_WithoutBackendPrefix(t *testing.T) {
	pkcs8, _ := setupService(t)

	// Generate a key and create a cert
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "test-key"})
	require.NoError(t, err)
	cert := createTestCert(t, "test-key", key.(crypto.Signer))

	err = pkcs8.SaveCert("test-key", cert)
	require.NoError(t, err)

	err = DeleteCertificateByID("test-key")
	assert.NoError(t, err)

	// Verify cert is deleted
	_, err = pkcs8.GetCert("test-key")
	assert.Error(t, err)
}

// Test ListCertificates

func TestListCertificates_AllBackends(t *testing.T) {
	pkcs8, pkcs11 := setupService(t)

	// Create certs in both backends
	key1, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "cert1"})
	require.NoError(t, err)
	cert1 := createTestCert(t, "cert1", key1.(crypto.Signer))
	err = pkcs8.SaveCert("cert1", cert1)
	require.NoError(t, err)

	key2, err := pkcs11.GenerateRSA(&types.KeyAttributes{CN: "cert2"})
	require.NoError(t, err)
	cert2 := createTestCert(t, "cert2", key2.(crypto.Signer))
	err = pkcs11.SaveCert("cert2", cert2)
	require.NoError(t, err)

	certs, err := ListCertificates()
	assert.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Contains(t, certs, "cert1")
	assert.Contains(t, certs, "cert2")
}

func TestListCertificates_SpecificBackend(t *testing.T) {
	pkcs8, pkcs11 := setupService(t)

	// Create certs in both backends
	key1, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "cert1"})
	require.NoError(t, err)
	cert1 := createTestCert(t, "cert1", key1.(crypto.Signer))
	err = pkcs8.SaveCert("cert1", cert1)
	require.NoError(t, err)

	key2, err := pkcs11.GenerateRSA(&types.KeyAttributes{CN: "cert2"})
	require.NoError(t, err)
	cert2 := createTestCert(t, "cert2", key2.(crypto.Signer))
	err = pkcs11.SaveCert("cert2", cert2)
	require.NoError(t, err)

	certs, err := ListCertificates("pkcs8")
	assert.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Contains(t, certs, "cert1")
}

func TestListCertificates_NonexistentBackend(t *testing.T) {
	setupService(t)

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
	setupService(t)

	err := Close()
	assert.NoError(t, err)

	// Note: Close() doesn't reset the service, so it's still considered initialized
	// Reset() is used for testing to completely clear the service
}

func TestClose_PropagatesErrors(t *testing.T) {
	pkcs8, _ := setupService(t)

	// Make pkcs8 return an error on close
	pkcs8.closeError = errors.New("close error")

	err := Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to close")
	assert.Contains(t, err.Error(), "pkcs8")
}

func TestClose_NotInitialized(t *testing.T) {
	Reset()

	err := Close()
	// Close() returns nil when not initialized
	assert.NoError(t, err)
}

// Test Reset

func TestReset_Success(t *testing.T) {
	setupService(t)

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
	setupService(t)
	assert.True(t, IsInitialized())
}

// Test concurrent access

func TestConcurrentAccess(t *testing.T) {
	setupService(t)

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

// mockSealerBackend is a mock backend that implements both Backend and Sealer interfaces
type mockSealerBackend struct {
	backendType types.BackendType
	canSeal     bool
	sealedData  map[string][]byte // Stores sealed data by key
}

func newMockSealerBackend(backendType types.BackendType) *mockSealerBackend {
	return &mockSealerBackend{
		backendType: backendType,
		canSeal:     true,
		sealedData:  make(map[string][]byte),
	}
}

// Backend interface implementation
func (m *mockSealerBackend) Type() types.BackendType { return m.backendType }
func (m *mockSealerBackend) Capabilities() types.Capabilities {
	return types.Capabilities{}
}
func (m *mockSealerBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackend) DeleteKey(attrs *types.KeyAttributes) error { return nil }
func (m *mockSealerBackend) ListKeys() ([]*types.KeyAttributes, error)  { return nil, nil }
func (m *mockSealerBackend) RotateKey(attrs *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *mockSealerBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not implemented")
}
func (m *mockSealerBackend) Close() error { return nil }

// Sealer interface implementation
func (m *mockSealerBackend) CanSeal() bool { return m.canSeal }

func (m *mockSealerBackend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if !m.canSeal {
		return nil, errors.New("sealing disabled")
	}

	keyID := "default"
	if opts != nil && opts.KeyAttributes != nil {
		keyID = opts.KeyAttributes.ID()
	}

	// Store the data
	m.sealedData[keyID] = data

	return &types.SealedData{
		Backend:    m.backendType,
		Ciphertext: []byte("mock-encrypted-" + string(data)),
		KeyID:      keyID,
		Metadata:   make(map[string][]byte),
	}, nil
}

func (m *mockSealerBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if !m.canSeal {
		return nil, errors.New("unsealing disabled")
	}

	if sealed.Backend != m.backendType {
		return nil, errors.New("backend mismatch")
	}

	keyID := "default"
	if opts != nil && opts.KeyAttributes != nil {
		keyID = opts.KeyAttributes.ID()
	}

	data, ok := m.sealedData[keyID]
	if !ok {
		return nil, errors.New("sealed data not found")
	}

	return data, nil
}

// Helper to create a mockKeyStore with a sealer backend
func newMockKeyStoreWithSealer(name string, backendType types.BackendType) *mockKeyStore {
	ms := newMockKeyStore(name)
	ms.backend = newMockSealerBackend(backendType)
	return ms
}

// setupSealerService creates a service with sealer-enabled backends
func setupSealerService(t *testing.T) (*mockKeyStore, *mockKeyStore) {
	t.Helper()
	Reset()

	pkcs8 := newMockKeyStoreWithSealer("pkcs8", types.BackendTypePKCS8)
	pkcs11 := newMockKeyStoreWithSealer("pkcs11", types.BackendTypePKCS11)

	err := Initialize(&ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs8":  pkcs8,
			"pkcs11": pkcs11,
		},
		DefaultBackend: "pkcs8",
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		Reset()
	})

	return pkcs8, pkcs11
}

// Test Seal

func TestSeal_Success(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	data := []byte("secret data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}

	sealed, err := Seal(ctx, data, opts)
	assert.NoError(t, err)
	assert.NotNil(t, sealed)
	assert.Equal(t, types.BackendTypePKCS8, sealed.Backend)
}

func TestSeal_NotInitialized(t *testing.T) {
	Reset()

	ctx := context.Background()
	_, err := Seal(ctx, []byte("data"), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// Test SealWithBackend

func TestSealWithBackend_Success(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	data := []byte("secret data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}

	sealed, err := SealWithBackend(ctx, "pkcs11", data, opts)
	assert.NoError(t, err)
	assert.NotNil(t, sealed)
	assert.Equal(t, types.BackendTypePKCS11, sealed.Backend)
}

func TestSealWithBackend_InvalidBackend(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	_, err := SealWithBackend(ctx, "nonexistent", []byte("data"), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

// Test Unseal

func TestUnseal_Success(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	originalData := []byte("secret data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}

	// First seal
	sealed, err := Seal(ctx, originalData, opts)
	require.NoError(t, err)

	// Then unseal
	unsealOpts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}
	plaintext, err := Unseal(ctx, sealed, unsealOpts)
	assert.NoError(t, err)
	assert.Equal(t, originalData, plaintext)
}

func TestUnseal_NilSealedData(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	_, err := Unseal(ctx, nil, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSealedData)
}

func TestUnseal_BackendNotFound(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    types.BackendTypeTPM2, // Not registered in our service
		Ciphertext: []byte("encrypted"),
	}

	_, err := Unseal(ctx, sealed, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

// Test UnsealWithBackend

func TestUnsealWithBackend_Success(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	originalData := []byte("secret data")
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}

	// Seal with pkcs11
	sealed, err := SealWithBackend(ctx, "pkcs11", originalData, opts)
	require.NoError(t, err)

	// Unseal with pkcs11
	unsealOpts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "test-key"},
	}
	plaintext, err := UnsealWithBackend(ctx, "pkcs11", sealed, unsealOpts)
	assert.NoError(t, err)
	assert.Equal(t, originalData, plaintext)
}

func TestUnsealWithBackend_InvalidBackend(t *testing.T) {
	setupSealerService(t)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS8,
		Ciphertext: []byte("encrypted"),
	}

	_, err := UnsealWithBackend(ctx, "nonexistent", sealed, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

// Test CanSeal

func TestCanSeal_WithSealerBackend(t *testing.T) {
	setupSealerService(t)

	// Default backend should support sealing
	assert.True(t, CanSeal())
}

func TestCanSeal_WithSpecificBackend(t *testing.T) {
	setupSealerService(t)

	assert.True(t, CanSeal("pkcs8"))
	assert.True(t, CanSeal("pkcs11"))
}

func TestCanSeal_InvalidBackend(t *testing.T) {
	setupSealerService(t)

	assert.False(t, CanSeal("nonexistent"))
}

func TestCanSeal_NotInitialized(t *testing.T) {
	Reset()

	assert.False(t, CanSeal())
}

// ========================================================================
// Extended Mock Implementation
// ========================================================================

// mockExtendedBackend implements Backend, SymmetricBackend, and ImportExportBackend
type mockExtendedBackend struct {
	backendType  types.BackendType
	capabilities types.Capabilities
	keys         map[string]crypto.PrivateKey
	symKeys      map[string]*mockSymmetricKey
}

func newMockExtendedBackend(backendType types.BackendType) *mockExtendedBackend {
	return &mockExtendedBackend{
		backendType: backendType,
		capabilities: types.Capabilities{
			Keys:                true,
			HardwareBacked:      backendType == types.BackendTypePKCS11 || backendType == types.BackendTypeTPM2,
			Signing:             true,
			Decryption:          true,
			SymmetricEncryption: true,
		},
		keys:    make(map[string]crypto.PrivateKey),
		symKeys: make(map[string]*mockSymmetricKey),
	}
}

// Backend interface
func (m *mockExtendedBackend) Type() types.BackendType          { return m.backendType }
func (m *mockExtendedBackend) Capabilities() types.Capabilities { return m.capabilities }
func (m *mockExtendedBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("use GenerateRSA or GenerateECDSA")
}
func (m *mockExtendedBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	return key, nil
}
func (m *mockExtendedBackend) DeleteKey(attrs *types.KeyAttributes) error {
	delete(m.keys, attrs.CN)
	return nil
}
func (m *mockExtendedBackend) ListKeys() ([]*types.KeyAttributes, error) {
	attrs := make([]*types.KeyAttributes, 0, len(m.keys)+len(m.symKeys))
	for cn := range m.keys {
		attrs = append(attrs, &types.KeyAttributes{CN: cn})
	}
	// Also include symmetric keys
	for cn := range m.symKeys {
		attrs = append(attrs, &types.KeyAttributes{CN: cn})
	}
	return attrs, nil
}
func (m *mockExtendedBackend) RotateKey(attrs *types.KeyAttributes) error {
	return errors.New("not implemented")
}
func (m *mockExtendedBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	if signer, ok := key.(crypto.Signer); ok {
		return signer, nil
	}
	return nil, errors.New("key does not implement crypto.Signer")
}
func (m *mockExtendedBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	if decrypter, ok := key.(crypto.Decrypter); ok {
		return decrypter, nil
	}
	return nil, errors.New("key does not implement crypto.Decrypter")
}
func (m *mockExtendedBackend) Close() error { return nil }

// Key generation helpers
func (m *mockExtendedBackend) generateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockExtendedBackend) generateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

// SymmetricBackend interface
func (m *mockExtendedBackend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	key := &mockSymmetricKey{
		id:        attrs.CN,
		algorithm: attrs.KeyAlgorithm,
		keyData:   make([]byte, 32), // AES-256
	}
	_, err := rand.Read(key.keyData)
	if err != nil {
		return nil, err
	}
	m.symKeys[attrs.CN] = key
	return key, nil
}

func (m *mockExtendedBackend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	key, ok := m.symKeys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	return key, nil
}

func (m *mockExtendedBackend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	key, ok := m.symKeys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	return &mockSymmetricEncrypter{key: key}, nil
}

// ImportExportBackend interface
func (m *mockExtendedBackend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	// Generate a wrapping key for import
	wrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		ImportToken:       []byte("mock-import-token"),
		Algorithm:         algorithm,
	}, nil
}

func (m *mockExtendedBackend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	// Simple mock wrapping - just return the key material with a prefix
	return &backend.WrappedKeyMaterial{
		WrappedKey:  append([]byte("wrapped:"), keyMaterial...),
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
	}, nil
}

func (m *mockExtendedBackend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	// Simple mock unwrapping - just remove the prefix
	if len(wrapped.WrappedKey) > 8 {
		return wrapped.WrappedKey[8:], nil
	}
	return nil, errors.New("invalid wrapped key")
}

func (m *mockExtendedBackend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	// Mock import - mark key as imported
	m.keys[attrs.CN] = &mockImportedKey{id: attrs.CN}
	return nil
}

func (m *mockExtendedBackend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	_, ok := m.keys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	return &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped:" + attrs.CN),
		Algorithm:  algorithm,
	}, nil
}

// mockImportedKey is a placeholder for imported keys
type mockImportedKey struct {
	id string
}

func (m *mockImportedKey) Public() crypto.PublicKey { return nil }

// mockSymmetricKey implements types.SymmetricKey
type mockSymmetricKey struct {
	id        string
	algorithm x509.PublicKeyAlgorithm
	keyData   []byte
}

func (m *mockSymmetricKey) Algorithm() string    { return "AES-256-GCM" }
func (m *mockSymmetricKey) KeySize() int         { return len(m.keyData) * 8 }
func (m *mockSymmetricKey) Raw() ([]byte, error) { return m.keyData, nil }

// mockSymmetricEncrypter implements types.SymmetricEncrypter
type mockSymmetricEncrypter struct {
	key *mockSymmetricKey
}

func (m *mockSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	// Mock encryption - just XOR with first byte of key (for testing only!)
	ciphertext := make([]byte, len(plaintext))
	for i, b := range plaintext {
		ciphertext[i] = b ^ m.key.keyData[i%len(m.key.keyData)]
	}
	return &types.EncryptedData{
		Ciphertext: ciphertext,
		Nonce:      []byte("mock-nonce"),
		Algorithm:  "AES-256-GCM",
	}, nil
}

func (m *mockSymmetricEncrypter) Decrypt(encrypted *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	// Mock decryption - just XOR with first byte of key (reverse of encrypt)
	plaintext := make([]byte, len(encrypted.Ciphertext))
	for i, b := range encrypted.Ciphertext {
		plaintext[i] = b ^ m.key.keyData[i%len(m.key.keyData)]
	}
	return plaintext, nil
}

// mockExtendedKeyStore wraps mockExtendedBackend to implement KeyStore
type mockExtendedKeyStore struct {
	name           string
	backendImpl    *mockExtendedBackend
	certs          map[string]*x509.Certificate
	certChains     map[string][]*x509.Certificate
	tlsCerts       map[string]tls.Certificate
	rotateKeyError error
}

func newMockExtendedKeyStore(name string, backendType types.BackendType) *mockExtendedKeyStore {
	return &mockExtendedKeyStore{
		name:        name,
		backendImpl: newMockExtendedBackend(backendType),
		certs:       make(map[string]*x509.Certificate),
		certChains:  make(map[string][]*x509.Certificate),
		tlsCerts:    make(map[string]tls.Certificate),
	}
}

// KeyStore interface implementation
func (m *mockExtendedKeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return m.backendImpl.generateRSA(attrs)
}

func (m *mockExtendedKeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return m.backendImpl.generateECDSA(attrs)
}

func (m *mockExtendedKeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("not implemented")
}

func (m *mockExtendedKeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return m.backendImpl.GetKey(attrs)
}

func (m *mockExtendedKeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	return m.backendImpl.DeleteKey(attrs)
}

func (m *mockExtendedKeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	return m.backendImpl.ListKeys()
}

func (m *mockExtendedKeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if m.rotateKeyError != nil {
		return nil, m.rotateKeyError
	}
	// Check if key exists first
	if _, ok := m.backendImpl.keys[attrs.CN]; !ok {
		return nil, backend.ErrKeyNotFound
	}
	// Delete old key and generate new one
	delete(m.backendImpl.keys, attrs.CN)
	return m.backendImpl.generateRSA(attrs)
}

func (m *mockExtendedKeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return m.backendImpl.Signer(attrs)
}

func (m *mockExtendedKeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return m.backendImpl.Decrypter(attrs)
}

func (m *mockExtendedKeyStore) SaveCert(keyID string, cert *x509.Certificate) error {
	m.certs[keyID] = cert
	return nil
}

func (m *mockExtendedKeyStore) GetCert(keyID string) (*x509.Certificate, error) {
	cert, ok := m.certs[keyID]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cert, nil
}

func (m *mockExtendedKeyStore) DeleteCert(keyID string) error {
	delete(m.certs, keyID)
	return nil
}

func (m *mockExtendedKeyStore) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	m.certChains[keyID] = chain
	return nil
}

func (m *mockExtendedKeyStore) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	chain, ok := m.certChains[keyID]
	if !ok {
		return nil, errors.New("certificate chain not found")
	}
	return chain, nil
}

func (m *mockExtendedKeyStore) ListCerts() ([]string, error) {
	ids := make([]string, 0, len(m.certs))
	for id := range m.certs {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *mockExtendedKeyStore) CertExists(keyID string) (bool, error) {
	_, ok := m.certs[keyID]
	return ok, nil
}

func (m *mockExtendedKeyStore) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	tlsCert, ok := m.tlsCerts[keyID]
	if !ok {
		return tls.Certificate{}, errors.New("TLS certificate not found")
	}
	return tlsCert, nil
}

func (m *mockExtendedKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	return m.GetKey(&types.KeyAttributes{CN: keyID})
}

func (m *mockExtendedKeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	return m.Signer(&types.KeyAttributes{CN: keyID})
}

func (m *mockExtendedKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	return m.Decrypter(&types.KeyAttributes{CN: keyID})
}

func (m *mockExtendedKeyStore) Backend() types.Backend {
	return m.backendImpl
}

func (m *mockExtendedKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}

func (m *mockExtendedKeyStore) Close() error {
	return nil
}

func (m *mockExtendedKeyStore) CanSeal() bool {
	return false
}

func (m *mockExtendedKeyStore) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	return nil, errors.New("sealing not supported")
}

func (m *mockExtendedKeyStore) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	return nil, errors.New("unsealing not supported")
}

// setupExtendedService creates a service with extended mock backends
func setupExtendedService(t *testing.T) (*mockExtendedKeyStore, *mockExtendedKeyStore) {
	t.Helper()
	Reset()

	pkcs8 := newMockExtendedKeyStore("pkcs8", types.BackendTypePKCS8)
	pkcs11 := newMockExtendedKeyStore("pkcs11", types.BackendTypePKCS11)

	err := Initialize(&ServiceConfig{
		Backends: map[string]KeyStore{
			"pkcs8":  pkcs8,
			"pkcs11": pkcs11,
		},
		DefaultBackend: "pkcs8",
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		Reset()
	})

	return pkcs8, pkcs11
}

// ========================================================================
// Test GetBackendInfo
// ========================================================================

func TestGetBackendInfo_Success(t *testing.T) {
	setupExtendedService(t)

	info, err := GetBackendInfo("pkcs8")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "pkcs8", info.ID)
	assert.Equal(t, types.BackendTypePKCS8, info.Type)
	assert.False(t, info.HardwareBacked)
}

func TestGetBackendInfo_HardwareBacked(t *testing.T) {
	setupExtendedService(t)

	info, err := GetBackendInfo("pkcs11")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, types.BackendTypePKCS11, info.Type)
	assert.True(t, info.HardwareBacked)
}

func TestGetBackendInfo_InvalidBackend(t *testing.T) {
	setupExtendedService(t)

	_, err := GetBackendInfo("nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestGetBackendInfo_NotInitialized(t *testing.T) {
	Reset()

	_, err := GetBackendInfo("pkcs8")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// ========================================================================
// Test GetBackendCapabilities
// ========================================================================

func TestGetBackendCapabilities_Success(t *testing.T) {
	setupExtendedService(t)

	caps, err := GetBackendCapabilities("pkcs8")
	assert.NoError(t, err)
	assert.True(t, caps.Signing)
	assert.True(t, caps.SymmetricEncryption)
}

func TestGetBackendCapabilities_InvalidBackend(t *testing.T) {
	setupExtendedService(t)

	_, err := GetBackendCapabilities("nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

// ========================================================================
// Test GenerateKeyWithBackend
// ========================================================================

func TestGenerateKeyWithBackend_RSA(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-rsa-key",
		KeyAlgorithm: x509.RSA,
	}

	key, err := GenerateKeyWithBackend("pkcs8", attrs)
	assert.NoError(t, err)
	assert.NotNil(t, key)

	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok, "expected RSA key")
}

func TestGenerateKeyWithBackend_ECDSA(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-key",
		KeyAlgorithm: x509.ECDSA,
	}

	key, err := GenerateKeyWithBackend("pkcs11", attrs)
	assert.NoError(t, err)
	assert.NotNil(t, key)

	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected ECDSA key")
}

func TestGenerateKeyWithBackend_InvalidBackend(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}

	_, err := GenerateKeyWithBackend("nonexistent", attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestGenerateKeyWithBackend_UnsupportedAlgorithm(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.DSA, // Unsupported
	}

	_, err := GenerateKeyWithBackend("pkcs8", attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key algorithm")
}

// ========================================================================
// Test RotateKey
// ========================================================================

func TestRotateKey_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate initial key
	attrs := &types.KeyAttributes{CN: "rotate-test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Rotate the key
	newKey, err := RotateKey("pkcs8:::rotate-test-key")
	assert.NoError(t, err)
	assert.NotNil(t, newKey)
}

func TestRotateKey_WithoutBackendPrefix(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate initial key
	attrs := &types.KeyAttributes{CN: "rotate-test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Rotate the key (uses default backend)
	newKey, err := RotateKey("rotate-test-key")
	assert.NoError(t, err)
	assert.NotNil(t, newKey)
}

func TestRotateKey_KeyNotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := RotateKey("nonexistent-key")
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ========================================================================
// Test Sign and Verify
// ========================================================================

func TestSign_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a key
	attrs := &types.KeyAttributes{CN: "sign-test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Sign some data
	data := []byte("test data to sign")
	signature, err := Sign("pkcs8:::sign-test-key", data, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSign_WithOptions(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a key
	attrs := &types.KeyAttributes{CN: "sign-test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Sign with SHA-512
	data := []byte("test data to sign")
	opts := &SignOptions{Hash: crypto.SHA512}
	signature, err := Sign("pkcs8:::sign-test-key", data, opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSign_KeyNotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := Sign("nonexistent-key", []byte("data"), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

func TestVerify_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate an ECDSA key for easier verification
	attrs := &types.KeyAttributes{CN: "verify-test-key"}
	key, err := pkcs8.GenerateECDSA(attrs)
	require.NoError(t, err)

	ecdsaKey := key.(*ecdsa.PrivateKey)

	// Create signature manually
	data := []byte("test data to verify")
	hasher := sha256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest)
	require.NoError(t, err)

	// Verify via service
	err = Verify("pkcs8:::verify-test-key", data, signature, &types.VerifyOpts{Hash: crypto.SHA256})
	assert.NoError(t, err)
}

func TestVerify_KeyNotFound(t *testing.T) {
	setupExtendedService(t)

	err := Verify("nonexistent-key", []byte("data"), []byte("sig"), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ========================================================================
// Test Encrypt and Decrypt
// ========================================================================

func TestEncrypt_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a symmetric key
	attrs := &types.KeyAttributes{CN: "encrypt-test-key"}
	_, err := pkcs8.backendImpl.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Encrypt some data
	plaintext := []byte("secret data")
	encrypted, err := Encrypt("pkcs8:::encrypt-test-key", plaintext, nil)
	assert.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted.Ciphertext)
}

func TestDecrypt_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a symmetric key
	attrs := &types.KeyAttributes{CN: "decrypt-test-key"}
	_, err := pkcs8.backendImpl.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Encrypt then decrypt
	originalData := []byte("secret data")
	encrypted, err := Encrypt("pkcs8:::decrypt-test-key", originalData, nil)
	require.NoError(t, err)

	decrypted, err := Decrypt("pkcs8:::decrypt-test-key", encrypted, nil)
	assert.NoError(t, err)
	assert.Equal(t, originalData, decrypted)
}

func TestEncrypt_KeyNotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := Encrypt("nonexistent-key", []byte("data"), nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ========================================================================
// Test Certificate Chain Operations
// ========================================================================

func TestSaveCertificateChain_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a key and certificate
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "cert-chain-key"})
	require.NoError(t, err)

	cert := createTestCert(t, "cert-chain-key", key.(crypto.Signer))
	chain := []*x509.Certificate{cert}

	// Save the chain
	err = SaveCertificateChainByID("pkcs8:::cert-chain-key", chain)
	assert.NoError(t, err)

	// Verify it was saved
	savedChain, ok := pkcs8.certChains["cert-chain-key"]
	assert.True(t, ok)
	assert.Len(t, savedChain, 1)
}

func TestCertificateChain_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a key and certificate
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "cert-chain-key"})
	require.NoError(t, err)

	cert := createTestCert(t, "cert-chain-key", key.(crypto.Signer))
	pkcs8.certChains["cert-chain-key"] = []*x509.Certificate{cert}

	// Retrieve the chain
	chain, err := CertificateChainByID("pkcs8:::cert-chain-key")
	assert.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Equal(t, cert, chain[0])
}

func TestCertificateChain_NotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := CertificateChainByID("nonexistent-key")
	assert.Error(t, err)
}

// ========================================================================
// Test CertificateExists
// ========================================================================

func TestCertificateExists_True(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a key and certificate
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "exists-test-key"})
	require.NoError(t, err)

	cert := createTestCert(t, "exists-test-key", key.(crypto.Signer))
	pkcs8.certs["exists-test-key"] = cert

	exists, err := CertificateExistsByID("pkcs8:::exists-test-key")
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestCertificateExists_False(t *testing.T) {
	setupExtendedService(t)

	exists, err := CertificateExistsByID("nonexistent-key")
	assert.NoError(t, err)
	assert.False(t, exists)
}

// ========================================================================
// Test TLSCertificateByID
// ========================================================================

func TestTLSCertificateByID_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Setup TLS certificate in mock
	key, err := pkcs8.GenerateRSA(&types.KeyAttributes{CN: "tls-test-key"})
	require.NoError(t, err)

	cert := createTestCert(t, "tls-test-key", key.(crypto.Signer))
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
	pkcs8.tlsCerts["tls-test-key"] = tlsCert

	// Retrieve via service
	result, err := TLSCertificateByID("pkcs8:::tls-test-key")
	assert.NoError(t, err)
	assert.NotNil(t, result.PrivateKey)
	assert.Equal(t, cert, result.Leaf)
}

func TestTLSCertificateByID_NotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := TLSCertificateByID("nonexistent-key")
	assert.Error(t, err)
}

// ========================================================================
// Test Import/Export Operations
// ========================================================================

func TestGetImportParameters_Success(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{CN: "import-test-key"}
	params, err := GetImportParameters("pkcs8", attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.NoError(t, err)
	assert.NotNil(t, params)
	assert.NotNil(t, params.WrappingPublicKey)
	assert.NotNil(t, params.ImportToken)
}

func TestGetImportParameters_InvalidBackend(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{CN: "import-test-key"}
	_, err := GetImportParameters("nonexistent", attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestWrapKey_Success(t *testing.T) {
	setupExtendedService(t)

	params := &backend.ImportParameters{
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("test-token"),
	}

	wrapped, err := WrapKey("pkcs8", []byte("key-material"), params)
	assert.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEmpty(t, wrapped.WrappedKey)
}

func TestUnwrapKey_Success(t *testing.T) {
	setupExtendedService(t)

	params := &backend.ImportParameters{
		Algorithm:   backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken: []byte("test-token"),
	}

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped:secret-key"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	unwrapped, err := UnwrapKey("pkcs8", wrapped, params)
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret-key"), unwrapped)
}

func TestImportKey_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	attrs := &types.KeyAttributes{CN: "imported-key"}
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped:key-data"),
		Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	err := ImportKey("pkcs8", attrs, wrapped)
	assert.NoError(t, err)

	// Verify key was imported
	_, ok := pkcs8.backendImpl.keys["imported-key"]
	assert.True(t, ok)
}

func TestExportKey_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a key to export
	attrs := &types.KeyAttributes{CN: "export-test-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Export the key
	wrapped, err := ExportKey("pkcs8:::export-test-key", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.NoError(t, err)
	assert.NotNil(t, wrapped)
	assert.NotEmpty(t, wrapped.WrappedKey)
}

func TestExportKey_KeyNotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := ExportKey("nonexistent-key", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ========================================================================
// Test CopyKey
// ========================================================================

func TestCopyKey_Success(t *testing.T) {
	pkcs8, pkcs11 := setupExtendedService(t)

	// Generate source key
	attrs := &types.KeyAttributes{CN: "copy-source-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	// Copy to pkcs11
	err = CopyKey("pkcs8:::copy-source-key", "pkcs11", nil)
	assert.NoError(t, err)

	// Verify key exists in pkcs11
	_, ok := pkcs11.backendImpl.keys["copy-source-key"]
	assert.True(t, ok)
}

func TestCopyKey_SourceNotFound(t *testing.T) {
	setupExtendedService(t)

	err := CopyKey("nonexistent-key", "pkcs11", nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

func TestCopyKey_InvalidDestBackend(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate source key
	attrs := &types.KeyAttributes{CN: "copy-source-key"}
	_, err := pkcs8.GenerateRSA(attrs)
	require.NoError(t, err)

	err = CopyKey("pkcs8:::copy-source-key", "nonexistent", nil)
	assert.Error(t, err)
}

// ========================================================================
// Test Symmetric Key Operations
// ========================================================================

func TestGenerateSymmetricKey_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	attrs := &types.KeyAttributes{CN: "sym-key-test"}
	symKey, err := GenerateSymmetricKey("pkcs8", attrs)
	assert.NoError(t, err)
	assert.NotNil(t, symKey)
	assert.Equal(t, "AES-256-GCM", symKey.Algorithm())
	assert.Equal(t, 256, symKey.KeySize())

	// Verify key was stored
	_, ok := pkcs8.backendImpl.symKeys["sym-key-test"]
	assert.True(t, ok)
}

func TestGenerateSymmetricKey_InvalidBackend(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{CN: "sym-key-test"}
	_, err := GenerateSymmetricKey("nonexistent", attrs)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestGetSymmetricKey_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate a key first
	attrs := &types.KeyAttributes{CN: "get-sym-key-test"}
	_, err := pkcs8.backendImpl.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	// Get it via service
	symKey, err := GetSymmetricKey("pkcs8:::get-sym-key-test")
	assert.NoError(t, err)
	assert.NotNil(t, symKey)
	assert.Equal(t, "AES-256-GCM", symKey.Algorithm())
}

func TestGetSymmetricKey_NotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := GetSymmetricKey("nonexistent-key")
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// ========================================================================
// Test Input Validation
// ========================================================================

func TestInputValidation_InvalidBackendName(t *testing.T) {
	setupExtendedService(t)

	// Test various functions with invalid backend names
	_, err := GetBackendInfo("../../../etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend name")

	_, err = GetBackendCapabilities("<script>alert('xss')</script>")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend name")
}

func TestInputValidation_InvalidKeyReference(t *testing.T) {
	setupExtendedService(t)

	// Test various functions with invalid key references
	_, err := RotateKey("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")

	_, err = Sign("", []byte("data"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")

	// Test SignerByID with invalid key ID
	_, err = SignerByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")

	// Test DecrypterByID with invalid key ID
	_, err = DecrypterByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")

	// Test SaveCertificateByID with invalid key reference
	err = SaveCertificateByID("", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")

	// Test CertificateByID with invalid key reference
	_, err = CertificateByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")

	// Test DeleteCertificateByID with invalid key reference
	err = DeleteCertificateByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")

	// Test KeyByID with invalid key reference
	_, err = KeyByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")

	// Test SaveCertificateChainByID with invalid key reference
	err = SaveCertificateChainByID("", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")

	// Test CertificateChainByID with invalid key reference
	_, err = CertificateChainByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")

	// Test CertificateExistsByID with invalid key reference
	_, err = CertificateExistsByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key")

	// Test WrapKey with invalid backend name
	_, err = WrapKey("", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend name")

	// Test UnwrapKey with invalid backend name
	_, err = UnwrapKey("", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend name")

	// Test ImportKey with invalid backend name
	err = ImportKey("", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend name")

	// Test DeleteKeyByID with invalid key ID
	err = DeleteKeyByID("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")
}

// ========================================================================
// Test GenerateKey simplified API
// ========================================================================

func TestGenerateKey_RSA(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-rsa-key",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	key, err := GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok, "expected RSA private key")
}

func TestGenerateKey_ECDSA(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-ecdsa-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	key, err := GenerateKey(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected ECDSA private key")
}

func TestGenerateKey_Ed25519(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-ed25519-key",
		KeyAlgorithm: x509.Ed25519,
	}

	// The mock returns not implemented error for Ed25519
	_, err := GenerateKey(attrs)
	assert.Error(t, err)
}

func TestGenerateKey_UnsupportedAlgorithm(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN:           "test-unknown-key",
		KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Unknown algorithm
	}

	_, err := GenerateKey(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key algorithm")
}

func TestGenerateKey_NotInitialized(t *testing.T) {
	Reset()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.RSA,
	}

	_, err := GenerateKey(attrs)
	assert.Error(t, err)
}

// ========================================================================
// Test Key simplified API
// ========================================================================

func TestKey_Success(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// First generate a key
	attrs := &types.KeyAttributes{
		CN:           "test-key-retrieve",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	_, err := GenerateKey(attrs)
	require.NoError(t, err)

	// Now retrieve it
	key, err := Key(attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	// Should be the same key
	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok)

	_ = pkcs8 // suppress unused warning
}

func TestKey_NotFound(t *testing.T) {
	setupExtendedService(t)

	attrs := &types.KeyAttributes{
		CN: "non-existent-key",
	}

	_, err := Key(attrs)
	assert.Error(t, err)
}

func TestKey_NotInitialized(t *testing.T) {
	Reset()

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}

	_, err := Key(attrs)
	assert.Error(t, err)
}

// ========================================================================
// Additional Error Path Tests
// ========================================================================

func TestVerify_InvalidKeyReference(t *testing.T) {
	setupExtendedService(t)

	err := Verify("", []byte("data"), []byte("sig"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")
}

func TestVerify_WithNilOpts(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate an ECDSA key
	attrs := &types.KeyAttributes{CN: "verify-nil-opts-key"}
	key, err := pkcs8.GenerateECDSA(attrs)
	require.NoError(t, err)

	ecdsaKey := key.(*ecdsa.PrivateKey)

	// Create signature manually with SHA256
	data := []byte("test data")
	hasher := sha256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest)
	require.NoError(t, err)

	// Verify with nil opts (should use default SHA256)
	err = Verify("pkcs8:::verify-nil-opts-key", data, signature, nil)
	assert.NoError(t, err)
}

func TestVerify_WithZeroHash(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate an ECDSA key
	attrs := &types.KeyAttributes{CN: "verify-zero-hash-key"}
	key, err := pkcs8.GenerateECDSA(attrs)
	require.NoError(t, err)

	ecdsaKey := key.(*ecdsa.PrivateKey)

	// Create signature manually with SHA256
	data := []byte("test data")
	hasher := sha256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, digest)
	require.NoError(t, err)

	// Verify with zero Hash (should use default SHA256)
	err = Verify("pkcs8:::verify-zero-hash-key", data, signature, &types.VerifyOpts{Hash: 0})
	assert.NoError(t, err)
}

func TestEncrypt_InvalidKeyReference(t *testing.T) {
	setupExtendedService(t)

	_, err := Encrypt("", []byte("data"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")
}

func TestDecrypt_InvalidKeyReference(t *testing.T) {
	setupExtendedService(t)

	_, err := Decrypt("", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")
}

func TestDecrypt_KeyNotFound(t *testing.T) {
	setupExtendedService(t)

	_, err := Decrypt("nonexistent-key", nil, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

func TestSign_WithNilOpts(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate an ECDSA key
	attrs := &types.KeyAttributes{CN: "sign-nil-opts-key"}
	_, err := pkcs8.GenerateECDSA(attrs)
	require.NoError(t, err)

	data := []byte("test data")
	signature, err := Sign("pkcs8:::sign-nil-opts-key", data, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestSign_WithZeroHash(t *testing.T) {
	pkcs8, _ := setupExtendedService(t)

	// Generate an ECDSA key
	attrs := &types.KeyAttributes{CN: "sign-zero-hash-key"}
	_, err := pkcs8.GenerateECDSA(attrs)
	require.NoError(t, err)

	data := []byte("test data")
	signature, err := Sign("pkcs8:::sign-zero-hash-key", data, &SignOptions{Hash: 0})
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)
}

func TestCopyKey_InvalidSourceKeyRef(t *testing.T) {
	setupExtendedService(t)

	err := CopyKey("", "pkcs11", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid source key ID")
}

func TestGetImportParameters_InvalidBackendName(t *testing.T) {
	setupExtendedService(t)

	_, err := GetImportParameters("", nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend name")
}

func TestGenerateSymmetricKey_InvalidBackendName(t *testing.T) {
	setupExtendedService(t)

	_, err := GenerateSymmetricKey("", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid backend name")
}

func TestGetSymmetricKey_InvalidKeyRef(t *testing.T) {
	setupExtendedService(t)

	_, err := GetSymmetricKey("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")
}

func TestExportKey_InvalidKeyRef(t *testing.T) {
	setupExtendedService(t)

	_, err := ExportKey("", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID")
}
