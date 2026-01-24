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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	client "github.com/jeremyhahn/go-keychain/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBackend implements types.Backend for testing
type mockBackend struct {
	backendType  types.BackendType
	capabilities types.Capabilities
	keys         map[string]crypto.PrivateKey
	symKeys      map[string]types.SymmetricKey
	closeErr     error
	rotateKeyErr error
}

func newMockBackend(bt types.BackendType) *mockBackend {
	return &mockBackend{
		backendType: bt,
		capabilities: types.Capabilities{
			Keys:                true,
			Signing:             true,
			Decryption:          true,
			KeyRotation:         true,
			SymmetricEncryption: true,
			Sealing:             true,
			Import:              true,
			Export:              true,
		},
		keys:    make(map[string]crypto.PrivateKey),
		symKeys: make(map[string]types.SymmetricKey),
	}
}

func (m *mockBackend) Type() types.BackendType {
	return m.backendType
}

func (m *mockBackend) Capabilities() types.Capabilities {
	return m.capabilities
}

func (m *mockBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
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
	case x509.Ed25519:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, errors.New("unsupported algorithm")
	}

	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	key, ok := m.keys[attrs.CN]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func (m *mockBackend) DeleteKey(attrs *types.KeyAttributes) error {
	if _, ok := m.keys[attrs.CN]; !ok {
		return errors.New("key not found")
	}
	delete(m.keys, attrs.CN)
	return nil
}

func (m *mockBackend) ListKeys() ([]*types.KeyAttributes, error) {
	result := make([]*types.KeyAttributes, 0, len(m.keys))
	for cn, key := range m.keys {
		attrs := &types.KeyAttributes{CN: cn}
		switch key.(type) {
		case *rsa.PrivateKey:
			attrs.KeyAlgorithm = x509.RSA
		case *ecdsa.PrivateKey:
			attrs.KeyAlgorithm = x509.ECDSA
		case ed25519.PrivateKey:
			attrs.KeyAlgorithm = x509.Ed25519
		}
		result = append(result, attrs)
	}
	for cn := range m.symKeys {
		result = append(result, &types.KeyAttributes{
			CN:                 cn,
			KeyType:            types.KeyTypeSecret,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		})
	}
	return result, nil
}

func (m *mockBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not support signing")
	}
	return signer, nil
}

func (m *mockBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("key does not support decryption")
	}
	return decrypter, nil
}

func (m *mockBackend) RotateKey(attrs *types.KeyAttributes) error {
	if m.rotateKeyErr != nil {
		return m.rotateKeyErr
	}
	return nil
}

func (m *mockBackend) Close() error {
	return m.closeErr
}

// mockSymmetricKey implements types.SymmetricKey
type mockSymmetricKey struct {
	algorithm string
	keySize   int
	rawKey    []byte
}

func (m *mockSymmetricKey) Algorithm() string { return m.algorithm }
func (m *mockSymmetricKey) KeySize() int      { return m.keySize }
func (m *mockSymmetricKey) Raw() ([]byte, error) {
	return m.rawKey, nil
}

// mockSymmetricEncrypter implements types.SymmetricEncrypter
type mockSymmetricEncrypter struct {
	key *mockSymmetricKey
}

func (m *mockSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &types.EncryptedData{
		Ciphertext: append([]byte("encrypted:"), plaintext...),
		Nonce:      nonce,
		Tag:        []byte("mocktag1234567890"),
	}, nil
}

func (m *mockSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if len(data.Ciphertext) < 10 {
		return nil, errors.New("invalid ciphertext")
	}
	return data.Ciphertext[10:], nil
}

// mockSymmetricBackend extends mockBackend with symmetric capabilities
type mockSymmetricBackend struct {
	*mockBackend
}

func newMockSymmetricBackend(bt types.BackendType) *mockSymmetricBackend {
	return &mockSymmetricBackend{
		mockBackend: newMockBackend(bt),
	}
}

func (m *mockSymmetricBackend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, err
	}
	symKey := &mockSymmetricKey{
		algorithm: string(attrs.SymmetricAlgorithm),
		keySize:   256,
		rawKey:    rawKey,
	}
	m.symKeys[attrs.CN] = symKey
	return symKey, nil
}

func (m *mockSymmetricBackend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	key, ok := m.symKeys[attrs.CN]
	if !ok {
		return nil, errors.New("symmetric key not found")
	}
	return key, nil
}

func (m *mockSymmetricBackend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	key, ok := m.symKeys[attrs.CN]
	if !ok {
		return nil, errors.New("symmetric key not found")
	}
	return &mockSymmetricEncrypter{key: key.(*mockSymmetricKey)}, nil
}

// mockImportExportBackend extends mockSymmetricBackend with import/export capabilities
type mockImportExportBackend struct {
	*mockSymmetricBackend
	wrappingKey *rsa.PrivateKey
}

func newMockImportExportBackend(bt types.BackendType) *mockImportExportBackend {
	wrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &mockImportExportBackend{
		mockSymmetricBackend: newMockSymmetricBackend(bt),
		wrappingKey:          wrappingKey,
	}
}

func (m *mockImportExportBackend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{
		WrappingPublicKey: &m.wrappingKey.PublicKey,
		ImportToken:       []byte("test-token"),
		Algorithm:         algorithm,
	}, nil
}

func (m *mockImportExportBackend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	pubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unsupported wrapping key type")
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

func (m *mockImportExportBackend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, m.wrappingKey, wrapped.WrappedKey, nil)
}

func (m *mockImportExportBackend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	// Simulate key import by storing it
	return nil
}

func (m *mockImportExportBackend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{
		WrappedKey: []byte("wrapped-key-data"),
		Algorithm:  algorithm,
	}, nil
}

// mockSealer implements types.Sealer
type mockSealerBackend struct {
	*mockImportExportBackend
	canSeal bool
}

func newMockSealerBackend(bt types.BackendType) *mockSealerBackend {
	return &mockSealerBackend{
		mockImportExportBackend: newMockImportExportBackend(bt),
		canSeal:                 true,
	}
}

func (m *mockSealerBackend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &types.SealedData{
		Backend:    m.Type(),
		Ciphertext: append([]byte("sealed:"), data...),
		Nonce:      nonce,
		Tag:        []byte("sealtag123456789"),
	}, nil
}

func (m *mockSealerBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if len(sealed.Ciphertext) < 7 {
		return nil, errors.New("invalid sealed data")
	}
	return sealed.Ciphertext[7:], nil
}

func (m *mockSealerBackend) CanSeal() bool {
	return m.canSeal
}

// mockKeyStore implements keychain.KeyStore
type mockKeyStore struct {
	name         string
	keys         map[string]crypto.PrivateKey
	certs        map[string]*x509.Certificate
	certChains   map[string][]*x509.Certificate
	backend      types.Backend
	closeErr     error
	listKeysErr  error
	listCertsErr error
}

func newMockKeyStore(name string, be types.Backend) *mockKeyStore {
	return &mockKeyStore{
		name:       name,
		keys:       make(map[string]crypto.PrivateKey),
		certs:      make(map[string]*x509.Certificate),
		certChains: make(map[string][]*x509.Certificate),
		backend:    be,
	}
}

func (m *mockKeyStore) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	keySize := 2048
	if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
		keySize = attrs.RSAAttributes.KeySize
	}
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockKeyStore) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	curve := elliptic.P256()
	if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
		curve = attrs.ECCAttributes.Curve
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
}

func (m *mockKeyStore) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	m.keys[attrs.CN] = key
	return key, nil
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
	result := make([]*types.KeyAttributes, 0, len(m.keys))
	for cn, key := range m.keys {
		attrs := &types.KeyAttributes{CN: cn}
		switch key.(type) {
		case *rsa.PrivateKey:
			attrs.KeyAlgorithm = x509.RSA
		case *ecdsa.PrivateKey:
			attrs.KeyAlgorithm = x509.ECDSA
		case ed25519.PrivateKey:
			attrs.KeyAlgorithm = x509.Ed25519
		}
		result = append(result, attrs)
	}
	// Add symmetric keys from the backend if it supports them
	if symBackend, ok := m.backend.(*mockSealerBackend); ok {
		for cn := range symBackend.symKeys {
			result = append(result, &types.KeyAttributes{
				CN:                 cn,
				KeyType:            types.KeyTypeSecret,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			})
		}
	}
	return result, nil
}

func (m *mockKeyStore) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	existingKey, ok := m.keys[attrs.CN]
	if !ok {
		return nil, errors.New("key not found")
	}

	var newKey crypto.PrivateKey
	var err error

	switch existingKey.(type) {
	case *rsa.PrivateKey:
		newKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case *ecdsa.PrivateKey:
		newKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519.PrivateKey:
		_, newKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, errors.New("unknown key type")
	}

	if err != nil {
		return nil, err
	}

	m.keys[attrs.CN] = newKey
	return newKey, nil
}

func (m *mockKeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not support signing")
	}
	return signer, nil
}

func (m *mockKeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	key, err := m.GetKey(attrs)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("key does not support decryption")
	}
	return decrypter, nil
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
	m.certChains[keyID] = chain
	return nil
}

func (m *mockKeyStore) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	chain, ok := m.certChains[keyID]
	if !ok {
		return nil, errors.New("certificate chain not found")
	}
	return chain, nil
}

func (m *mockKeyStore) ListCerts() ([]string, error) {
	if m.listCertsErr != nil {
		return nil, m.listCertsErr
	}
	result := make([]string, 0, len(m.certs))
	for keyID := range m.certs {
		result = append(result, keyID)
	}
	return result, nil
}

func (m *mockKeyStore) CertExists(keyID string) (bool, error) {
	_, ok := m.certs[keyID]
	return ok, nil
}

func (m *mockKeyStore) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	cert, ok := m.certs[keyID]
	if !ok {
		return tls.Certificate{}, errors.New("certificate not found")
	}

	key, err := m.GetKey(attrs)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Build certificate chain if available
	certChain := [][]byte{cert.Raw}
	if chain, ok := m.certChains[keyID]; ok {
		for _, c := range chain {
			certChain = append(certChain, c.Raw)
		}
	}

	return tls.Certificate{
		Certificate: certChain,
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

func (m *mockKeyStore) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	key, ok := m.keys[keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func (m *mockKeyStore) GetSignerByID(keyID string) (crypto.Signer, error) {
	key, err := m.GetKeyByID(keyID)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key does not support signing")
	}
	return signer, nil
}

func (m *mockKeyStore) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
	key, err := m.GetKeyByID(keyID)
	if err != nil {
		return nil, err
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("key does not support decryption")
	}
	return decrypter, nil
}

func (m *mockKeyStore) Backend() types.Backend {
	return m.backend
}

func (m *mockKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}

func (m *mockKeyStore) Close() error {
	return m.closeErr
}

func (m *mockKeyStore) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if sealer, ok := m.backend.(types.Sealer); ok {
		return sealer.Seal(ctx, data, opts)
	}
	return nil, errors.New("backend does not support sealing")
}

func (m *mockKeyStore) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealer, ok := m.backend.(types.Sealer); ok {
		return sealer.Unseal(ctx, sealed, opts)
	}
	return nil, errors.New("backend does not support unsealing")
}

func (m *mockKeyStore) CanSeal() bool {
	if sealer, ok := m.backend.(types.Sealer); ok {
		return sealer.CanSeal()
	}
	return false
}

// Test helpers

func setupTestService(t *testing.T) (*mockKeyStore, *mockSealerBackend) {
	t.Helper()
	keychain.Reset()

	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)

	config := &keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": ks,
		},
		DefaultBackend: "software",
	}

	err := keychain.Initialize(config)
	require.NoError(t, err)

	return ks, be
}

func createTestCertificate(t *testing.T, cn string, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// Tests for NewAPIServiceAdapter

func TestNewAPIServiceAdapter_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)
	assert.NotNil(t, adapter)
}

func TestNewAPIServiceAdapter_NotInitialized(t *testing.T) {
	keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	assert.Error(t, err)
	assert.Nil(t, adapter)
	assert.Contains(t, err.Error(), "keychain service not initialized")
}

// Tests for Health

func TestAPIServiceAdapter_Health_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	status, version, err := adapter.Health(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, "healthy", status)
	assert.NotEmpty(t, version)
}

// Tests for ListBackends

func TestAPIServiceAdapter_ListBackends_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	backends, err := adapter.ListBackends(context.Background())
	assert.NoError(t, err)
	assert.Len(t, backends, 1)
	assert.Equal(t, "software", backends[0].ID)
}

// Tests for GetBackend

func TestAPIServiceAdapter_GetBackend_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	info, err := adapter.GetBackend(context.Background(), "software")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "software", info.ID)
}

func TestAPIServiceAdapter_GetBackend_NotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	info, err := adapter.GetBackend(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "backend not found")
}

// Tests for GenerateKey

func TestAPIServiceAdapter_GenerateKey_RSA_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-rsa-key",
		Backend:   "software",
		Algorithm: "RSA",
		KeySize:   2048,
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-rsa-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestAPIServiceAdapter_GenerateKey_ECDSA_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-ecdsa-key",
		Backend:   "software",
		Algorithm: "ECDSA",
		Curve:     "P-256",
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-ecdsa-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestAPIServiceAdapter_GenerateKey_Ed25519_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-ed25519-key",
		Backend:   "software",
		Algorithm: "Ed25519",
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-ed25519-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestAPIServiceAdapter_GenerateKey_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		Backend:   "software",
		Algorithm: "RSA",
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_GenerateKey_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-key",
		Algorithm: "RSA",
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_GenerateKey_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-key",
		Backend:   "nonexistent",
		Algorithm: "RSA",
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_GenerateKey_UnsupportedAlgorithm(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Algorithm: "unknown",
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestAPIServiceAdapter_GenerateKey_InvalidCurve(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-key",
		Backend:   "software",
		Algorithm: "ECDSA",
		Curve:     "invalid-curve",
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid curve")
}

func TestAPIServiceAdapter_GenerateKey_Symmetric_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-symmetric-key",
		Backend:   "software",
		Algorithm: "symmetric",
		KeySize:   256,
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-symmetric-key", resp.KeyID)
}

func TestAPIServiceAdapter_GenerateKey_Symmetric_Default256(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-symmetric-key-default",
		Backend:   "software",
		Algorithm: "symmetric",
		KeySize:   0, // Should default to 256
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-symmetric-key-default", resp.KeyID)
}

func TestAPIServiceAdapter_GenerateKey_Symmetric_AES128(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-aes128-key",
		Backend:   "software",
		Algorithm: "symmetric",
		KeySize:   128,
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-aes128-key", resp.KeyID)
}

func TestAPIServiceAdapter_GenerateKey_Symmetric_AES192(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-aes192-key",
		Backend:   "software",
		Algorithm: "symmetric",
		KeySize:   192,
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-aes192-key", resp.KeyID)
}

func TestAPIServiceAdapter_GenerateKey_Symmetric_InvalidKeySize(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-invalid-key",
		Backend:   "software",
		Algorithm: "symmetric",
		KeySize:   512, // Invalid key size
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid key size for symmetric key")
}

func TestAPIServiceAdapter_GenerateKey_RSA_DefaultKeySize(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-rsa-default",
		Backend:   "software",
		Algorithm: "RSA",
		KeySize:   0, // Should default to 2048
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestAPIServiceAdapter_GenerateKey_ECDSA_DefaultCurve(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-ecdsa-default",
		Backend:   "software",
		Algorithm: "ECDSA",
		Curve:     "", // Should default to P-256
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestAPIServiceAdapter_GenerateKey_KeyTypeAsFallback(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GenerateKeyRequest{
		KeyID:     "test-keytype-fallback",
		Backend:   "software",
		KeyType:   "RSA", // Using KeyType instead of Algorithm
		Algorithm: "",
		KeySize:   2048,
	}

	resp, err := adapter.GenerateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-keytype-fallback", resp.KeyID)
}

// Tests for ListKeys

func TestAPIServiceAdapter_ListKeys_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key
	attrs := &types.KeyAttributes{CN: "list-test-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.ListKeys(context.Background(), "software")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.GreaterOrEqual(t, len(resp.Keys), 1)
}

func TestAPIServiceAdapter_ListKeys_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.ListKeys(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_ListKeys_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.ListKeys(context.Background(), "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

// Tests for GetKey

func TestAPIServiceAdapter_GetKey_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key
	attrs := &types.KeyAttributes{CN: "get-test-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetKey(context.Background(), "software", "get-test-key")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "get-test-key", resp.KeyID)
}

func TestAPIServiceAdapter_GetKey_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetKey(context.Background(), "", "test-key")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_GetKey_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetKey(context.Background(), "software", "")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_GetKey_NotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetKey(context.Background(), "software", "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

// Tests for DeleteKey

func TestAPIServiceAdapter_DeleteKey_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key
	attrs := &types.KeyAttributes{CN: "delete-test-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.DeleteKey(context.Background(), "software", "delete-test-key")
	assert.NoError(t, err)

	// Verify key is deleted
	resp, err := adapter.GetKey(context.Background(), "software", "delete-test-key")
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestAPIServiceAdapter_DeleteKey_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.DeleteKey(context.Background(), "", "test-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_DeleteKey_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.DeleteKey(context.Background(), "software", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_DeleteKey_NotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.DeleteKey(context.Background(), "software", "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key not found")
}

// Tests for Sign

func TestAPIServiceAdapter_Sign_RSA_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key
	attrs := &types.KeyAttributes{CN: "sign-test-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	data := []byte("test data to sign")
	req := &client.SignRequest{
		Backend: "software",
		KeyID:   "sign-test-key",
		Data:    data,
		Hash:    "SHA256",
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Signature)
}

func TestAPIServiceAdapter_Sign_Ed25519_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an Ed25519 key
	attrs := &types.KeyAttributes{CN: "ed25519-sign-key", KeyAlgorithm: x509.Ed25519}
	_, err := ks.GenerateEd25519(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	data := []byte("test data to sign with ed25519")
	req := &client.SignRequest{
		Backend: "software",
		KeyID:   "ed25519-sign-key",
		Data:    data,
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Signature)
}

func TestAPIServiceAdapter_Sign_ECDSA_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an ECDSA key
	attrs := &types.KeyAttributes{CN: "ecdsa-sign-key", KeyAlgorithm: x509.ECDSA}
	_, err := ks.GenerateECDSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	data := []byte("test data to sign with ecdsa")
	req := &client.SignRequest{
		Backend: "software",
		KeyID:   "ecdsa-sign-key",
		Data:    data,
		Hash:    "SHA256",
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Signature)
}

func TestAPIServiceAdapter_Sign_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SignRequest{
		KeyID: "test-key",
		Data:  []byte("test"),
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_Sign_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SignRequest{
		Backend: "software",
		Data:    []byte("test"),
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_Sign_MissingData(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SignRequest{
		Backend: "software",
		KeyID:   "test-key",
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "data is required")
}

// Tests for Verify

func TestAPIServiceAdapter_Verify_RSA_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key
	attrs := &types.KeyAttributes{CN: "verify-test-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// First sign some data
	data := []byte("test data to verify")
	signReq := &client.SignRequest{
		Backend: "software",
		KeyID:   "verify-test-key",
		Data:    data,
		Hash:    "SHA256",
	}

	signResp, err := adapter.Sign(context.Background(), signReq)
	require.NoError(t, err)

	// Now verify
	verifyReq := &client.VerifyRequest{
		Backend:   "software",
		KeyID:     "verify-test-key",
		Data:      data,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	}

	resp, err := adapter.Verify(context.Background(), verifyReq)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
}

func TestAPIServiceAdapter_Verify_Ed25519_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an Ed25519 key
	attrs := &types.KeyAttributes{CN: "ed25519-verify-key", KeyAlgorithm: x509.Ed25519}
	_, err := ks.GenerateEd25519(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Sign data
	data := []byte("test data for ed25519 verification")
	signReq := &client.SignRequest{
		Backend: "software",
		KeyID:   "ed25519-verify-key",
		Data:    data,
	}

	signResp, err := adapter.Sign(context.Background(), signReq)
	require.NoError(t, err)

	// Verify
	verifyReq := &client.VerifyRequest{
		Backend:   "software",
		KeyID:     "ed25519-verify-key",
		Data:      data,
		Signature: signResp.Signature,
	}

	resp, err := adapter.Verify(context.Background(), verifyReq)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
}

func TestAPIServiceAdapter_Verify_ECDSA_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an ECDSA key
	attrs := &types.KeyAttributes{CN: "ecdsa-verify-key", KeyAlgorithm: x509.ECDSA}
	_, err := ks.GenerateECDSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Sign data
	data := []byte("test data for ecdsa verification")
	signReq := &client.SignRequest{
		Backend: "software",
		KeyID:   "ecdsa-verify-key",
		Data:    data,
		Hash:    "SHA256",
	}

	signResp, err := adapter.Sign(context.Background(), signReq)
	require.NoError(t, err)

	// Verify
	verifyReq := &client.VerifyRequest{
		Backend:   "software",
		KeyID:     "ecdsa-verify-key",
		Data:      data,
		Signature: signResp.Signature,
		Hash:      "SHA256",
	}

	resp, err := adapter.Verify(context.Background(), verifyReq)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
}

func TestAPIServiceAdapter_Verify_InvalidSignature(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key
	attrs := &types.KeyAttributes{CN: "verify-invalid-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Try to verify with invalid signature
	verifyReq := &client.VerifyRequest{
		Backend:   "software",
		KeyID:     "verify-invalid-key",
		Data:      []byte("some data"),
		Signature: []byte("invalid-signature-data"),
		Hash:      "SHA256",
	}

	resp, err := adapter.Verify(context.Background(), verifyReq)
	assert.NoError(t, err) // Should not error, just return invalid
	assert.NotNil(t, resp)
	assert.False(t, resp.Valid)
}

func TestAPIServiceAdapter_Verify_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing backend
	req := &client.VerifyRequest{
		KeyID:     "test-key",
		Data:      []byte("test"),
		Signature: []byte("sig"),
	}
	_, err = adapter.Verify(context.Background(), req)
	assert.Contains(t, err.Error(), "backend is required")

	// Missing key_id
	req = &client.VerifyRequest{
		Backend:   "software",
		Data:      []byte("test"),
		Signature: []byte("sig"),
	}
	_, err = adapter.Verify(context.Background(), req)
	assert.Contains(t, err.Error(), "key_id is required")

	// Missing data
	req = &client.VerifyRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Signature: []byte("sig"),
	}
	_, err = adapter.Verify(context.Background(), req)
	assert.Contains(t, err.Error(), "data is required")

	// Missing signature
	req = &client.VerifyRequest{
		Backend: "software",
		KeyID:   "test-key",
		Data:    []byte("test"),
	}
	_, err = adapter.Verify(context.Background(), req)
	assert.Contains(t, err.Error(), "signature is required")
}

// Tests for Encrypt/Decrypt (symmetric)

func TestAPIServiceAdapter_Encrypt_Success(t *testing.T) {
	_, be := setupTestService(t)
	defer keychain.Reset()

	// Generate a symmetric key
	symAttrs := &types.KeyAttributes{
		CN:                 "encrypt-test-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err := be.GenerateSymmetricKey(symAttrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptRequest{
		Backend:   "software",
		KeyID:     "encrypt-test-key",
		Plaintext: []byte("secret data"),
	}

	resp, err := adapter.Encrypt(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)
	assert.NotEmpty(t, resp.Nonce)
}

func TestAPIServiceAdapter_Encrypt_WithAAD(t *testing.T) {
	_, be := setupTestService(t)
	defer keychain.Reset()

	// Generate a symmetric key
	symAttrs := &types.KeyAttributes{
		CN:                 "encrypt-aad-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err := be.GenerateSymmetricKey(symAttrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptRequest{
		Backend:        "software",
		KeyID:          "encrypt-aad-key",
		Plaintext:      []byte("secret data with aad"),
		AdditionalData: []byte("authenticated data"),
	}

	resp, err := adapter.Encrypt(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestAPIServiceAdapter_Decrypt_Success(t *testing.T) {
	_, be := setupTestService(t)
	defer keychain.Reset()

	// Generate a symmetric key
	symAttrs := &types.KeyAttributes{
		CN:                 "decrypt-test-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err := be.GenerateSymmetricKey(symAttrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// First encrypt
	plaintext := []byte("secret data to decrypt")
	encReq := &client.EncryptRequest{
		Backend:   "software",
		KeyID:     "decrypt-test-key",
		Plaintext: plaintext,
	}

	encResp, err := adapter.Encrypt(context.Background(), encReq)
	require.NoError(t, err)

	// Now decrypt
	decReq := &client.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-test-key",
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Tag:        encResp.Tag,
	}

	decResp, err := adapter.Decrypt(context.Background(), decReq)
	assert.NoError(t, err)
	assert.NotNil(t, decResp)
	assert.Equal(t, plaintext, decResp.Plaintext)
}

func TestAPIServiceAdapter_Decrypt_Asymmetric_RSA_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an RSA key for asymmetric decryption
	attrs := &types.KeyAttributes{CN: "rsa-decrypt-key", KeyAlgorithm: x509.RSA}
	rsaKey, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Encrypt with the public key using PKCS1v15 (not OAEP) because
	// the adapter uses decrypter.Decrypt(nil, ciphertext, nil) which defaults to PKCS1v15
	rsaPrivKey := rsaKey.(*rsa.PrivateKey)
	plaintext := []byte("secret message")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaPrivKey.PublicKey, plaintext)
	require.NoError(t, err)

	// Decrypt
	decReq := &client.DecryptRequest{
		Backend:    "software",
		KeyID:      "rsa-decrypt-key",
		Ciphertext: ciphertext,
	}

	decResp, err := adapter.Decrypt(context.Background(), decReq)
	assert.NoError(t, err)
	assert.NotNil(t, decResp)
	assert.Equal(t, plaintext, decResp.Plaintext)
}

func TestAPIServiceAdapter_Encrypt_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing backend
	req := &client.EncryptRequest{
		KeyID:     "test-key",
		Plaintext: []byte("test"),
	}
	_, err = adapter.Encrypt(context.Background(), req)
	assert.Contains(t, err.Error(), "backend is required")

	// Missing key_id
	req = &client.EncryptRequest{
		Backend:   "software",
		Plaintext: []byte("test"),
	}
	_, err = adapter.Encrypt(context.Background(), req)
	assert.Contains(t, err.Error(), "key_id is required")

	// Missing plaintext
	req = &client.EncryptRequest{
		Backend: "software",
		KeyID:   "test-key",
	}
	_, err = adapter.Encrypt(context.Background(), req)
	assert.Contains(t, err.Error(), "plaintext is required")
}

func TestAPIServiceAdapter_Decrypt_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing backend
	req := &client.DecryptRequest{
		KeyID:      "test-key",
		Ciphertext: []byte("test"),
	}
	_, err = adapter.Decrypt(context.Background(), req)
	assert.Contains(t, err.Error(), "backend is required")

	// Missing key_id
	req = &client.DecryptRequest{
		Backend:    "software",
		Ciphertext: []byte("test"),
	}
	_, err = adapter.Decrypt(context.Background(), req)
	assert.Contains(t, err.Error(), "key_id is required")

	// Missing ciphertext
	req = &client.DecryptRequest{
		Backend: "software",
		KeyID:   "test-key",
	}
	_, err = adapter.Decrypt(context.Background(), req)
	assert.Contains(t, err.Error(), "ciphertext is required")
}

// Tests for RotateKey

func TestAPIServiceAdapter_RotateKey_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key
	attrs := &types.KeyAttributes{CN: "rotate-test-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.RotateKeyRequest{
		Backend: "software",
		KeyID:   "rotate-test-key",
	}

	resp, err := adapter.RotateKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.NotEmpty(t, resp.PublicKeyPEM)
}

func TestAPIServiceAdapter_RotateKey_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.RotateKeyRequest{
		KeyID: "test-key",
	}

	resp, err := adapter.RotateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_RotateKey_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.RotateKeyRequest{
		Backend: "software",
	}

	resp, err := adapter.RotateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key_id is required")
}

// Tests for key versioning stubs

func TestAPIServiceAdapter_ListKeyVersions_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.ListKeyVersionsRequest{Backend: "software", KeyID: "test"}
	resp, err := adapter.ListKeyVersions(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key versioning is not yet supported")
}

func TestAPIServiceAdapter_EnableKeyVersion_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EnableKeyVersionRequest{Backend: "software", KeyID: "test", Version: 1}
	resp, err := adapter.EnableKeyVersion(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key versioning is not yet supported")
}

func TestAPIServiceAdapter_DisableKeyVersion_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.DisableKeyVersionRequest{Backend: "software", KeyID: "test", Version: 1}
	resp, err := adapter.DisableKeyVersion(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key versioning is not yet supported")
}

func TestAPIServiceAdapter_EnableAllKeyVersions_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EnableAllKeyVersionsRequest{Backend: "software", KeyID: "test"}
	resp, err := adapter.EnableAllKeyVersions(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key versioning is not yet supported")
}

func TestAPIServiceAdapter_DisableAllKeyVersions_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.DisableAllKeyVersionsRequest{Backend: "software", KeyID: "test"}
	resp, err := adapter.DisableAllKeyVersions(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key versioning is not yet supported")
}

// Tests for user management stubs

func TestAPIServiceAdapter_ListUsers_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.ListUsers(context.Background())
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_GetUser_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetUser(context.Background(), "testuser")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_DeleteUser_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.DeleteUser(context.Background(), "testuser")
	assert.Error(t, err)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_EnableUser_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.EnableUser(context.Background(), "testuser")
	assert.Error(t, err)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_DisableUser_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.DisableUser(context.Background(), "testuser")
	assert.Error(t, err)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_ListUserCredentials_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.ListUserCredentials(context.Background(), "testuser")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, client.ErrNotSupported, err)
}

// Tests for authentication stubs

func TestAPIServiceAdapter_BeginRegistration_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.BeginRegistrationRequest{Username: "testuser"}
	resp, err := adapter.BeginRegistration(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_FinishRegistration_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.FinishRegistrationRequest{Username: "testuser"}
	resp, err := adapter.FinishRegistration(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_BeginAuthentication_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.BeginAuthenticationRequest{Username: "testuser"}
	resp, err := adapter.BeginAuthentication(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, client.ErrNotSupported, err)
}

func TestAPIServiceAdapter_FinishAuthentication_NotSupported(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.FinishAuthenticationRequest{Username: "testuser"}
	resp, err := adapter.FinishAuthentication(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, client.ErrNotSupported, err)
}

// Tests for certificate operations

func TestAPIServiceAdapter_GetCertificate_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "cert-test-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "cert-test-key", signer)
	err = ks.SaveCert("cert-test-key", cert)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetCertificate(context.Background(), "software", "cert-test-key")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "cert-test-key", resp.KeyID)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestAPIServiceAdapter_GetCertificate_NotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetCertificate(context.Background(), "software", "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "certificate not found")
}

func TestAPIServiceAdapter_SaveCertificate_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "save-cert-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "save-cert-key", signer)
	certPEM := encodeCertToPEM(cert)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateRequest{
		KeyID:          "save-cert-key",
		CertificatePEM: certPEM,
	}

	err = adapter.SaveCertificate(context.Background(), req)
	assert.NoError(t, err)
}

func TestAPIServiceAdapter_SaveCertificate_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateRequest{
		CertificatePEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	err = adapter.SaveCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_SaveCertificate_MissingCertPEM(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateRequest{
		KeyID: "test-key",
	}

	err = adapter.SaveCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate_pem is required")
}

func TestAPIServiceAdapter_SaveCertificate_InvalidPEM(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateRequest{
		KeyID:          "test-key",
		CertificatePEM: "invalid pem data",
	}

	err = adapter.SaveCertificate(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate PEM")
}

func TestAPIServiceAdapter_DeleteCertificate_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "del-cert-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "del-cert-key", signer)
	err = ks.SaveCert("del-cert-key", cert)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	err = adapter.DeleteCertificate(context.Background(), "software", "del-cert-key")
	assert.NoError(t, err)
}

func TestAPIServiceAdapter_CertificateExists_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "exists-cert-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "exists-cert-key", signer)
	err = ks.SaveCert("exists-cert-key", cert)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	exists, err := adapter.CertificateExists(context.Background(), "software", "exists-cert-key")
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestAPIServiceAdapter_CertificateExists_NotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	exists, err := adapter.CertificateExists(context.Background(), "software", "nonexistent")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestAPIServiceAdapter_ListCertificates_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "list-cert-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "list-cert-key", signer)
	err = ks.SaveCert("list-cert-key", cert)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.ListCertificates(context.Background(), "software")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.GreaterOrEqual(t, len(resp.Certificates), 1)
}

func TestAPIServiceAdapter_ListCertificates_Error(t *testing.T) {
	keychain.Reset()

	// Set up with a mock keystore that errors on ListCerts
	be := newMockSealerBackend(types.BackendTypeSoftware)
	ks := newMockKeyStore("software", be)
	ks.listCertsErr = errors.New("database error")

	config := &keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": ks,
		},
		DefaultBackend: "software",
	}

	err := keychain.Initialize(config)
	require.NoError(t, err)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.ListCertificates(context.Background(), "software")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to list certificates")
}

// Tests for certificate chain operations

func TestAPIServiceAdapter_SaveCertificateChain_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "chain-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "chain-key", signer)
	certPEM := encodeCertToPEM(cert)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateChainRequest{
		KeyID:    "chain-key",
		ChainPEM: []string{certPEM},
	}

	err = adapter.SaveCertificateChain(context.Background(), req)
	assert.NoError(t, err)
}

func TestAPIServiceAdapter_SaveCertificateChain_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateChainRequest{
		ChainPEM: []string{"cert"},
	}

	err = adapter.SaveCertificateChain(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_SaveCertificateChain_MissingChain(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateChainRequest{
		KeyID: "test-key",
	}

	err = adapter.SaveCertificateChain(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chain_pem is required")
}

func TestAPIServiceAdapter_SaveCertificateChain_InvalidPEM(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SaveCertificateChainRequest{
		KeyID:    "test-key",
		ChainPEM: []string{"invalid-pem-data"},
	}

	err = adapter.SaveCertificateChain(context.Background(), req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid certificate PEM at index 0")
}

func TestAPIServiceAdapter_GetCertificateChain_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate chain
	attrs := &types.KeyAttributes{CN: "get-chain-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "get-chain-key", signer)
	err = ks.SaveCertChain("get-chain-key", []*x509.Certificate{cert})
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetCertificateChain(context.Background(), "software", "get-chain-key")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "get-chain-key", resp.KeyID)
	assert.Len(t, resp.ChainPEM, 1)
}

func TestAPIServiceAdapter_GetCertificateChain_NotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetCertificateChain(context.Background(), "software", "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "certificate chain not found")
}

// Tests for TLS certificate

func TestAPIServiceAdapter_GetTLSCertificate_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "tls-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	cert := createTestCertificate(t, "tls-key", signer)
	err = ks.SaveCert("tls-key", cert)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetTLSCertificate(context.Background(), "software", "tls-key")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "tls-key", resp.KeyID)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestAPIServiceAdapter_GetTLSCertificate_WithChain(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test key and certificate
	attrs := &types.KeyAttributes{CN: "tls-chain-key", KeyAlgorithm: x509.RSA}
	key, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)

	leafCert := createTestCertificate(t, "tls-chain-key", signer)
	intermediateCert := createTestCertificate(t, "intermediate-ca", signer)

	err = ks.SaveCert("tls-chain-key", leafCert)
	require.NoError(t, err)
	err = ks.SaveCertChain("tls-chain-key", []*x509.Certificate{intermediateCert})
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetTLSCertificate(context.Background(), "software", "tls-chain-key")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "tls-chain-key", resp.KeyID)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.NotEmpty(t, resp.ChainPEM)
}

func TestAPIServiceAdapter_GetTLSCertificate_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetTLSCertificate(context.Background(), "", "test-key")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_GetTLSCertificate_MissingKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetTLSCertificate(context.Background(), "software", "")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_GetTLSCertificate_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetTLSCertificate(context.Background(), "nonexistent", "test-key")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_GetTLSCertificate_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.GetTLSCertificate(context.Background(), "software", "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

// Tests for Seal/Unseal

func TestAPIServiceAdapter_Seal_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data"),
	}

	resp, err := adapter.Seal(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestAPIServiceAdapter_Seal_WithAAD(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data with aad"),
		AAD:     []byte("authenticated data"),
	}

	resp, err := adapter.Seal(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestAPIServiceAdapter_Seal_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SealRequest{
		Data: []byte("secret data"),
	}

	resp, err := adapter.Seal(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_Seal_MissingData(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SealRequest{
		Backend: "software",
	}

	resp, err := adapter.Seal(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "data is required")
}

func TestAPIServiceAdapter_Unseal_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// First seal some data
	sealReq := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data to unseal"),
	}

	sealResp, err := adapter.Seal(context.Background(), sealReq)
	require.NoError(t, err)

	// Now unseal
	unsealReq := &client.UnsealRequest{
		Backend:    "software",
		Ciphertext: sealResp.Ciphertext,
		Nonce:      sealResp.Nonce,
		Tag:        sealResp.Tag,
	}

	unsealResp, err := adapter.Unseal(context.Background(), unsealReq)
	assert.NoError(t, err)
	assert.NotNil(t, unsealResp)
	assert.Equal(t, []byte("secret data to unseal"), unsealResp.Plaintext)
}

func TestAPIServiceAdapter_Unseal_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.UnsealRequest{
		Ciphertext: []byte("encrypted"),
	}

	resp, err := adapter.Unseal(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_Unseal_MissingCiphertext(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.UnsealRequest{
		Backend: "software",
	}

	resp, err := adapter.Unseal(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "ciphertext is required")
}

func TestAPIServiceAdapter_Unseal_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.UnsealRequest{
		Backend:    "nonexistent",
		Ciphertext: []byte("encrypted-data"),
	}

	resp, err := adapter.Unseal(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

// Tests for CanSeal

func TestAPIServiceAdapter_CanSeal_WithBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.CanSeal(context.Background(), "software")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "software", resp.Backend)
}

func TestAPIServiceAdapter_CanSeal_DefaultBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.CanSeal(context.Background(), "")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

// Tests for EncryptAsym

func TestAPIServiceAdapter_EncryptAsym_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a test RSA key
	attrs := &types.KeyAttributes{CN: "asym-enc-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "asym-enc-key",
		Plaintext: []byte("test data for asymmetric encryption"),
		Hash:      "SHA256",
	}

	resp, err := adapter.EncryptAsym(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestAPIServiceAdapter_EncryptAsym_NonRSAKey(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create an ECDSA key (non-RSA)
	attrs := &types.KeyAttributes{CN: "ecdsa-asym-key", KeyAlgorithm: x509.ECDSA}
	_, err := ks.GenerateECDSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "ecdsa-asym-key",
		Plaintext: []byte("test data"),
	}

	resp, err := adapter.EncryptAsym(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "asymmetric encryption only supported for RSA keys")
}

func TestAPIServiceAdapter_EncryptAsym_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing backend
	req := &client.EncryptAsymRequest{
		KeyID:     "test-key",
		Plaintext: []byte("test"),
	}
	_, err = adapter.EncryptAsym(context.Background(), req)
	assert.Contains(t, err.Error(), "backend is required")

	// Missing key_id
	req = &client.EncryptAsymRequest{
		Backend:   "software",
		Plaintext: []byte("test"),
	}
	_, err = adapter.EncryptAsym(context.Background(), req)
	assert.Contains(t, err.Error(), "key_id is required")

	// Missing plaintext
	req = &client.EncryptAsymRequest{
		Backend: "software",
		KeyID:   "test-key",
	}
	_, err = adapter.EncryptAsym(context.Background(), req)
	assert.Contains(t, err.Error(), "plaintext is required")
}

func TestAPIServiceAdapter_EncryptAsym_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptAsymRequest{
		Backend:   "nonexistent",
		KeyID:     "test-key",
		Plaintext: []byte("test"),
	}

	resp, err := adapter.EncryptAsym(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_EncryptAsym_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "nonexistent",
		Plaintext: []byte("test"),
	}

	resp, err := adapter.EncryptAsym(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

// Tests for Import/Export operations

func TestAPIServiceAdapter_ImportKey_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.ImportKeyRequest{
		Backend:            "software",
		KeyID:              "imported-key",
		WrappedKeyMaterial: []byte("wrapped-key-material"),
		Algorithm:          "RSA-OAEP-256",
	}

	resp, err := adapter.ImportKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Equal(t, "imported-key", resp.KeyID)
}

func TestAPIServiceAdapter_ImportKey_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing backend
	req := &client.ImportKeyRequest{
		KeyID:              "test-key",
		WrappedKeyMaterial: []byte("wrapped"),
	}
	_, err = adapter.ImportKey(context.Background(), req)
	assert.Contains(t, err.Error(), "backend is required")

	// Missing key_id
	req = &client.ImportKeyRequest{
		Backend:            "software",
		WrappedKeyMaterial: []byte("wrapped"),
	}
	_, err = adapter.ImportKey(context.Background(), req)
	assert.Contains(t, err.Error(), "key_id is required")

	// Missing wrapped_key_material
	req = &client.ImportKeyRequest{
		Backend: "software",
		KeyID:   "test-key",
	}
	_, err = adapter.ImportKey(context.Background(), req)
	assert.Contains(t, err.Error(), "wrapped_key_material is required")
}

func TestAPIServiceAdapter_ExportKey_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a key to export
	attrs := &types.KeyAttributes{CN: "export-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.ExportKeyRequest{
		Backend:   "software",
		KeyID:     "export-key",
		Algorithm: "RSA-OAEP-256",
	}

	resp, err := adapter.ExportKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "export-key", resp.KeyID)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestAPIServiceAdapter_ExportKey_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing backend
	req := &client.ExportKeyRequest{
		KeyID: "test-key",
	}
	_, err = adapter.ExportKey(context.Background(), req)
	assert.Contains(t, err.Error(), "backend is required")

	// Missing key_id
	req = &client.ExportKeyRequest{
		Backend: "software",
	}
	_, err = adapter.ExportKey(context.Background(), req)
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestAPIServiceAdapter_GetImportParameters_Success(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "test-key",
		Algorithm: "RSA-OAEP-256",
	}

	resp, err := adapter.GetImportParameters(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.WrappingPublicKey)
}

func TestAPIServiceAdapter_GetImportParameters_MissingBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GetImportParametersRequest{
		KeyID: "test-key",
	}
	_, err = adapter.GetImportParameters(context.Background(), req)
	assert.Contains(t, err.Error(), "backend is required")
}

func TestAPIServiceAdapter_WrapKey_Success(t *testing.T) {
	_, be := setupTestService(t)
	defer keychain.Reset()

	// Get wrapping public key
	pubKeyDER, err := x509.MarshalPKIXPublicKey(&be.wrappingKey.PublicKey)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.WrapKeyRequest{
		KeyMaterial:       []byte("secret-key-material"),
		WrappingPublicKey: pubKeyDER,
		Algorithm:         "RSA-OAEP-256",
	}

	resp, err := adapter.WrapKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.WrappedKeyMaterial)
}

func TestAPIServiceAdapter_WrapKey_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing key_material
	req := &client.WrapKeyRequest{
		WrappingPublicKey: []byte("key"),
	}
	_, err = adapter.WrapKey(context.Background(), req)
	assert.Contains(t, err.Error(), "key_material is required")

	// Missing wrapping_public_key
	req = &client.WrapKeyRequest{
		KeyMaterial: []byte("material"),
	}
	_, err = adapter.WrapKey(context.Background(), req)
	assert.Contains(t, err.Error(), "wrapping_public_key is required")
}

func TestAPIServiceAdapter_WrapKey_InvalidPublicKey(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.WrapKeyRequest{
		KeyMaterial:       []byte("secret-key-material"),
		WrappingPublicKey: []byte("invalid-public-key"),
		Algorithm:         "RSA-OAEP-256",
	}

	resp, err := adapter.WrapKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to parse wrapping public key")
}

func TestAPIServiceAdapter_UnwrapKey_Success(t *testing.T) {
	_, be := setupTestService(t)
	defer keychain.Reset()

	// Wrap some key material first
	keyMaterial := []byte("secret-key-material-16")
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &be.wrappingKey.PublicKey, keyMaterial, nil)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.UnwrapKeyRequest{
		WrappedKeyMaterial: wrapped,
		Algorithm:          "RSA-OAEP-256",
	}

	resp, err := adapter.UnwrapKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, keyMaterial, resp.KeyMaterial)
}

func TestAPIServiceAdapter_UnwrapKey_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing wrapped_key_material
	req := &client.UnwrapKeyRequest{}
	_, err = adapter.UnwrapKey(context.Background(), req)
	assert.Contains(t, err.Error(), "wrapped_key_material is required")
}

// Tests for CopyKey

func TestAPIServiceAdapter_CopyKey_MissingFields(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Missing source_backend
	req := &client.CopyKeyRequest{
		SourceKeyID: "key",
		DestBackend: "dest",
		DestKeyID:   "dest-key",
	}
	_, err = adapter.CopyKey(context.Background(), req)
	assert.Contains(t, err.Error(), "source_backend is required")

	// Missing source_key_id
	req = &client.CopyKeyRequest{
		SourceBackend: "source",
		DestBackend:   "dest",
		DestKeyID:     "dest-key",
	}
	_, err = adapter.CopyKey(context.Background(), req)
	assert.Contains(t, err.Error(), "source_key_id is required")

	// Missing dest_backend
	req = &client.CopyKeyRequest{
		SourceBackend: "source",
		SourceKeyID:   "key",
		DestKeyID:     "dest-key",
	}
	_, err = adapter.CopyKey(context.Background(), req)
	assert.Contains(t, err.Error(), "dest_backend is required")

	// Missing dest_key_id
	req = &client.CopyKeyRequest{
		SourceBackend: "source",
		SourceKeyID:   "key",
		DestBackend:   "dest",
	}
	_, err = adapter.CopyKey(context.Background(), req)
	assert.Contains(t, err.Error(), "dest_key_id is required")
}

func TestAPIServiceAdapter_CopyKey_SourceBackendNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.CopyKeyRequest{
		SourceBackend: "nonexistent",
		SourceKeyID:   "key",
		DestBackend:   "software",
		DestKeyID:     "dest-key",
	}
	_, err = adapter.CopyKey(context.Background(), req)
	assert.Contains(t, err.Error(), "source backend not found")
}

func TestAPIServiceAdapter_CopyKey_DestBackendNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "key",
		DestBackend:   "nonexistent",
		DestKeyID:     "dest-key",
	}
	_, err = adapter.CopyKey(context.Background(), req)
	assert.Contains(t, err.Error(), "destination backend not found")
}

func TestAPIServiceAdapter_CopyKey_Success(t *testing.T) {
	ks, _ := setupTestService(t)
	defer keychain.Reset()

	// Create a key to copy
	attrs := &types.KeyAttributes{CN: "copy-src-key", KeyAlgorithm: x509.RSA}
	_, err := ks.GenerateRSA(attrs)
	require.NoError(t, err)

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "copy-src-key",
		DestBackend:   "software",
		DestKeyID:     "copy-dest-key",
		Algorithm:     "RSA-OAEP-256",
	}

	resp, err := adapter.CopyKey(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Equal(t, "copy-dest-key", resp.KeyID)
}

// Test helper functions

func TestAPIServiceAdapter_parseHashAlgorithm(t *testing.T) {
	tests := []struct {
		input    string
		expected crypto.Hash
	}{
		{"", crypto.SHA256},
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
		{"sha256", crypto.SHA256},
		{"invalid", crypto.SHA256},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := parseHashAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestAPIServiceAdapter_getAlgorithmString(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		expected string
	}{
		{
			name: "symmetric algorithm",
			attrs: &types.KeyAttributes{
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			expected: "aes256-gcm",
		},
		{
			name: "RSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
			},
			expected: "RSA",
		},
		{
			name: "ECDSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
			},
			expected: "ECDSA",
		},
		{
			name: "unknown algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
			},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := getAlgorithmString(tc.attrs)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestAPIServiceAdapter_extractPublicKeyPEM(t *testing.T) {
	// Test with RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemStr, err := extractPublicKeyPEM(rsaKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, pemStr)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")

	// Test with ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemStr, err = extractPublicKeyPEM(ecdsaKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, pemStr)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")

	// Test with Ed25519 key
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemStr, err = extractPublicKeyPEM(ed25519Key)
	assert.NoError(t, err)
	assert.NotEmpty(t, pemStr)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
}

func TestAPIServiceAdapter_extractPublicKeyPEM_UnsupportedType(t *testing.T) {
	// Test with unsupported type (string is not a valid key type)
	pemStr, err := extractPublicKeyPEM("not a key")
	assert.Error(t, err)
	assert.Empty(t, pemStr)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestAPIServiceAdapter_parseCertFromPEM(t *testing.T) {
	// Create a valid certificate
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertificate(t, "test-cert", rsaKey)
	certPEM := encodeCertToPEM(cert)

	// Test valid PEM
	parsed, err := parseCertFromPEM(certPEM)
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, "test-cert", parsed.Subject.CommonName)

	// Test invalid PEM - no block
	_, err = parseCertFromPEM("invalid data")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")

	// Test invalid PEM - wrong type
	wrongPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("test"),
	})
	_, err = parseCertFromPEM(string(wrongPEM))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PEM type")
}

func TestAPIServiceAdapter_encodeCertToPEM(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cert := createTestCertificate(t, "encode-test", rsaKey)
	pemStr := encodeCertToPEM(cert)

	assert.NotEmpty(t, pemStr)
	assert.Contains(t, pemStr, "BEGIN CERTIFICATE")
	assert.Contains(t, pemStr, "END CERTIFICATE")
}

// Test interface compliance at compile time
var _ client.KeychainServicer = (*APIServiceAdapter)(nil)

// Additional tests for coverage improvements

func TestAPIServiceAdapter_Seal_WithInvalidKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Use an invalid key ID format: format is backend:type:algo:keyname (4 parts) or simple name (no colons)
	// Using 2 or 3 colons should cause an error
	req := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data"),
		KeyID:   "invalid:partial:format", // 3 parts instead of 4
	}

	// This should fail with invalid key ID format error
	resp, err := adapter.Seal(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid key ID format")
}

func TestAPIServiceAdapter_Seal_WithValidKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Use the unified key ID format: backend:type:algo:keyname (4 parts with colons)
	// Using empty segments for type and algo
	req := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data with key ID"),
		KeyID:   "software:::test-key", // Valid 4-part format
	}

	resp, err := adapter.Seal(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestAPIServiceAdapter_Seal_WithSimpleKeyName(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// Use a simple key name (no colons)
	req := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data with simple key ID"),
		KeyID:   "simple-key-name",
	}

	resp, err := adapter.Seal(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestAPIServiceAdapter_Unseal_WithInvalidKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// First seal some data
	sealReq := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data"),
	}
	sealResp, err := adapter.Seal(context.Background(), sealReq)
	require.NoError(t, err)

	// Try to unseal with invalid key ID (wrong format)
	unsealReq := &client.UnsealRequest{
		Backend:    "software",
		Ciphertext: sealResp.Ciphertext,
		Nonce:      sealResp.Nonce,
		Tag:        sealResp.Tag,
		KeyID:      "invalid:partial:format", // 3 parts instead of 4
	}

	resp, err := adapter.Unseal(context.Background(), unsealReq)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid key ID format")
}

func TestAPIServiceAdapter_Unseal_WithValidKeyID(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	// First seal some data
	sealReq := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data with key ID"),
	}
	sealResp, err := adapter.Seal(context.Background(), sealReq)
	require.NoError(t, err)

	// Unseal with valid key ID format (4 parts)
	unsealReq := &client.UnsealRequest{
		Backend:    "software",
		Ciphertext: sealResp.Ciphertext,
		Nonce:      sealResp.Nonce,
		Tag:        sealResp.Tag,
		KeyID:      "software:::test-key",
	}

	resp, err := adapter.Unseal(context.Background(), unsealReq)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, []byte("secret data with key ID"), resp.Plaintext)
}

func TestAPIServiceAdapter_Unseal_WithAAD(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	aad := []byte("additional authenticated data")

	// Seal with AAD
	sealReq := &client.SealRequest{
		Backend: "software",
		Data:    []byte("secret data with aad"),
		AAD:     aad,
	}
	sealResp, err := adapter.Seal(context.Background(), sealReq)
	require.NoError(t, err)

	// Unseal with same AAD
	unsealReq := &client.UnsealRequest{
		Backend:    "software",
		Ciphertext: sealResp.Ciphertext,
		Nonce:      sealResp.Nonce,
		Tag:        sealResp.Tag,
		AAD:        aad,
	}

	resp, err := adapter.Unseal(context.Background(), unsealReq)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, []byte("secret data with aad"), resp.Plaintext)
}

func TestAPIServiceAdapter_RotateKey_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.RotateKeyRequest{
		Backend: "nonexistent",
		KeyID:   "test-key",
	}

	resp, err := adapter.RotateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_RotateKey_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.RotateKeyRequest{
		Backend: "software",
		KeyID:   "nonexistent-key",
	}

	resp, err := adapter.RotateKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

func TestAPIServiceAdapter_ExportKey_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.ExportKeyRequest{
		Backend:   "nonexistent",
		KeyID:     "test-key",
		Algorithm: "RSA-OAEP-256",
	}

	resp, err := adapter.ExportKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_ExportKey_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.ExportKeyRequest{
		Backend:   "software",
		KeyID:     "nonexistent-key",
		Algorithm: "RSA-OAEP-256",
	}

	resp, err := adapter.ExportKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

func TestAPIServiceAdapter_ImportKey_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.ImportKeyRequest{
		Backend:            "nonexistent",
		KeyID:              "imported-key",
		WrappedKeyMaterial: []byte("wrapped-key-material"),
		Algorithm:          "RSA-OAEP-256",
	}

	resp, err := adapter.ImportKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_GetImportParameters_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.GetImportParametersRequest{
		Backend:   "nonexistent",
		KeyID:     "test-key",
		Algorithm: "RSA-OAEP-256",
	}

	resp, err := adapter.GetImportParameters(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_Encrypt_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptRequest{
		Backend:   "nonexistent",
		KeyID:     "test-key",
		Plaintext: []byte("test data"),
	}

	resp, err := adapter.Encrypt(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_Encrypt_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.EncryptRequest{
		Backend:   "software",
		KeyID:     "nonexistent-key",
		Plaintext: []byte("test data"),
	}

	resp, err := adapter.Encrypt(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

func TestAPIServiceAdapter_Decrypt_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.DecryptRequest{
		Backend:    "nonexistent",
		KeyID:      "test-key",
		Ciphertext: []byte("test data"),
	}

	resp, err := adapter.Decrypt(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_Decrypt_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.DecryptRequest{
		Backend:    "software",
		KeyID:      "nonexistent-key",
		Ciphertext: []byte("test data"),
	}

	resp, err := adapter.Decrypt(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

func TestAPIServiceAdapter_Sign_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SignRequest{
		Backend: "nonexistent",
		KeyID:   "test-key",
		Data:    []byte("test data"),
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_Sign_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SignRequest{
		Backend: "software",
		KeyID:   "nonexistent-key",
		Data:    []byte("test data"),
	}

	resp, err := adapter.Sign(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

func TestAPIServiceAdapter_Verify_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.VerifyRequest{
		Backend:   "nonexistent",
		KeyID:     "test-key",
		Data:      []byte("test data"),
		Signature: []byte("signature"),
	}

	resp, err := adapter.Verify(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "backend not found")
}

func TestAPIServiceAdapter_Verify_KeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.VerifyRequest{
		Backend:   "software",
		KeyID:     "nonexistent-key",
		Data:      []byte("test data"),
		Signature: []byte("signature"),
	}

	resp, err := adapter.Verify(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

func TestAPIServiceAdapter_Seal_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.SealRequest{
		Backend: "nonexistent",
		Data:    []byte("test data"),
	}

	resp, err := adapter.Seal(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to seal data")
}

func TestAPIServiceAdapter_CanSeal_InvalidBackend(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	resp, err := adapter.CanSeal(context.Background(), "nonexistent")
	assert.NoError(t, err) // CanSeal returns false for non-existent backends, not an error
	assert.NotNil(t, resp)
	assert.False(t, resp.CanSeal)
}

func TestAPIServiceAdapter_CopyKey_SourceKeyNotFound(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "nonexistent-key",
		DestBackend:   "software",
		DestKeyID:     "dest-key",
	}

	resp, err := adapter.CopyKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "key not found")
}

func TestAPIServiceAdapter_UnwrapKey_InvalidWrappedKey(t *testing.T) {
	setupTestService(t)
	defer keychain.Reset()

	adapter, err := NewAPIServiceAdapter()
	require.NoError(t, err)

	req := &client.UnwrapKeyRequest{
		WrappedKeyMaterial: []byte("invalid-wrapped-key-data"),
		Algorithm:          "RSA-OAEP-256",
	}

	resp, err := adapter.UnwrapKey(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to unwrap key")
}
