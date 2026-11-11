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

// Package ca coverage boost, ninth pass: targets remaining sub-91% functions
// not yet exercised by the prior eight passes.
// All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	backendpkg "github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers shared across boost9
// =============================================================================

// newB9Backend creates a fresh software-backed xkms.Backend + certstore for
// use by multi-identity constructor tests.
func newB9Backend(t *testing.T) (xkms.Backend, certstore.CertStore) {
	t.Helper()
	ks := storage.NewMemory()
	sw, err := software.NewBackend(&software.Config{KeyStorage: ks})
	require.NoError(t, err)
	cs := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: sw, CertStorage: cs})
	require.NoError(t, err)
	certStore, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	return backend, certStore
}

// b9Ed25519KeyConfig returns a KeyConfig for Ed25519 (no hash, no curve).
func b9Ed25519KeyConfig() []*types.KeyConfig {
	return []*types.KeyConfig{
		{
			KeyAlgorithm:       types.AlgorithmEd25519,
			SignatureAlgorithm: types.SigEd25519,
			StoreType:          types.StoreSoftware,
			KeyType:            "CA",
		},
	}
}

// setupEd25519CA creates a fully initialized CA backed by an Ed25519 root key.
// This exercises the Ed25519 branch in getOrGenerateCAKey and getSigningHashFunc.
func setupEd25519CA(t *testing.T) *CA {
	t.Helper()

	backend, cs := newB9Backend(t)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Ed25519 Root CA B9"
	config.Identity[0].Subject.Organization = "Test Organization"
	config.Identity[0].Keys = b9Ed25519KeyConfig()

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:          config,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.NoError(t, err)
	require.NoError(t, caIface.Init(context.Background()))

	concreteCA, ok := caIface.(*CA)
	require.True(t, ok)
	return concreteCA
}

// =============================================================================
// ca.go — Sign: getSigner error + Sign error paths
// (brings Sign from 77.8% toward 100%)
// =============================================================================

// TestSign_GetSignerError verifies that Sign propagates getSigner errors.
// We exercise this by calling Sign on an uninitialised CA that has been
// force-marked initialized but has no issuing identity configured.
func TestSign_GetSignerError_B9(t *testing.T) {
	t.Parallel()
	ca := &CA{config: &MultiIdentityCAConfig{}}
	ca.initialized.Store(true)
	_, err := ca.Sign(rand.Reader, []byte("payload"), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSigningFailed)
}

// =============================================================================
// ca.go — Load: success with intermediate, and key-not-found error
// =============================================================================

// TestLoad_RootKeyNotFound exercises the "root key not found" branch in Load.
func TestLoad_RootKeyNotFound_B9(t *testing.T) {
	t.Parallel()

	// Init with one backend, then Load with a different (empty) keystore.
	initBackend, cs := newB9Backend(t)
	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "LoadKeyMissing Root B9"
	config.Identity[0].Keys[0].KeyType = "CA"

	initCA := &CA{
		config:      config,
		keyStore:    initBackend,
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: initBackend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, initCA.Init(context.Background()))

	// Use a fresh empty backend (no keys) but same certstore (cert exists).
	emptyBackend, _ := newB9Backend(t)
	loadCA := &CA{
		config:      config,
		keyStore:    emptyBackend, // keys missing here
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: emptyBackend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	err := loadCA.Load(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyStoreRequired)
}

// =============================================================================
// ca.go — getOrGenerateCAKey: Ed25519 branch + unsupported algorithm default
// =============================================================================

// TestGetOrGenerateCAKey_UnsupportedAlgorithm_B9 exercises the default error
// branch in getOrGenerateCAKey by injecting an x509.UnknownPublicKeyAlgorithm
// on a key the backend genuinely reports as not found. The generation
// switch's default branch (ErrInvalidKeyAlgorithm) is only reachable past
// go-xkms#801's fail-closed check when GetKey's failure classifies as
// errors.Is(err, backend.ErrKeyNotFound); it is exercised here through a
// mock backend rather than the software backend's own KeyAttributes.Validate
// (which would itself reject an unset algorithm before getOrGenerateCAKey's
// generation switch ever runs).
func TestGetOrGenerateCAKey_UnsupportedAlgorithm_B9(t *testing.T) {
	t.Parallel()
	mockKP := mocks.NewMockBackend()
	mockKP.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, backendpkg.ErrKeyNotFound
	}
	ca := setupUninitializedCAWithKeyProvider(t, mockKP)

	attrs := &types.KeyAttributes{
		CN:           "unsupported-algo-b9",
		KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		KeyType:      types.KeyTypeCA,
		StoreType:    types.StoreSoftware,
	}
	_, err := ca.getOrGenerateCAKey(context.Background(), attrs)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
	assert.Empty(t, mockKP.GenerateKeyCalls)
}

// =============================================================================
// constructors.go — ResolveStores: factory-based paths
// =============================================================================

// TestResolveStores_CertStoreFactoryError_B9 exercises certstore factory error.
func TestResolveStores_CertStoreFactoryError_B9(t *testing.T) {
	t.Parallel()
	backend, _ := newB9Backend(t)

	p := &Params{
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStoreFactory: func(cn string) (certstore.CertStore, error) {
			return nil, errors.New("certstore factory failure")
		},
	}
	_, _, _, err := p.ResolveStores("test-b9")
	require.Error(t, err)
}

// TestResolveStores_CertStoreFactoryNil_B9 exercises certstore factory returning nil.
func TestResolveStores_CertStoreFactoryNil_B9(t *testing.T) {
	t.Parallel()
	backend, _ := newB9Backend(t)

	p := &Params{
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStoreFactory: func(cn string) (certstore.CertStore, error) {
			return nil, nil
		},
	}
	_, _, _, err := p.ResolveStores("test-b9")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStoreFactoryReturnedNil)
}

// TestResolveStores_ObjectStoreFactoryError_B9 exercises object store factory error.
func TestResolveStores_ObjectStoreFactoryError_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	p := &Params{
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		ObjectStoreFactory: ObjectStoreFactoryFunc(func(cn string) (qrdbsdk.Storage, error) {
			return nil, errors.New("objstore factory failure")
		}),
	}
	_, _, _, err := p.ResolveStores("test-b9")
	require.Error(t, err)
}

// =============================================================================
// cross_signing.go — ImportXSignedCertificate, XSignedRootCertificate,
// XSignedIntermediateCertificates, CrossSignedPEM
// =============================================================================

// b9MakeSelfSignedCACert creates an in-memory self-signed CA certificate.
func b9MakeSelfSignedCACert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// TestXSignedRootCertificate_NoObjectStore_B9 exercises ErrObjectStoreRequired.
func TestXSignedRootCertificate_NoObjectStore_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = nil

	cert, _ := b9MakeSelfSignedCACert(t, "xroot-nostore-b9")
	_, err := ca.XSignedRootCertificate("issuer-b9", cert)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// TestXSignedIntermediateCertificates_NoObjectStore_B9 exercises ErrObjectStoreRequired.
func TestXSignedIntermediateCertificates_NoObjectStore_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = nil

	cert, _ := b9MakeSelfSignedCACert(t, "xint-nostore-b9")
	_, err := ca.XSignedIntermediateCertificates("issuer-b9", cert)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// =============================================================================
// ca.go — SignedBlob: Ed25519 (hashFunc==0) path
// =============================================================================

// TestSignedBlob_Ed25519_B9 exercises the hashFunc==0 branch in SignedBlob,
// which is taken when the CA uses an Ed25519 key (PureEd25519 signs directly
// without pre-hashing).
func TestSignedBlob_Ed25519_B9(t *testing.T) {
	t.Parallel()
	ca := setupEd25519CA(t)
	data := []byte("test-ed25519-signed-blob-b9")
	sig, err := ca.SignedBlob(context.Background(), data)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

// =============================================================================
// csr.go — getOrGenerateKey: RSA branch and default fallback
// =============================================================================

// TestGetOrGenerateKey_ExistingKey_B9 exercises the "signer already in store"
// early return in getOrGenerateKey by issuing a cert (stores its key) and then
// calling getOrGenerateKey with the same attrs.
func TestGetOrGenerateKey_ExistingKey_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	cn := "existing-key-b9"
	issueCertAndSaveToKeyStore(t, ca, cn)

	req := &CertificateRequest{
		TenantID:      testTenant,
		Subject:       Subject{CommonName: cn},
		KeyAttributes: softwareKeyAttrs(cn),
	}
	signer, err := ca.getOrGenerateKey(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// TestGetOrGenerateKey_DefaultFallback_B9 exercises the default ECDSA fallback
// case in getOrGenerateKey when KeyAlgorithm is set to an unknown value (0).
func TestGetOrGenerateKey_DefaultFallback_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	req := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "default-fallback-b9"},
		KeyAttributes: &types.KeyAttributes{
			CN:           "default-fallback-b9",
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm, // triggers default branch
			StoreType:    types.StoreSoftware,
			KeyType:      types.KeyTypeTLS,
		},
	}
	signer, err := ca.getOrGenerateKey(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

// =============================================================================
// ca.go — IsRevoked: nil serial returns (false, nil)
// =============================================================================

// TestIsRevoked_NilSerial_B9 exercises the nil serial early return in IsRevoked.
func TestIsRevoked_NilSerial_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	revoked, err := ca.IsRevoked(nil)
	require.NoError(t, err)
	assert.False(t, revoked)
}
