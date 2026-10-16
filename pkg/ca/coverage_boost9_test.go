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
	"encoding/pem"
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

// TestSign_NotInitialized exercises the ErrNotInitialized guard at the top of Sign.
func TestSign_NotInitialized_B9(t *testing.T) {
	t.Parallel()
	ca := &CA{}
	_, err := ca.Sign(nil, []byte("digest"), nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// TestSign_Success exercises the happy path of Sign using the CA as crypto.Signer.
func TestSign_Success_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	// Sign a SHA-256 digest of a small message.
	digest := make([]byte, 32) // 32 bytes = SHA-256 output
	_, err := rand.Read(digest)
	require.NoError(t, err)
	sig, err := ca.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

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
// ca.go — CABundle: both intermediate-present and empty-bundle error paths
// =============================================================================

// TestCABundle_WithIntermediate exercises the intermediate branch (line 831-838)
// where intermediateCert != nil adds to the bundle.
func TestCABundle_WithIntermediate_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCAWithRealIntermediate(t)
	bundle, err := ca.CABundle()
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
	// Bundle must contain at least two PEM blocks (intermediate + root).
	rest := bundle
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		count++
	}
	assert.GreaterOrEqual(t, count, 2)
}

// TestCABundle_EmptyBundle exercises the "buf.Len() == 0" guard by zeroing
// both cached certificates after initialization.
func TestCABundle_EmptyBundle_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	ca.mu.Lock()
	orig := ca.rootCert
	ca.rootCert = nil
	ca.intermediateCert = nil
	ca.mu.Unlock()
	defer func() {
		ca.mu.Lock()
		ca.rootCert = orig
		ca.mu.Unlock()
	}()

	_, err := ca.CABundle()
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

// =============================================================================
// ca.go — Load: success with intermediate, and key-not-found error
// =============================================================================

// TestLoad_WithIntermediate exercises the HasIntermediate() branch (lines 620-639)
// in Load by first calling Init to persist certs then Load on a fresh CA instance.
func TestLoad_WithIntermediate_B9(t *testing.T) {
	t.Parallel()

	backend, cs := newB9Backend(t)
	config := DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = "Load Root B9"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[1].Subject.CommonName = "Load Intermediate B9"
	config.Identity[1].Keys[0].KeyType = "CA"

	// Init: persists root + intermediate certs to cs.
	initCA := &CA{
		config:          config,
		keyStore:        backend,
		keystoreMap:     map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:       cs,
		revocationStore: storage.NewMemory(),
		revocations:     make(map[string]*RevocationInfo),
		serialGen:       NewSerialGenerator(NewMemoryStorage()),
		profiles:        NewDefaultProfileRegistry(),
	}
	require.NoError(t, initCA.Init(context.Background()))

	// Load: re-open using same backend/certstore (keys already exist).
	loadCA := &CA{
		config:          config,
		keyStore:        backend,
		keystoreMap:     map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:       cs,
		revocationStore: storage.NewMemory(),
		revocations:     make(map[string]*RevocationInfo),
		serialGen:       NewSerialGenerator(NewMemoryStorage()),
		profiles:        NewDefaultProfileRegistry(),
	}
	err := loadCA.Load(context.Background())
	require.NoError(t, err)
	assert.True(t, loadCA.IsInitialized())
	assert.NotNil(t, loadCA.intermediateCert)
}

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

// TestGetOrGenerateCAKey_Ed25519_B9 exercises the Ed25519 branch in
// getOrGenerateCAKey (line 923) via the full CA init path.
func TestGetOrGenerateCAKey_Ed25519_B9(t *testing.T) {
	t.Parallel()
	ca := setupEd25519CA(t)
	assert.NotNil(t, ca.rootCert)
	assert.Equal(t, x509.PureEd25519, ca.rootCert.SignatureAlgorithm)
}

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
// ca.go — createRootCertificate: SANS + CRL/OCSP/AIA URL branches
// =============================================================================

// TestCreateRootCertificate_WithSANsAndURLs_B9 exercises the SANS, CRL, OCSP,
// and AIA URL branches (lines 990-1006) inside createRootCertificate.
func TestCreateRootCertificate_WithSANsAndURLs_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "SANsURLs Root B9"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[0].SANS = &SubjectAlternativeNames{
		DNS:   []string{"root-b9.example.com"},
		Email: []string{"ca@example.com"},
	}
	config.Identity[0].CRLDistributionPoints = []string{"http://crl.example.com/root.crl"}
	config.Identity[0].OCSPServers = []string{"http://ocsp.example.com"}
	config.Identity[0].IssuingCertificateURLs = []string{"http://aia.example.com/root.crt"}

	// Use the direct CA struct with the multi-identity config so that
	// createRootCertificate reads SANS and URL fields from rootIdentity.
	ca := &CA{
		config:      config,
		keyStore:    backend,
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init(context.Background()))

	root := ca.rootCert
	require.NotNil(t, root)
	assert.NotEmpty(t, root.DNSNames)
	assert.NotEmpty(t, root.EmailAddresses)
	assert.NotEmpty(t, root.CRLDistributionPoints)
	assert.NotEmpty(t, root.OCSPServer)
	assert.NotEmpty(t, root.IssuingCertificateURL)
}

// =============================================================================
// constructors.go — NewCA: single-identity (root only) and two-identity paths
// =============================================================================

// TestNewCA_RootOnly_B9 exercises the len(params.Identity)==1 early return path.
func TestNewCA_RootOnly_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := DefaultMultiIdentityCAConfig()
	cfg.Identity[0].Subject.CommonName = "NewCA Root Only B9"
	cfg.Identity[0].Keys[0].KeyType = "CA"

	params := &Params{
		Identity:        cfg.Identity,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
	}
	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	assert.NotNil(t, root)
	assert.Nil(t, intermediate)
	assert.True(t, root.IsInitialized())
}

// TestNewCA_WithIntermediate_B9 exercises the full NewCA path with two identities.
func TestNewCA_WithIntermediate_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := DefaultMultiIdentityCAConfigWithIntermediate()
	cfg.Identity[0].Subject.CommonName = "NewCA Root B9"
	cfg.Identity[0].Keys[0].KeyType = "CA"
	cfg.Identity[1].Subject.CommonName = "NewCA Intermediate B9"
	cfg.Identity[1].Keys[0].KeyType = "CA"

	params := &Params{
		Identity:        cfg.Identity,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
	}
	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	assert.NotNil(t, root)
	assert.NotNil(t, intermediate)
	assert.True(t, root.IsInitialized())
	assert.True(t, intermediate.IsInitialized())
}

// TestNewCA_NilParams_B9 exercises the nil params guard.
func TestNewCA_NilParams_B9(t *testing.T) {
	t.Parallel()
	_, _, err := NewCA(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestNewCA_NoIdentity_B9 exercises the empty-identity guard.
func TestNewCA_NoIdentity_B9(t *testing.T) {
	t.Parallel()
	_, _, err := NewCA(context.Background(), &Params{})
	assert.ErrorIs(t, err, ErrNoIdentity)
}

// =============================================================================
// constructors.go — NewIntermediateCA error paths
// =============================================================================

// TestNewIntermediateCA_NilParams_B9 exercises nil params guard.
func TestNewIntermediateCA_NilParams_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := NewIntermediateCA(context.Background(), nil, ca)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestNewIntermediateCA_NilParent_B9 exercises nil parent guard.
func TestNewIntermediateCA_NilParent_B9(t *testing.T) {
	t.Parallel()
	cfg := DefaultMultiIdentityCAConfigWithIntermediate()
	_, err := NewIntermediateCA(context.Background(), &Params{Identity: cfg.Identity}, nil)
	assert.ErrorIs(t, err, ErrParentCARequired)
}

// TestNewIntermediateCA_UninitParent_B9 exercises uninitialized parent guard.
func TestNewIntermediateCA_UninitParent_B9(t *testing.T) {
	t.Parallel()
	uninit := setupUninitializedCA(t)
	cfg := DefaultMultiIdentityCAConfigWithIntermediate()
	_, err := NewIntermediateCA(context.Background(), &Params{Identity: cfg.Identity}, uninit)
	assert.ErrorIs(t, err, ErrParentCANotInitialized)
}

// TestNewIntermediateCA_NoIntermediateIdentity_B9 exercises the len(Identity)<2 guard.
func TestNewIntermediateCA_NoIntermediateIdentity_B9(t *testing.T) {
	t.Parallel()
	root := setupTestCA(t)
	cfg := DefaultMultiIdentityCAConfig()
	_, err := NewIntermediateCA(context.Background(), &Params{Identity: cfg.Identity}, root)
	assert.ErrorIs(t, err, ErrNoIntermediateIdentity)
}

// =============================================================================
// constructors.go — NewParentCA error paths
// =============================================================================

// TestNewParentCA_NilParams_B9 exercises nil params guard.
func TestNewParentCA_NilParams_B9(t *testing.T) {
	t.Parallel()
	_, err := NewParentCA(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestNewParentCA_NoIdentity_B9 exercises empty identity guard.
func TestNewParentCA_NoIdentity_B9(t *testing.T) {
	t.Parallel()
	_, err := NewParentCA(&Params{})
	assert.ErrorIs(t, err, ErrNoIdentity)
}

// TestNewParentCA_Success_B9 exercises the full happy path of NewParentCA.
func TestNewParentCA_Success_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := DefaultMultiIdentityCAConfig()
	cfg.Identity[0].Subject.CommonName = "NewParentCA Root B9"
	cfg.Identity[0].Keys[0].KeyType = "CA"

	params := &Params{
		Identity:        cfg.Identity,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       NewSerialGenerator(NewMemoryStorage()),
	}
	root, err := NewParentCA(params)
	require.NoError(t, err)
	assert.NotNil(t, root)
	// Not initialized yet (caller must call Init).
	assert.False(t, root.IsInitialized())

	require.NoError(t, root.Init(context.Background()))
	assert.True(t, root.IsInitialized())
}

// =============================================================================
// constructors.go — ResolveStores: factory-based paths
// =============================================================================

// TestResolveStores_KeyStoreFactory_B9 exercises the KeyStoreFactory branch.
func TestResolveStores_KeyStoreFactory_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	p := &Params{
		KeyStoreFactory: func(cn string) (xkms.Backend, error) {
			return backend, nil
		},
		CertStore: cs,
	}
	ks, retCS, retOS, err := p.ResolveStores("test-b9")
	require.NoError(t, err)
	assert.Equal(t, backend, ks)
	assert.Equal(t, cs, retCS)
	assert.Nil(t, retOS)
}

// TestResolveStores_KeyStoreFactoryError_B9 exercises a factory returning error.
func TestResolveStores_KeyStoreFactoryError_B9(t *testing.T) {
	t.Parallel()
	_, cs := newB9Backend(t)

	p := &Params{
		KeyStoreFactory: func(cn string) (xkms.Backend, error) {
			return nil, errors.New("factory failure")
		},
		CertStore: cs,
	}
	_, _, _, err := p.ResolveStores("test-b9")
	require.Error(t, err)
}

// TestResolveStores_KeyStoreFactoryNil_B9 exercises factory returning nil backend.
func TestResolveStores_KeyStoreFactoryNil_B9(t *testing.T) {
	t.Parallel()
	_, cs := newB9Backend(t)

	p := &Params{
		KeyStoreFactory: func(cn string) (xkms.Backend, error) {
			return nil, nil // nil store: must error
		},
		CertStore: cs,
	}
	_, _, _, err := p.ResolveStores("test-b9")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStoreFactoryReturnedNil)
}

// TestResolveStores_CertStoreFactory_B9 exercises the CertStoreFactory branch.
func TestResolveStores_CertStoreFactory_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	p := &Params{
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStoreFactory: func(cn string) (certstore.CertStore, error) {
			return cs, nil
		},
	}
	_, retCS, _, err := p.ResolveStores("test-b9")
	require.NoError(t, err)
	assert.Equal(t, cs, retCS)
}

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

// TestResolveStores_ObjectStoreFactory_B9 exercises the ObjectStoreFactory branch.
func TestResolveStores_ObjectStoreFactory_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	objStore := qrdbsdk.NewMemoryStorage()

	p := &Params{
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		ObjectStoreFactory: ObjectStoreFactoryFunc(func(cn string) (qrdbsdk.Storage, error) {
			return objStore, nil
		}),
	}
	_, _, retOS, err := p.ResolveStores("test-b9")
	require.NoError(t, err)
	assert.Equal(t, objStore, retOS)
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

// TestImportXSignedCertificate_Success_B9 exercises ImportXSignedCertificate.
func TestImportXSignedCertificate_Success_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

	cert, _ := b9MakeSelfSignedCACert(t, "xsigned-import-b9")
	err := ca.ImportXSignedCertificate("issuer-b9", cert)
	require.NoError(t, err)
}

// TestImportXSignedCertificate_NoObjectStore_B9 exercises ErrObjectStoreRequired.
func TestImportXSignedCertificate_NoObjectStore_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = nil

	cert, _ := b9MakeSelfSignedCACert(t, "xsigned-nostore-b9")
	err := ca.ImportXSignedCertificate("issuer-b9", cert)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// TestImportXSignedCertificate_EmptyIssuer_B9 exercises empty issuerCN guard.
func TestImportXSignedCertificate_EmptyIssuer_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

	cert, _ := b9MakeSelfSignedCACert(t, "xsigned-emptyissuer-b9")
	err := ca.ImportXSignedCertificate("", cert)
	require.Error(t, err)
}

// TestImportXSignedCertificate_NilCert_B9 exercises nil cert guard.
func TestImportXSignedCertificate_NilCert_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

	err := ca.ImportXSignedCertificate("issuer-b9", nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// TestXSignedRootCertificate_SelfSigned_B9 exercises the early return when
// cert is already self-signed (Issuer == Subject).
func TestXSignedRootCertificate_SelfSigned_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

	cert, _ := b9MakeSelfSignedCACert(t, "xroot-selfsigned-b9")
	got, err := ca.XSignedRootCertificate("issuer-b9", cert)
	require.NoError(t, err)
	assert.Equal(t, cert, got)
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

// TestXSignedIntermediateCertificates_Empty_B9 exercises XSignedIntermediateCertificates
// when the chain lookup immediately fails (no cross-signed certs in store).
func TestXSignedIntermediateCertificates_Empty_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

	// Manufacture a non-self-signed cert (Issuer != Subject) so the loop runs.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	childTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xint-child-b9"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	parentTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject:      pkix.Name{CommonName: "xint-parent-b9"},
	}
	der, err := x509.CreateCertificate(rand.Reader, childTmpl, parentTmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	ints, err := ca.XSignedIntermediateCertificates("issuer-b9", cert)
	require.NoError(t, err)
	assert.Empty(t, ints)
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

// TestCrossSignedPEM_NilAttrs_B9 exercises nil attrs guard in CrossSignedPEM.
func TestCrossSignedPEM_NilAttrs_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

	_, err := ca.CrossSignedPEM(nil)
	require.Error(t, err)
}

// TestCrossSignedPEM_NoObjectStore_B9 exercises ErrObjectStoreRequired in CrossSignedPEM.
func TestCrossSignedPEM_NoObjectStore_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = nil

	attrs := &types.KeyAttributes{CN: "some-cn-b9"}
	_, err := ca.CrossSignedPEM(attrs)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// TestCrossSignedPEM_NotFound_B9 exercises the "bundle is empty" error path.
func TestCrossSignedPEM_NotFound_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage() // empty store

	attrs := &types.KeyAttributes{CN: "missing-cn-b9"}
	_, err := ca.CrossSignedPEM(attrs)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// TestCrossSignedPEM_Found_B9 exercises the successful bundle-building path.
func TestCrossSignedPEM_Found_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

	subjectCN := "crosssignedpem-subject-b9"
	cert, _ := b9MakeSelfSignedCACert(t, subjectCN)
	require.NoError(t, ca.ImportXSignedCertificate("issuer-b9", cert))

	attrs := &types.KeyAttributes{CN: subjectCN}
	bundle, err := ca.CrossSignedPEM(attrs)
	require.NoError(t, err)
	assert.NotEmpty(t, bundle)
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
		Subject: Subject{CommonName: "default-fallback-b9"},
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
// ca.go — createIntermediateCertificates: SANS + URL branches in intermediate
// =============================================================================

// TestCreateIntermediateCertificates_WithSANsAndURLs_B9 exercises the SANS,
// CRL, OCSP, AIA URL branches in createSingleIntermediateCertificate by
// configuring an intermediate identity with those fields set.
func TestCreateIntermediateCertificates_WithSANsAndURLs_B9(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	config := DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = "SANsInt Root B9"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[1].Subject.CommonName = "SANsInt Intermediate B9"
	config.Identity[1].Keys[0].KeyType = "CA"
	config.Identity[1].SANS = &SubjectAlternativeNames{
		DNS: []string{"intermediate-b9.example.com"},
	}
	config.Identity[1].CRLDistributionPoints = []string{"http://crl.example.com/int.crl"}
	config.Identity[1].OCSPServers = []string{"http://ocsp.example.com"}
	config.Identity[1].IssuingCertificateURLs = []string{"http://aia.example.com/int.crt"}

	ca := &CA{
		config:      config,
		keyStore:    backend,
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init(context.Background()))
	require.NotNil(t, ca.intermediateCert)
	assert.NotEmpty(t, ca.intermediateCert.DNSNames)
	assert.NotEmpty(t, ca.intermediateCert.CRLDistributionPoints)
	assert.NotEmpty(t, ca.intermediateCert.OCSPServer)
	assert.NotEmpty(t, ca.intermediateCert.IssuingCertificateURL)
}

// =============================================================================
// ca.go — GenerateCRL: issuingCert==nil path
// =============================================================================

// TestGenerateCRL_NoIssuingCert_B9 exercises the issuingCert==nil guard by
// zeroing the root cert after initialization.
func TestGenerateCRL_NoIssuingCert_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	ca.mu.Lock()
	orig := ca.rootCert
	ca.rootCert = nil
	ca.intermediateCert = nil
	ca.mu.Unlock()
	defer func() {
		ca.mu.Lock()
		ca.rootCert = orig
		ca.mu.Unlock()
	}()

	_, err := ca.GenerateCRL(context.Background())
	assert.ErrorIs(t, err, ErrCRLGenerationFailed)
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

// =============================================================================
// ca_extensions.go — CABundle filtered: storeType mismatch path
// =============================================================================

// TestCAKeyAttributes_StoreTypeMismatch_B9 exercises the mismatch guard in
// CAKeyAttributes (lines 448-451) where storeType != configured type.
func TestCAKeyAttributes_StoreTypeMismatch_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	// The CA is configured with StoreSoftware; request TPM2 to trigger mismatch.
	_, err := ca.CAKeyAttributes(types.StoreTPM2)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidStoreType)
}

// TestCASigner_AlgorithmMismatch_B9 exercises the algorithm mismatch guard in
// CASigner (lines 470-473).
func TestCASigner_AlgorithmMismatch_B9(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	// The CA has an ECDSA key; request RSA to trigger the mismatch.
	_, err := ca.CASigner(context.Background(), types.StoreSoftware, x509.RSA)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
}

// =============================================================================
// ca_extensions.go — loadPersistedRevocations: invalid serial string path
// =============================================================================

// TestLoadPersistedRevocations_InvalidSerial_B9 proves a record whose serial
// cannot be parsed fails the load with ErrRevocationRecordCorrupt naming the
// key, rather than being skipped (which would silently un-revoke it).
func TestLoadPersistedRevocations_InvalidSerial_B9(t *testing.T) {
	t.Parallel()
	backend := storage.NewMemory()
	ca := &CA{
		revocationStore: backend,
		revocations:     make(map[string]*RevocationInfo),
	}
	// Store a record with a non-numeric serial that SetString will reject.
	badJSON := []byte(`{"serial":"not-a-number","reason":0,"revoked_at":"2024-01-01T00:00:00Z"}`)
	key := revocationKeyPrefix + "bad-serial.json"
	require.NoError(t, backend.Put(context.Background(), key, badJSON))

	err := ca.loadPersistedRevocations(context.Background())
	require.ErrorIs(t, err, ErrRevocationRecordCorrupt)
	assert.Contains(t, err.Error(), key)
	assert.Empty(t, ca.revocations)
}
