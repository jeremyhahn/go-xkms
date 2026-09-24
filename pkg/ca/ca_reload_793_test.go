// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ca

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// go-xkms#793 -- Load must resolve KeyAttributes the same way Init did
// =============================================================================
//
// Init resolves an identity's key attributes through getCAKeyAttributes,
// which defaults KeyType to KeyTypeCA when the identity's KeyConfig leaves
// key-type unset. Before this fix, Load called the identity's bare
// ToKeyAttributes directly and skipped that default, so a root identity
// whose KeyConfig never set key-type produced a KeyAttributes.Validate
// failure ("key type is required") on every Load -- never a genuine
// not-found -- and pkg/server's initializeCA treated that failure exactly
// like "never initialized" and called Init again, minting a brand new
// self-signed root certificate on every restart.

// setupTestCAWithoutExplicitKeyType is setupTestCA (service_adapter_test.go)
// minus the `Keys[0].KeyType = "CA"` line: it reproduces a CA identity whose
// KeyConfig never sets key-type explicitly, exactly the shape of the shipped
// xkmsd-integration.yaml root identity absent that field, matching the
// go-xkms#793 report. The backends and stores are returned alongside the
// initialized CA so a second, independent *CA can be built over the same
// durable state to exercise Load.
func setupTestCAWithoutExplicitKeyType(t *testing.T) (initialized *CA, keyStorage, certStorage storage.Backend) {
	t.Helper()

	keyStorage = storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)

	certStorage = storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)

	certAdapter := storage.NewCertAdapter(storage.NewMemory())
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "793 Root CA"
	config.Identity[0].Subject.Organization = "Test Organization"
	// Deliberately NOT setting config.Identity[0].Keys[0].KeyType: this is
	// the exact condition go-xkms#793 reproduces.

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:          config,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.NoError(t, err)
	require.NoError(t, caIface.Init(context.Background()))

	concrete, ok := caIface.(*CA)
	require.True(t, ok)
	return concrete, keyStorage, certStorage
}

// TestCA_Load_AfterInit_KeyTypeOmittedFromConfig is the go-xkms#793
// regression: a second *CA instance sharing the same durable key and
// certificate storage as an already-initialized CA whose identity never set
// key-type must Load successfully -- not fail with a KeyAttributes
// validation error that pkg/server's initializeCA would otherwise mistake
// for "not yet initialized" and paper over with a brand new root.
func TestCA_Load_AfterInit_KeyTypeOmittedFromConfig(t *testing.T) {
	ca1, keyStorage, certStorage := setupTestCAWithoutExplicitKeyType(t)
	cert1, err := ca1.CACertificate()
	require.NoError(t, err)

	// A fresh *CA over the identical durable stores and config, modeling a
	// second `xkmsd run` over the same data directory.
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	ca2 := &CA{
		keyStore:        backend,
		keystoreMap:     ca1.keystoreMap,
		certStore:       ca1.certStore,
		config:          ca1.config,
		revocationStore: ca1.revocationStore,
		revocations:     make(map[string]*RevocationInfo),
	}

	err = ca2.Load(context.Background())
	require.NoError(t, err, "Load must succeed over the same durable state Init wrote, even when key-type was never set explicitly")
	assert.True(t, ca2.IsInitialized())

	cert2, err := ca2.CACertificate()
	require.NoError(t, err)
	assert.Equal(t, cert1.SerialNumber, cert2.SerialNumber, "Load must resolve the exact certificate Init stored, not mint a new one")
	assert.Equal(t, cert1.RawSubjectPublicKeyInfo, cert2.RawSubjectPublicKeyInfo, "Load must resolve the same key Init generated")
}

// TestCA_Load_NeverInitialized_ReturnsErrCertificateNotFound proves the one
// Load failure that legitimately means "never initialized": an empty
// certificate store. pkg/server's initializeCA keys its Load-vs-Init
// decision on errors.Is(err, ca.ErrCertificateNotFound); this is the
// positive case for that contract.
func TestCA_Load_NeverInitialized_ReturnsErrCertificateNotFound(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	certAdapter := storage.NewCertAdapter(storage.NewMemory())
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "793 Never Initialized Root CA"
	config.Identity[0].Keys[0].KeyType = "CA"

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:          config,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.NoError(t, err)

	err = caIface.Load(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCertificateNotFound),
		"an empty store must fail Load with the one sentinel initializeCA treats as \"proceed to Init\", got %v", err)
}

// TestCA_Load_CorruptPersistedCertificate_DoesNotReportNotFound proves the
// other half of the go-xkms#793 contract: a persisted root certificate that
// exists but cannot be parsed (damaged storage, truncated write, bit rot)
// must fail Load with an error that does NOT satisfy
// errors.Is(err, ErrCertificateNotFound). initializeCA's Load-vs-Init
// decision keys on that sentinel; a corrupt record wrongly classified as
// "not found" would make initializeCA silently mint a brand new CA over
// existing, merely-damaged state instead of failing startup closed.
func TestCA_Load_CorruptPersistedCertificate_DoesNotReportNotFound(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "793 Corrupt Root CA"
	config.Identity[0].Keys[0].KeyType = "CA"

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:          config,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.NoError(t, err)
	require.NoError(t, caIface.Init(context.Background()))

	// Damage the persisted root certificate record directly, in place --
	// modeling bit rot or a truncated write, not a missing key.
	require.NoError(t, certAdapterStorage.Put(context.Background(),
		storage.CertPath(config.Identity[0].Subject.CommonName), []byte("not a certificate")))

	ca2 := &CA{
		keyStore:        backend,
		keystoreMap:     caIface.(*CA).keystoreMap,
		certStore:       cs,
		config:          config,
		revocationStore: storage.NewMemory(),
		revocations:     make(map[string]*RevocationInfo),
	}

	err = ca2.Load(context.Background())
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrCertificateNotFound),
		"a corrupt persisted certificate must not be classified as not-found, got %v", err)
}
