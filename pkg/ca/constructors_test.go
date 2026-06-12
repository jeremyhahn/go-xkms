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

package ca

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newInMemoryBackend builds an xkms.Backend backed by in-memory software
// storage. Each call produces a fresh, isolated backend.
func newInMemoryBackend(t *testing.T) xkms.Backend {
	t.Helper()
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)
	return backend
}

// newInMemoryCertStore builds an in-memory CertStore.
func newInMemoryCertStore(t *testing.T) certstore.CertStore {
	t.Helper()
	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(storage.NewMemory()),
	})
	require.NoError(t, err)
	return cs
}

// rootIdentity builds a valid root CA Identity with the given CN and ECDSA
// P-256 key configuration.
func rootIdentity(cn string) Identity {
	return Identity{
		Subject: Subject{CommonName: cn, Organization: "Test Org"},
		Valid:   DefaultRootValidityYears,
		Keys: []*types.KeyConfig{
			{
				KeyAlgorithm:       types.AlgorithmECDSA,
				Hash:               types.HashSHA256,
				SignatureAlgorithm: types.SigECDSAWithSHA256,
				StoreType:          types.StoreSoftware,
				ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
				KeyType:            "CA",
			},
		},
		KeystoreType:  types.StoreSoftware,
		IsRoot:        true,
		MaxPathLength: 1,
	}
}

// intermediateIdentity builds a valid intermediate CA Identity.
func intermediateIdentity(cn, parentCN string) Identity {
	return Identity{
		Subject: Subject{CommonName: cn, Organization: "Test Org"},
		Valid:   DefaultIntermediateValidityYears,
		Keys: []*types.KeyConfig{
			{
				KeyAlgorithm:       types.AlgorithmECDSA,
				Hash:               types.HashSHA256,
				SignatureAlgorithm: types.SigECDSAWithSHA256,
				StoreType:          types.StoreSoftware,
				ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
				KeyType:            "CA",
			},
		},
		KeystoreType:      types.StoreSoftware,
		IsRoot:            false,
		ParentCA:          parentCN,
		MaxPathLengthZero: true,
	}
}

// =============================================================================
// NewCA
// =============================================================================

func TestNewCA_RootOnly(t *testing.T) {
	params := &Params{
		Identity:  []Identity{rootIdentity("Root Only CA")},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}

	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, root)
	assert.Nil(t, intermediate)
	assert.True(t, root.IsInitialized())
	assert.Equal(t, "Root Only CA", root.(*CA).Identity())

	cert, err := root.CACertificate()
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "Root Only CA", cert.Subject.CommonName)
	// Root is self-signed.
	assert.Equal(t, cert.Subject.String(), cert.Issuer.String())
}

func TestNewCA_RootAndIntermediate(t *testing.T) {
	params := &Params{
		Identity: []Identity{
			rootIdentity("Root+Int Root"),
			intermediateIdentity("Root+Int Intermediate", "Root+Int Root"),
		},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}

	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, root)
	require.NotNil(t, intermediate)
	assert.True(t, root.IsInitialized(), "root should be initialized")
	assert.True(t, intermediate.IsInitialized(), "intermediate should be initialized")

	rootCert, err := root.CACertificate()
	require.NoError(t, err)
	intCert, err := intermediate.CACertificate()
	require.NoError(t, err)

	// Intermediate is issued by the root.
	assert.Equal(t, rootCert.Subject.String(), intCert.Issuer.String())
	assert.Equal(t, "Root+Int Intermediate", intCert.Subject.CommonName)
	assert.True(t, intCert.IsCA)
}

func TestNewCA_NilParams(t *testing.T) {
	_, _, err := NewCA(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewCA_EmptyIdentity(t *testing.T) {
	_, _, err := NewCA(context.Background(), &Params{
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	})
	assert.ErrorIs(t, err, ErrNoIdentity)
}

// =============================================================================
// NewParentCA
// =============================================================================

func TestNewParentCA_ValidatesIdentity(t *testing.T) {
	_, err := NewParentCA(&Params{
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	})
	assert.ErrorIs(t, err, ErrNoIdentity)
}

func TestNewParentCA_NilParams(t *testing.T) {
	_, err := NewParentCA(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewParentCA_ReturnsUninitialized(t *testing.T) {
	params := &Params{
		Identity:  []Identity{rootIdentity("Uninit Root")},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}
	root, err := NewParentCA(params)
	require.NoError(t, err)
	require.NotNil(t, root)
	// NewParentCA must NOT initialize; that is the caller's responsibility.
	assert.False(t, root.IsInitialized())

	require.NoError(t, root.Init(context.Background()))
	assert.True(t, root.IsInitialized())
}

// =============================================================================
// NewIntermediateCA
// =============================================================================

func TestNewIntermediateCA_RequiresParentInitialized(t *testing.T) {
	params := &Params{
		Identity: []Identity{
			rootIdentity("Uninit Parent"),
			intermediateIdentity("Intermediate", "Uninit Parent"),
		},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}
	root, err := NewParentCA(params)
	require.NoError(t, err)
	require.False(t, root.IsInitialized())

	_, err = NewIntermediateCA(context.Background(), params, root)
	assert.ErrorIs(t, err, ErrParentCANotInitialized)
}

func TestNewIntermediateCA_RequiresParent(t *testing.T) {
	params := &Params{
		Identity: []Identity{
			rootIdentity("R"),
			intermediateIdentity("I", "R"),
		},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}
	_, err := NewIntermediateCA(context.Background(), params, nil)
	assert.ErrorIs(t, err, ErrParentCARequired)
}

func TestNewIntermediateCA_RequiresIntermediateIdentity(t *testing.T) {
	params := &Params{
		Identity:  []Identity{rootIdentity("Solo Root")},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}
	root, err := NewParentCA(params)
	require.NoError(t, err)
	require.NoError(t, root.Init(context.Background()))

	_, err = NewIntermediateCA(context.Background(), params, root)
	assert.ErrorIs(t, err, ErrNoIntermediateIdentity)
}

// =============================================================================
// Factory resolution
// =============================================================================

func TestNewCA_FactoryResolution(t *testing.T) {
	var (
		keyCalls  []string
		certCalls []string
	)

	rootKS := newInMemoryBackend(t)
	intKS := newInMemoryBackend(t)
	rootCS := newInMemoryCertStore(t)
	intCS := newInMemoryCertStore(t)

	keyFactory := func(cn string) (xkms.Backend, error) {
		keyCalls = append(keyCalls, cn)
		switch cn {
		case "FactoryRoot":
			return rootKS, nil
		case "FactoryIntermediate":
			return intKS, nil
		}
		return nil, errors.New("unexpected cn: " + cn)
	}
	certFactory := func(cn string) (certstore.CertStore, error) {
		certCalls = append(certCalls, cn)
		switch cn {
		case "FactoryRoot":
			return rootCS, nil
		case "FactoryIntermediate":
			return intCS, nil
		}
		return nil, errors.New("unexpected cn: " + cn)
	}

	params := &Params{
		Identity: []Identity{
			rootIdentity("FactoryRoot"),
			intermediateIdentity("FactoryIntermediate", "FactoryRoot"),
		},
		KeyStoreFactory:  keyFactory,
		CertStoreFactory: certFactory,
	}

	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, root)
	require.NotNil(t, intermediate)

	// Each factory should have been invoked for each CA's CN.
	assert.Contains(t, keyCalls, "FactoryRoot")
	assert.Contains(t, keyCalls, "FactoryIntermediate")
	assert.Contains(t, certCalls, "FactoryRoot")
	assert.Contains(t, certCalls, "FactoryIntermediate")

	// Root cert should be in the root's certstore, intermediate cert in the
	// intermediate's certstore. This proves per-CA store routing.
	rootCert, err := rootCS.GetCertificate("FactoryRoot")
	require.NoError(t, err)
	assert.Equal(t, "FactoryRoot", rootCert.Subject.CommonName)

	intCert, err := intCS.GetCertificate("FactoryIntermediate")
	require.NoError(t, err)
	assert.Equal(t, "FactoryIntermediate", intCert.Subject.CommonName)
	assert.Equal(t, "FactoryRoot", intCert.Issuer.CommonName)
}

func TestNewCA_FactoryError(t *testing.T) {
	sentinel := errors.New("boom")
	params := &Params{
		Identity: []Identity{rootIdentity("Errored")},
		KeyStoreFactory: func(cn string) (xkms.Backend, error) {
			return nil, sentinel
		},
		CertStore: newInMemoryCertStore(t),
	}
	_, _, err := NewCA(context.Background(), params)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
}

func TestNewCA_FactoryReturnsNil(t *testing.T) {
	params := &Params{
		Identity: []Identity{rootIdentity("Niled")},
		KeyStoreFactory: func(cn string) (xkms.Backend, error) {
			return nil, nil
		},
		CertStore: newInMemoryCertStore(t),
	}
	_, _, err := NewCA(context.Background(), params)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStoreFactoryReturnedNil)
}

// =============================================================================
// Shared stores (no factories)
// =============================================================================

func TestNewCA_SharedStores(t *testing.T) {
	sharedKS := newInMemoryBackend(t)
	sharedCS := newInMemoryCertStore(t)

	params := &Params{
		Identity: []Identity{
			rootIdentity("Shared Root"),
			intermediateIdentity("Shared Intermediate", "Shared Root"),
		},
		KeyStore:  sharedKS,
		CertStore: sharedCS,
	}

	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, root)
	require.NotNil(t, intermediate)

	// Both certs should live in the single shared certstore.
	rootCert, err := sharedCS.GetCertificate("Shared Root")
	require.NoError(t, err)
	assert.Equal(t, "Shared Root", rootCert.Subject.CommonName)

	intCert, err := sharedCS.GetCertificate("Shared Intermediate")
	require.NoError(t, err)
	assert.Equal(t, "Shared Intermediate", intCert.Subject.CommonName)
	assert.Equal(t, "Shared Root", intCert.Issuer.CommonName)
}

// =============================================================================
// ResolveStores
// =============================================================================

func TestResolveStores_MissingKeyStore(t *testing.T) {
	p := &Params{CertStore: newInMemoryCertStore(t)}
	_, _, _, err := p.ResolveStores("nope")
	assert.ErrorIs(t, err, ErrKeyStoreRequired)
}

func TestResolveStores_MissingCertStore(t *testing.T) {
	p := &Params{KeyStore: newInMemoryBackend(t)}
	_, _, _, err := p.ResolveStores("nope")
	assert.ErrorIs(t, err, ErrCertStoreRequired)
}

func TestResolveStores_SharedPath(t *testing.T) {
	ks := newInMemoryBackend(t)
	cs := newInMemoryCertStore(t)
	p := &Params{KeyStore: ks, CertStore: cs}
	gotKS, gotCS, gotOS, err := p.ResolveStores("any")
	require.NoError(t, err)
	assert.Same(t, ks, gotKS)
	assert.Same(t, cs, gotCS)
	assert.Nil(t, gotOS)
}

// =============================================================================
// IssuingIdentity multi-key preservation
// =============================================================================

// multiKeyIdentity builds a root Identity with three KeyConfig entries
// (ECDSA, RSA, Ed25519) for algorithm-agility testing. The ECDSA entry is
// the active signing key; the other two are advertised via IssuingIdentity()
// so consumers such as the ACME admin status endpoint can list the full key
// slice.
func multiKeyIdentity(cn string) Identity {
	keys := []*types.KeyConfig{
		{
			KeyAlgorithm:       types.AlgorithmECDSA,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigECDSAWithSHA256,
			StoreType:          types.StoreSoftware,
			ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
			KeyType:            "CA",
		},
		{
			KeyAlgorithm:       types.AlgorithmRSA,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigSHA256WithRSA,
			StoreType:          types.StoreSoftware,
			RSAConfig:          &types.RSAConfig{KeySize: 2048},
			KeyType:            "CA",
		},
		{
			KeyAlgorithm:       types.AlgorithmEd25519,
			Hash:               types.HashSHA256,
			SignatureAlgorithm: types.SigEd25519,
			StoreType:          types.StoreSoftware,
			KeyType:            "CA",
		},
	}
	return Identity{
		Subject:       Subject{CommonName: cn, Organization: "Multi-Key Org"},
		Valid:         DefaultRootValidityYears,
		Keys:          keys,
		KeystoreType:  types.StoreSoftware,
		IsRoot:        true,
		MaxPathLength: 1,
	}
}

// TestIssuingIdentity_PreservesMultiKeySlice asserts that a 3-key Identity
// round-trips through NewParentCA -> IssuingIdentity() without losing any
// entries. Historically caConfigFromIdentity built a flat CAConfig that
// dropped every Keys[i>0], so IssuingIdentity() surfaced only the active
// key. The fix is the inputIdentity field on *CA: NewParentCA /
// NewIntermediateCA set it on the returned instance, and IssuingIdentity()
// returns it verbatim when non-nil.
func TestIssuingIdentity_PreservesMultiKeySlice(t *testing.T) {
	root := multiKeyIdentity("Multi-Key Root")
	params := &Params{
		Identity:  []Identity{root},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}

	instance, err := NewParentCA(params)
	require.NoError(t, err)

	caInstance, ok := instance.(*CA)
	require.True(t, ok, "NewParentCA must return *CA")
	require.NotNil(t, caInstance.inputIdentity, "inputIdentity must be populated for multi-identity constructors")

	issuing := caInstance.IssuingIdentity()
	require.Len(t, issuing.Keys, 3, "IssuingIdentity must preserve all 3 KeyConfig entries")

	assert.Equal(t, types.AlgorithmECDSA, issuing.Keys[0].KeyAlgorithm)
	assert.Equal(t, types.AlgorithmRSA, issuing.Keys[1].KeyAlgorithm)
	assert.Equal(t, types.AlgorithmEd25519, issuing.Keys[2].KeyAlgorithm)

	assert.Equal(t, "Multi-Key Root", issuing.Subject.CommonName)
	assert.True(t, issuing.IsRoot)
}

// TestIssuingIdentity_PreservesMultiKeySlice_Intermediate asserts the same
// preservation applies to the intermediate returned by NewIntermediateCA
// (via NewCA). The intermediate's active key is ECDSA but the full 3-key
// slice must survive so algorithm-agility callers can discover RSA / Ed25519.
func TestIssuingIdentity_PreservesMultiKeySlice_Intermediate(t *testing.T) {
	root := multiKeyIdentity("MKI Root")
	intermediate := multiKeyIdentity("MKI Intermediate")
	intermediate.IsRoot = false
	intermediate.ParentCA = "MKI Root"
	intermediate.MaxPathLengthZero = true
	intermediate.Valid = DefaultIntermediateValidityYears

	params := &Params{
		Identity:  []Identity{root, intermediate},
		KeyStore:  newInMemoryBackend(t),
		CertStore: newInMemoryCertStore(t),
	}

	_, intInstance, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, intInstance)

	caInt, ok := intInstance.(*CA)
	require.True(t, ok)
	require.NotNil(t, caInt.inputIdentity)

	issuing := caInt.IssuingIdentity()
	require.Len(t, issuing.Keys, 3)
	assert.Equal(t, types.AlgorithmECDSA, issuing.Keys[0].KeyAlgorithm)
	assert.Equal(t, types.AlgorithmRSA, issuing.Keys[1].KeyAlgorithm)
	assert.Equal(t, types.AlgorithmEd25519, issuing.Keys[2].KeyAlgorithm)
	assert.Equal(t, "MKI Intermediate", issuing.Subject.CommonName)
	assert.False(t, issuing.IsRoot)
}

// TestIssuingIdentity_SingleKeyFallback asserts that CAs constructed via the
// bare New(*Params) constructor (which doesn't go through multi-identity
// logic) still have a working IssuingIdentity(). Because no inputIdentity is
// set, the method falls back to reconstructing from the internal
// MultiIdentityCAConfig -- a single KeyConfig derived from the caller's
// KeyAttributes.
func TestIssuingIdentity_SingleKeyFallback(t *testing.T) {
	keyAttrs, err := (&Identity{
		Subject: Subject{CommonName: "Bare New CA"},
		Keys: []*types.KeyConfig{
			{
				KeyAlgorithm:       types.AlgorithmECDSA,
				Hash:               types.HashSHA256,
				SignatureAlgorithm: types.SigECDSAWithSHA256,
				StoreType:          types.StoreSoftware,
				ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
			},
		},
	}).ToKeyAttributes()
	require.NoError(t, err)

	instance, err := New(&Params{
		Config: &CAConfig{
			Identity:  "Bare New CA",
			Subject:   &Subject{CommonName: "Bare New CA"},
			IsRootCA:  true,
			StoreType: types.StoreSoftware,
		},
		KeyAttributes: keyAttrs,
		KeyStore:      newInMemoryBackend(t),
		CertStore:     newInMemoryCertStore(t),
	})
	require.NoError(t, err)

	caInstance, ok := instance.(*CA)
	require.True(t, ok)
	assert.Nil(t, caInstance.inputIdentity, "inputIdentity should be nil for bare New(*Params)")

	issuing := caInstance.IssuingIdentity()
	require.Len(t, issuing.Keys, 1, "fallback path surfaces the single KeyConfig derived from KeyAttributes")
	assert.Equal(t, types.AlgorithmECDSA, issuing.Keys[0].KeyAlgorithm)
}
