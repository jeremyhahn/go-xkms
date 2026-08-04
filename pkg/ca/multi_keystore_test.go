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
	"crypto"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test doubles
// =============================================================================

// countingBackend wraps a real xkms.Backend and records how often each
// key-generation and signing method is invoked. It lets the routing tests
// prove which physical backend a CA key operation actually reached while still
// producing real key material.
type countingBackend struct {
	xkms.Backend
	genRSA   atomic.Int32
	genECDSA atomic.Int32
	genEd    atomic.Int32
	getKey   atomic.Int32
	signer   atomic.Int32
}

func (c *countingBackend) GenerateRSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	c.genRSA.Add(1)
	return c.Backend.GenerateRSA(ctx, attrs)
}

func (c *countingBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	c.genECDSA.Add(1)
	return c.Backend.GenerateECDSA(ctx, attrs)
}

func (c *countingBackend) GenerateEd25519(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	c.genEd.Add(1)
	return c.Backend.GenerateEd25519(ctx, attrs)
}

func (c *countingBackend) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	c.getKey.Add(1)
	return c.Backend.GetKey(ctx, attrs)
}

func (c *countingBackend) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	c.signer.Add(1)
	return c.Backend.Signer(ctx, attrs)
}

func newCountingBackend(t *testing.T) *countingBackend {
	t.Helper()
	return &countingBackend{Backend: newInMemoryBackend(t)}
}

// keyConfig builds a single KeyConfig for the given algorithm + store type.
func keyConfig(algo types.KeyAlgorithmString, store types.StoreType) *types.KeyConfig {
	kc := &types.KeyConfig{
		KeyAlgorithm: algo,
		Hash:         types.HashSHA256,
		StoreType:    store,
		KeyType:      "CA",
	}
	switch algo {
	case types.AlgorithmECDSA:
		kc.SignatureAlgorithm = types.SigECDSAWithSHA256
		kc.ECCConfig = &types.ECCConfig{Curve: types.CurveP256}
	case types.AlgorithmRSA:
		kc.SignatureAlgorithm = types.SigSHA256WithRSA
		kc.RSAConfig = &types.RSAConfig{KeySize: 2048}
	}
	return kc
}

// =============================================================================
// buildKeystoreMap
// =============================================================================

func TestBuildKeystoreMap_NilFactory(t *testing.T) {
	id := rootIdentity("Nil Factory CA")
	m, err := buildKeystoreMap(&id, id.Subject.CommonName, nil)
	require.NoError(t, err)
	assert.Nil(t, m, "nil factory must yield a nil map (legacy path)")
}

func TestBuildKeystoreMap_NilIdentity(t *testing.T) {
	factory := func(string, types.StoreType) (xkms.Backend, error) {
		t.Fatal("factory must not be called for a nil identity")
		return nil, nil
	}
	m, err := buildKeystoreMap(nil, "cn", factory)
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestBuildKeystoreMap_FactoryCalled(t *testing.T) {
	// Identity with four keys across two unique store types. The factory must
	// be invoked exactly once per unique StoreType (deduped), not once per key.
	id := Identity{
		Subject: Subject{CommonName: "Dedup CA"},
		Valid:   DefaultRootValidityYears,
		Keys: []*types.KeyConfig{
			keyConfig(types.AlgorithmECDSA, types.StoreSoftware),
			keyConfig(types.AlgorithmECDSA, types.StoreTPM2),
			keyConfig(types.AlgorithmRSA, types.StoreSoftware),
			keyConfig(types.AlgorithmRSA, types.StoreTPM2),
		},
		IsRoot: true,
	}

	var calls atomic.Int32
	perType := map[types.StoreType]xkms.Backend{
		types.StoreSoftware: newInMemoryBackend(t),
		types.StoreTPM2:     newInMemoryBackend(t),
	}
	seen := map[types.StoreType]int{}
	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		calls.Add(1)
		seen[st]++
		return perType[st], nil
	}

	m, err := buildKeystoreMap(&id, id.Subject.CommonName, factory)
	require.NoError(t, err)
	require.Len(t, m, 2, "map must hold one entry per unique store type")
	assert.Equal(t, int32(2), calls.Load(), "factory invoked once per unique store type")
	assert.Equal(t, 1, seen[types.StoreSoftware])
	assert.Equal(t, 1, seen[types.StoreTPM2])
	assert.Same(t, perType[types.StoreSoftware], m[types.StoreSoftware])
	assert.Same(t, perType[types.StoreTPM2], m[types.StoreTPM2])
}

func TestBuildKeystoreMap_EmptyStoreTypeDefaultsSoftware(t *testing.T) {
	id := Identity{
		Subject: Subject{CommonName: "Default Store CA"},
		Keys:    []*types.KeyConfig{keyConfig(types.AlgorithmECDSA, "")},
	}
	var got types.StoreType
	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		got = st
		return newInMemoryBackend(t), nil
	}
	m, err := buildKeystoreMap(&id, id.Subject.CommonName, factory)
	require.NoError(t, err)
	assert.Equal(t, types.StoreSoftware, got, "empty store type defaults to software")
	_, ok := m[types.StoreSoftware]
	assert.True(t, ok)
}

func TestBuildKeystoreMap_FactoryError(t *testing.T) {
	sentinel := errors.New("boom")
	id := rootIdentity("Factory Error CA")
	factory := func(string, types.StoreType) (xkms.Backend, error) {
		return nil, sentinel
	}
	m, err := buildKeystoreMap(&id, id.Subject.CommonName, factory)
	assert.Nil(t, m)
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
}

func TestBuildKeystoreMap_FactoryReturnedNil(t *testing.T) {
	id := rootIdentity("Factory Nil CA")
	factory := func(string, types.StoreType) (xkms.Backend, error) {
		return nil, nil
	}
	m, err := buildKeystoreMap(&id, id.Subject.CommonName, factory)
	assert.Nil(t, m)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyStoreRequired)
}

// =============================================================================
// resolveKeyBackend
// =============================================================================

func TestResolveKeyBackend_WithMap(t *testing.T) {
	sw := newInMemoryBackend(t)
	tpm := newInMemoryBackend(t)
	fallback := newInMemoryBackend(t)
	ca := &CA{
		keyStore: fallback,
		keystoreMap: map[types.StoreType]xkms.Backend{
			types.StoreSoftware: sw,
			types.StoreTPM2:     tpm,
		},
	}
	assert.Same(t, sw, ca.resolveKeyBackend(types.StoreSoftware))
	assert.Same(t, tpm, ca.resolveKeyBackend(types.StoreTPM2))
	// A store type absent from the map falls back to the single keyStore.
	assert.Same(t, fallback, ca.resolveKeyBackend(types.StorePKCS11))
}

func TestResolveKeyBackend_Fallback(t *testing.T) {
	fallback := newInMemoryBackend(t)
	ca := &CA{keyStore: fallback} // nil keystoreMap == legacy path
	assert.Same(t, fallback, ca.resolveKeyBackend(types.StoreTPM2))
	assert.Same(t, fallback, ca.resolveKeyBackend(types.StoreSoftware))
}

// =============================================================================
// Backward compatibility gate
// =============================================================================

// TestNewCA_BackwardCompat is the mandatory non-regression gate: an existing
// single-KeyStore CA (no BackendForStore, no Keystores) must behave identically
// to before — nil keystoreMap, all key ops routed to the single keyStore, and a
// fully functional init/sign/issue lifecycle.
func TestNewCA_BackwardCompat(t *testing.T) {
	ks := newInMemoryBackend(t)
	params := &Params{
		Identity:  []Identity{rootIdentity("BackwardCompat Root CA")},
		KeyStore:  ks,
		CertStore: newInMemoryCertStore(t),
	}

	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, root)
	assert.Nil(t, intermediate)

	caImpl, ok := root.(*CA)
	require.True(t, ok)

	// The defining backward-compat invariant: no per-store map, and every
	// store type resolves to the single injected keyStore.
	assert.Nil(t, caImpl.keystoreMap, "no BackendForStore => keystoreMap must be nil")
	assert.Same(t, ks, caImpl.resolveKeyBackend(types.StoreSoftware))
	assert.Same(t, ks, caImpl.resolveKeyBackend(types.StoreTPM2))
	assert.Same(t, ks, caImpl.resolveKeyBackend(types.StorePKCS11))

	// Lifecycle still works end-to-end: the self-signed root cert exists...
	caCert, err := root.CACertificate()
	require.NoError(t, err)
	require.NotNil(t, caCert)
	assert.Equal(t, "BackwardCompat Root CA", caCert.Subject.CommonName)
	assert.Equal(t, caCert.Subject.String(), caCert.Issuer.String())

	// ...and the CA can still issue and verify a leaf certificate.
	issued, err := root.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "leaf.example.com"},
		Valid:   1,
	})
	require.NoError(t, err)
	require.NotNil(t, issued)
	_, err = root.Verify(issued.Certificate)
	require.NoError(t, err)
}

// =============================================================================
// initSecondaryKeys (via Init / NewCA, the multi-key routing path)
// =============================================================================

// TestInitSecondaryKeys_AllGenerated proves per-key routing during Init:
// Keys[0] (primary, software RSA) drives the CA certificate and signing;
// Keys[1] (tpm2 RSA) lands in the tpm2-routed backend; Keys[2] (software
// ECDSA) lands in the software backend.
func TestInitSecondaryKeys_AllGenerated(t *testing.T) {
	sw := newCountingBackend(t)
	tpm := newCountingBackend(t)

	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		switch st {
		case types.StoreSoftware:
			return sw, nil
		case types.StoreTPM2:
			return tpm, nil
		default:
			return nil, errors.New("unexpected store type")
		}
	}

	id := Identity{
		Subject:      Subject{CommonName: "Multi-Key Root CA", Organization: "Test Org"},
		Valid:        DefaultRootValidityYears,
		KeystoreType: types.StoreSoftware, // primary is software
		Keys: []*types.KeyConfig{
			keyConfig(types.AlgorithmRSA, types.StoreSoftware),   // [0] primary
			keyConfig(types.AlgorithmRSA, types.StoreTPM2),       // [1] secondary tpm2
			keyConfig(types.AlgorithmECDSA, types.StoreSoftware), // [2] secondary software
		},
		IsRoot:        true,
		MaxPathLength: 1,
	}

	params := &Params{
		Identity:        []Identity{id},
		KeyStore:        sw, // fallback (also software-routed)
		CertStore:       newInMemoryCertStore(t),
		BackendForStore: factory,
	}

	root, _, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	caImpl := root.(*CA)

	// keystoreMap built from the full Keys slice: two unique store types.
	require.Len(t, caImpl.keystoreMap, 2)
	assert.Same(t, sw, caImpl.keystoreMap[types.StoreSoftware])
	assert.Same(t, tpm, caImpl.keystoreMap[types.StoreTPM2])

	// The secondary tpm2 RSA key was generated in the tpm2-routed backend.
	assert.Equal(t, int32(1), tpm.genRSA.Load(), "tpm2 secondary RSA key generated in tpm2 backend")
	assert.Equal(t, int32(0), tpm.genECDSA.Load(), "no ECDSA in tpm2 backend")

	// The primary (RSA) + secondary software ECDSA landed in the software backend.
	assert.Equal(t, int32(1), sw.genRSA.Load(), "primary RSA generated in software backend")
	assert.Equal(t, int32(1), sw.genECDSA.Load(), "secondary software ECDSA generated in software backend")

	// getSigner routes to the primary (Keys[0] == software) backend.
	swSignsBefore := sw.signer.Load()
	signer, err := caImpl.getSigner(context.Background())
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.Equal(t, swSignsBefore+1, sw.signer.Load(), "signer resolved from software backend (Keys[0])")
	assert.Equal(t, int32(0), tpm.signer.Load(), "tpm2 backend not used for signing")
}

// TestInitSecondaryKeys_NoSecondaryNoop confirms a single-key identity makes
// initSecondaryKeys a no-op (no extra generations beyond the primary).
func TestInitSecondaryKeys_NoSecondaryNoop(t *testing.T) {
	ca := &CA{}
	// nil identity and inputIdentity => immediate no-op, no panic.
	require.NoError(t, ca.initSecondaryKeys(context.Background(), nil))

	id := rootIdentity("Single Key CA")
	require.NoError(t, ca.initSecondaryKeys(context.Background(), &id))
}
