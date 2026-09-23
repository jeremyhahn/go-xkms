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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
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
	assert.Nil(t, m)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendForStoreRequired, "nil factory must be rejected: there is no single-keystore fallback")
}

func TestBuildKeystoreMap_NilIdentity(t *testing.T) {
	factory := func(string, types.StoreType) (xkms.Backend, error) {
		t.Fatal("factory must not be called for a nil identity")
		return nil, nil
	}
	m, err := buildKeystoreMap(nil, "cn", factory)
	assert.Nil(t, m)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidConfig)
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
	ca := &CA{
		keystoreMap: map[types.StoreType]xkms.Backend{
			types.StoreSoftware: sw,
			types.StoreTPM2:     tpm,
		},
	}
	got, err := ca.resolveKeyBackend(types.StoreSoftware)
	require.NoError(t, err)
	assert.Same(t, sw, got)

	got, err = ca.resolveKeyBackend(types.StoreTPM2)
	require.NoError(t, err)
	assert.Same(t, tpm, got)
}

// TestResolveKeyBackend_MissingStoreType proves a StoreType absent from
// keystoreMap fails with a typed error instead of silently falling back to
// a single shared backend.
func TestResolveKeyBackend_MissingStoreType(t *testing.T) {
	ca := &CA{
		keystoreMap: map[types.StoreType]xkms.Backend{
			types.StoreSoftware: newInMemoryBackend(t),
		},
	}
	got, err := ca.resolveKeyBackend(types.StorePKCS11)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyStoreRequired)
}

// =============================================================================
// BackendForStore / RevocationStore are mandatory
// =============================================================================

// TestNewCA_RequiresBackendForStore is the compat-removal gate: constructing
// a CA the old single-KeyStore way — no BackendForStore, no per-StoreType
// routing — now fails with a typed error instead of silently succeeding.
func TestNewCA_RequiresBackendForStore(t *testing.T) {
	ks := newInMemoryBackend(t)
	params := &Params{
		Identity:        []Identity{rootIdentity("No BackendForStore Root CA")},
		KeyStore:        ks,
		CertStore:       newInMemoryCertStore(t),
		RevocationStore: storage.NewMemory(),
	}

	_, _, err := NewCA(context.Background(), params)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendForStoreRequired)
}

// TestNewCA_RequiresRevocationStore is the compat-removal gate for the
// revocation persistence fallback: constructing a CA without a
// RevocationStore now fails with a typed error instead of silently falling
// back to the object store or in-memory-only tracking.
func TestNewCA_RequiresRevocationStore(t *testing.T) {
	ks := newInMemoryBackend(t)
	params := &Params{
		Identity:        []Identity{rootIdentity("No RevocationStore Root CA")},
		KeyStore:        ks,
		CertStore:       newInMemoryCertStore(t),
		BackendForStore: singleBackendFactory(ks),
	}

	_, _, err := NewCA(context.Background(), params)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRevocationStoreRequired)
}

// TestNewCA_ExplicitSingleBackend proves the canonical replacement for the
// deleted fallback: a caller with one uniform backend supplies a
// BackendForStore factory that returns it for every StoreType, an explicit
// choice rather than an implicit default, and the CA operates normally.
func TestNewCA_ExplicitSingleBackend(t *testing.T) {
	ks := newInMemoryBackend(t)
	params := &Params{
		Identity:        []Identity{rootIdentity("Explicit Single Backend Root CA")},
		KeyStore:        ks,
		CertStore:       newInMemoryCertStore(t),
		BackendForStore: singleBackendFactory(ks),
		RevocationStore: storage.NewMemory(),
	}

	root, intermediate, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.NotNil(t, root)
	assert.Nil(t, intermediate)

	caImpl, ok := root.(*CA)
	require.True(t, ok)
	got, err := caImpl.resolveKeyBackend(types.StoreSoftware)
	require.NoError(t, err)
	assert.Same(t, ks, got)

	// Lifecycle still works end-to-end: the self-signed root cert exists...
	caCert, err := root.CACertificate()
	require.NoError(t, err)
	require.NotNil(t, caCert)
	assert.Equal(t, "Explicit Single Backend Root CA", caCert.Subject.CommonName)
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
		Subject: Subject{CommonName: "Multi-Key Root CA", Organization: "Test Org"},
		Valid:   DefaultRootValidityYears,
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
		KeyStore:        sw, // used for TLS/CSR paths, not CA signing key routing
		CertStore:       newInMemoryCertStore(t),
		BackendForStore: factory,
		RevocationStore: storage.NewMemory(),
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

// failGenerateRSABackend wraps a real xkms.Backend and fails every
// GenerateRSA call, so a secondary RSA key can be made to fail generation
// while the primary key's own (different) backend keeps working normally.
type failGenerateRSABackend struct {
	xkms.Backend
	err error
}

func (b *failGenerateRSABackend) GenerateRSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, b.err
}

// TestInit_SecondaryKeyFailureIsRecordedNotFatal is the failure-injection
// test for issue #687: initSecondaryKeys' discarded error (`_ =
// ca.initSecondaryKeys(...)` in Init) must no longer vanish silently. It
// proves that when a secondary key (Keys[1]) fails to generate, Init still
// succeeds (the documented best-effort contract: the CA is usable off its
// primary key) but SecondaryKeyInitError reports the failure instead of the
// caller having no way to learn a multi-key CA is only partially
// provisioned.
func TestInit_SecondaryKeyFailureIsRecordedNotFatal(t *testing.T) {
	primary := newInMemoryBackend(t)
	injected := errors.New("injected secondary key generation failure")
	secondary := &failGenerateRSABackend{Backend: newInMemoryBackend(t), err: injected}

	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		switch st {
		case types.StoreSoftware:
			return primary, nil
		case types.StoreTPM2:
			return secondary, nil
		default:
			return nil, errors.New("unexpected store type")
		}
	}

	id := Identity{
		Subject: Subject{CommonName: "Secondary Key Failure Root CA", Organization: "Test Org"},
		Valid:   DefaultRootValidityYears,
		Keys: []*types.KeyConfig{
			keyConfig(types.AlgorithmECDSA, types.StoreSoftware), // [0] primary
			keyConfig(types.AlgorithmRSA, types.StoreTPM2),       // [1] secondary, generation fails
		},
		IsRoot:        true,
		MaxPathLength: 1,
	}

	params := &Params{
		Identity:        []Identity{id},
		KeyStore:        primary,
		CertStore:       newInMemoryCertStore(t),
		BackendForStore: factory,
		RevocationStore: storage.NewMemory(),
	}

	root, _, err := NewCA(context.Background(), params)
	require.NoError(t, err, "a secondary-key failure must not fail Init/NewCA")
	caImpl := root.(*CA)

	secErr := caImpl.SecondaryKeyInitError()
	require.Error(t, secErr, "the discarded secondary-key failure must be recorded, not silently dropped")
	assert.ErrorIs(t, secErr, injected)

	// The CA is still fully usable off its primary key.
	issued, err := caImpl.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "leaf.example.com"},
		Valid:   1,
	})
	require.NoError(t, err)
	require.NotNil(t, issued)
}

// TestInit_SecondaryKeySuccessLeavesNoError proves the happy path (all
// secondary keys generated) leaves SecondaryKeyInitError nil.
func TestInit_SecondaryKeySuccessLeavesNoError(t *testing.T) {
	sw := newCountingBackend(t)

	id := Identity{
		Subject: Subject{CommonName: "Secondary Key Success Root CA", Organization: "Test Org"},
		Valid:   DefaultRootValidityYears,
		Keys: []*types.KeyConfig{
			keyConfig(types.AlgorithmECDSA, types.StoreSoftware), // [0] primary
			keyConfig(types.AlgorithmRSA, types.StoreSoftware),   // [1] secondary
		},
		IsRoot:        true,
		MaxPathLength: 1,
	}

	params := &Params{
		Identity:        []Identity{id},
		KeyStore:        sw,
		CertStore:       newInMemoryCertStore(t),
		BackendForStore: singleBackendFactory(sw),
		RevocationStore: storage.NewMemory(),
	}

	root, _, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	caImpl := root.(*CA)

	assert.NoError(t, caImpl.SecondaryKeyInitError())
	assert.Equal(t, int32(1), sw.genRSA.Load(), "secondary RSA key generated")
}
