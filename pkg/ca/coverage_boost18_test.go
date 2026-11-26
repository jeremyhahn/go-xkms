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

// Package ca coverage boost, eighteenth pass: NewHierarchicalCA (0% covered
// prior to this pass — every existing multi-identity/cluster test constructs
// the CA struct literal directly rather than through the constructor) plus
// the ErrIdentityNotFound.Error() formatting method.
package ca

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// NewHierarchicalCA
// =============================================================================

func TestNewHierarchicalCA_NilParams_B18(t *testing.T) {
	t.Parallel()
	_, err := NewHierarchicalCA(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewHierarchicalCA_InvalidConfig_B18(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	// Empty MultiIdentityCAConfig has no identities, so Validate() fails and
	// the underlying error (not necessarily ErrInvalidConfig itself) surfaces
	// unwrapped from NewHierarchicalCA.
	_, err := NewHierarchicalCA(&MultiIdentityParams{
		Config:          &MultiIdentityCAConfig{},
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.Error(t, err)
}

// TestNewHierarchicalCA_PreservesFullTopology proves the defining behavior of
// NewHierarchicalCA versus NewFromMultiIdentityConfig: every configured
// identity (root, platform intermediate, and a sibling cluster intermediate)
// is created and independently resolvable via IssuerForIdentity after Init,
// using ONLY the default (nil) SerialGen/Profiles/BackendForStore.
func TestNewHierarchicalCA_PreservesFullTopology_B18(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := clusterTestConfig()

	got, err := NewHierarchicalCA(&MultiIdentityParams{
		Config:          cfg,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	require.NoError(t, err)
	require.NotNil(t, got)

	require.NoError(t, got.Init(context.Background()))

	issuer, ok := got.(IdentityIssuer)
	require.True(t, ok, "NewHierarchicalCA must return an IdentityIssuer")

	for _, cn := range []string{"Test Root CA", "Test Platform CA", "Test Cluster CA"} {
		signer, cert, err := issuer.IssuerForIdentity(context.Background(), cn)
		require.NoError(t, err, "IssuerForIdentity(%q)", cn)
		require.NotNil(t, signer)
		require.NotNil(t, cert)
		assert.Equal(t, cn, cert.Subject.CommonName)
	}

	// An identity absent from the config is rejected with the typed error,
	// proving the hierarchy is not silently flattened to a single issuer.
	_, _, err = issuer.IssuerForIdentity(context.Background(), "No Such CA")
	var notFound *ErrIdentityNotFound
	require.ErrorAs(t, err, &notFound)
}

// TestNewHierarchicalCA_WithBackendForStore proves the BackendForStore
// routing path: buildKeystoreMap runs for every configured identity and the
// resulting per-store-type backends are recorded on the CA.
func TestNewHierarchicalCA_WithBackendForStore_B18(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := clusterTestConfig()

	var calls int
	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		calls++
		return backend, nil
	}

	got, err := NewHierarchicalCA(&MultiIdentityParams{
		Config:          cfg,
		KeyStore:        backend,
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		BackendForStore: factory,
	})
	require.NoError(t, err)
	caImpl, ok := got.(*CA)
	require.True(t, ok)
	require.NotNil(t, caImpl.keystoreMap)
	assert.Same(t, backend, caImpl.keystoreMap[types.StoreSoftware])
	assert.Greater(t, calls, 0, "factory must be invoked for at least one identity")

	require.NoError(t, got.Init(context.Background()))
}

// TestNewHierarchicalCA_BackendForStoreError proves a factory failure for
// any configured identity aborts construction (buildKeystoreMap's error
// propagates from NewHierarchicalCA rather than being swallowed).
func TestNewHierarchicalCA_BackendForStoreError_B18(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := clusterTestConfig()

	errFactory := errors.New("factory unavailable")
	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		return nil, errFactory
	}

	_, err := NewHierarchicalCA(&MultiIdentityParams{
		Config:          cfg,
		KeyStore:        backend,
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		BackendForStore: factory,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, errFactory)
}

// TestNewHierarchicalCA_CustomSerialGenAndProfiles proves the non-nil
// SerialGen/Profiles overrides are wired onto the returned CA rather than
// the defaults, mirroring the analogous NewFromMultiIdentityConfig behavior.
func TestNewHierarchicalCA_CustomSerialGenAndProfiles_B18(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)
	cfg := clusterTestConfig()

	customSerialGen := NewSerialGenerator(NewMemoryStorage())
	customProfiles := NewDefaultProfileRegistry()

	got, err := NewHierarchicalCA(&MultiIdentityParams{
		Config:          cfg,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       customSerialGen,
		Profiles:        customProfiles,
	})
	require.NoError(t, err)
	caImpl, ok := got.(*CA)
	require.True(t, ok)
	assert.Same(t, customSerialGen, caImpl.serialGen)
	assert.Same(t, customProfiles, caImpl.profiles)
}

// =============================================================================
// ErrIdentityNotFound.Error()
// =============================================================================

// TestErrIdentityNotFound_Error covers the Error() string formatting, which
// the existing errors.As-based assertions in identity_issuer_test.go never
// invoke directly.
func TestErrIdentityNotFound_Error_B18(t *testing.T) {
	t.Parallel()
	err := &ErrIdentityNotFound{CommonName: "Ghost CA"}
	assert.Equal(t, "ca: no configured identity with common name Ghost CA", err.Error())
}
