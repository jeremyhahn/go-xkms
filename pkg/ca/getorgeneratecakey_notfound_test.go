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
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	backendpkg "github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// setupUninitializedCAWithKeyProvider builds a not-yet-initialized CA whose
// key backend is the supplied types.KeyProvider, so tests can control
// exactly what GetKey and GenerateKey return without going through a real
// software/hardware backend. This is go-xkms#801: getOrGenerateCAKey must
// fail closed, not generate a replacement key, when GetKey fails for a
// reason other than "key does not exist".
func setupUninitializedCAWithKeyProvider(t *testing.T, kp types.KeyProvider) *CA {
	t.Helper()

	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     kp,
		CertStorage: certStorage,
	})
	if err != nil {
		t.Fatalf("Failed to create xkms backend: %v", err)
	}

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{
		CertStorage: certAdapter,
	})
	if err != nil {
		t.Fatalf("Failed to create certstore: %v", err)
	}

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "GetKey Failure CA"
	config.Identity[0].Keys[0].KeyType = "CA"

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:          config,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	concreteCA, ok := caIface.(*CA)
	if !ok {
		t.Fatalf("Expected *CA type, got %T", caIface)
	}

	return concreteCA
}

// TestCA_GetOrGenerateCAKey_NonNotFoundFailsClosed is the core regression
// test for go-xkms#801: when the backend's GetKey fails for a reason other
// than the key genuinely not existing (a TPM transient fault, a PKCS#11
// login failure, an I/O error, etc.), getOrGenerateCAKey must fail closed
// -- return a typed error -- rather than treat the failure as "no key yet"
// and silently generate (and potentially persist over) a CA signing key.
func TestCA_GetOrGenerateCAKey_NonNotFoundFailsClosed(t *testing.T) {
	transientErr := errors.New("tpm2: transient bus error")
	mockKP := mocks.NewMockBackend()
	mockKP.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, transientErr
	}

	ca := setupUninitializedCAWithKeyProvider(t, mockKP)
	rootIdentity := ca.config.RootIdentity()
	require.NotNil(t, rootIdentity)

	attrs, err := ca.getCAKeyAttributes(rootIdentity)
	require.NoError(t, err)

	_, err = ca.getOrGenerateCAKey(context.Background(), attrs)
	require.Error(t, err)

	assert.ErrorIs(t, err, ErrKeyRetrievalFailed, "a non-not-found GetKey failure must surface as ErrKeyRetrievalFailed")
	assert.False(t, errors.Is(err, backendpkg.ErrKeyNotFound), "a transient GetKey failure must not be classified as ErrKeyNotFound")
	assert.Empty(t, mockKP.GenerateKeyCalls, "getOrGenerateCAKey must not generate a replacement key when it cannot determine whether one already exists")
}

// TestCA_GetOrGenerateCAKey_GenuineNotFoundStillGenerates is the companion
// first-boot regression test: when GetKey genuinely reports the key does
// not exist (errors.Is(err, backend.ErrKeyNotFound)), getOrGenerateCAKey
// must still generate one, so a fresh CA can bootstrap.
func TestCA_GetOrGenerateCAKey_GenuineNotFoundStillGenerates(t *testing.T) {
	mockKP := mocks.NewMockBackend()
	mockKP.GetKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, backendpkg.ErrKeyNotFound
	}

	ca := setupUninitializedCAWithKeyProvider(t, mockKP)
	rootIdentity := ca.config.RootIdentity()
	require.NotNil(t, rootIdentity)

	attrs, err := ca.getCAKeyAttributes(rootIdentity)
	require.NoError(t, err)

	key, err := ca.getOrGenerateCAKey(context.Background(), attrs)
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Len(t, mockKP.GenerateKeyCalls, 1, "a genuine not-found result must still generate the first-boot key")
}
