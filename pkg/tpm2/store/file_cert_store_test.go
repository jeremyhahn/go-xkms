// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC

package store

import (
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FileCertStore Tests
// =============================================================================

func TestFileCertStore_NewFileCertStore(t *testing.T) {
	logger := testCertLogger()
	backend := storage.NewMemory()

	certStore := NewFileCertStore(logger, backend)

	// NewFileCertStore's return type is CertificateStorer, so a caller
	// assigning it (as certStore is here) already gets the interface
	// compliance check at compile time.
	assert.NotNil(t, certStore)
}

func TestFileCertStore_certStorageKey(t *testing.T) {
	t.Run("nil attributes returns error", func(t *testing.T) {
		key, err := certStorageKey(nil)
		assert.Equal(t, "", key)
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("empty CN returns error", func(t *testing.T) {
		key, err := certStorageKey(&types.KeyAttributes{})
		assert.Equal(t, "", key)
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("attributes without parent", func(t *testing.T) {
		key, err := certStorageKey(&types.KeyAttributes{CN: "test-cert"})
		require.NoError(t, err)
		assert.Equal(t, "test-cert"+FSEXT_CERTIFICATE, key)
	})

	t.Run("attributes with parent", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:     "child-cert",
			Parent: &types.KeyAttributes{CN: "parent-cert"},
		}
		key, err := certStorageKey(attrs)
		require.NoError(t, err)
		assert.Equal(t, "parent-cert/child-cert"+FSEXT_CERTIFICATE, key)
	})
}

func TestFileCertStore_SaveAndGet(t *testing.T) {
	certStore := NewFileCertStore(testCertLogger(), storage.NewMemory())

	t.Run("save with nil attributes returns error", func(t *testing.T) {
		testCert := generateTestCertificate(t, "save-nil-attrs")
		err := certStore.Save(nil, testCert)
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("save nil certificate returns error", func(t *testing.T) {
		err := certStore.Save(&types.KeyAttributes{CN: "nil-cert"}, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate is nil")
	})

	t.Run("get with nil attributes returns error", func(t *testing.T) {
		cert, err := certStore.Get(nil)
		assert.Nil(t, cert)
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("get non-existent certificate returns ErrCertNotFound", func(t *testing.T) {
		cert, err := certStore.Get(&types.KeyAttributes{CN: "does-not-exist"})
		assert.Nil(t, cert)
		assert.ErrorIs(t, err, ErrCertNotFound)
	})

	t.Run("round trip through the same backing storage.Backend as key blobs", func(t *testing.T) {
		testCert := generateTestCertificate(t, "round-trip-cert")
		attrs := &types.KeyAttributes{CN: "round-trip-cert"}

		require.NoError(t, certStore.Save(attrs, testCert))

		got, err := certStore.Get(attrs)
		require.NoError(t, err)
		assert.True(t, testCert.Equal(got))
	})

	t.Run("save overwrites a previously stored certificate", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "overwrite-cert"}
		cert1 := generateTestCertificate(t, "overwrite-cert-1")
		cert2 := generateTestCertificate(t, "overwrite-cert-2")

		require.NoError(t, certStore.Save(attrs, cert1))
		require.NoError(t, certStore.Save(attrs, cert2))

		got, err := certStore.Get(attrs)
		require.NoError(t, err)
		assert.True(t, cert2.Equal(got))
	})

	t.Run("parent-prefixed key addresses the same certificate MemoryCertStore would", func(t *testing.T) {
		testCert := generateTestCertificate(t, "child-cert")
		attrs := &types.KeyAttributes{
			CN:     "child-cert",
			Parent: &types.KeyAttributes{CN: "parent-cert"},
		}

		require.NoError(t, certStore.Save(attrs, testCert))

		got, err := certStore.Get(attrs)
		require.NoError(t, err)
		assert.True(t, testCert.Equal(got))
	})
}

func TestFileCertStore_Get_CorruptData(t *testing.T) {
	backend := storage.NewMemory()
	certStore := NewFileCertStore(testCertLogger(), backend)
	attrs := &types.KeyAttributes{CN: "corrupt-cert"}

	t.Run("non-PEM data is refused", func(t *testing.T) {
		key, err := certStorageKey(attrs)
		require.NoError(t, err)
		require.NoError(t, backend.Put(t.Context(), key, []byte("not a PEM block")))

		cert, err := certStore.Get(attrs)
		assert.Nil(t, cert)
		assert.Error(t, err)
	})

	t.Run("PEM block with unparseable DER is refused", func(t *testing.T) {
		key, err := certStorageKey(attrs)
		require.NoError(t, err)
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
		require.NoError(t, backend.Put(t.Context(), key, bad))

		cert, err := certStore.Get(attrs)
		assert.Nil(t, cert)
		assert.Error(t, err)
	})
}

func TestFileCertStore_Delete(t *testing.T) {
	certStore := NewFileCertStore(testCertLogger(), storage.NewMemory())

	t.Run("delete with nil attributes returns error", func(t *testing.T) {
		assert.ErrorIs(t, certStore.Delete(nil), ErrEmptyKeyCN)
	})

	t.Run("delete non-existent certificate returns ErrCertNotFound", func(t *testing.T) {
		err := certStore.Delete(&types.KeyAttributes{CN: "never-saved"})
		assert.ErrorIs(t, err, ErrCertNotFound)
	})

	t.Run("delete removes a stored certificate", func(t *testing.T) {
		testCert := generateTestCertificate(t, "delete-cert")
		attrs := &types.KeyAttributes{CN: "delete-cert"}

		require.NoError(t, certStore.Save(attrs, testCert))
		require.NoError(t, certStore.Delete(attrs))

		_, err := certStore.Get(attrs)
		assert.ErrorIs(t, err, ErrCertNotFound)
	})
}

func TestFileCertStore_ImportCertificate(t *testing.T) {
	certStore := NewFileCertStore(testCertLogger(), storage.NewMemory())

	t.Run("import with nil attributes returns error", func(t *testing.T) {
		certPEM := generateTestCertificatePEM(t, "import-nil-attrs")
		cert, err := certStore.ImportCertificate(nil, certPEM)
		assert.Nil(t, cert)
		assert.Error(t, err)
	})

	t.Run("import invalid PEM returns error", func(t *testing.T) {
		cert, err := certStore.ImportCertificate(&types.KeyAttributes{CN: "import-bad-pem"}, []byte("not pem"))
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("import valid certificate persists it", func(t *testing.T) {
		certPEM := generateTestCertificatePEM(t, "import-ok")
		attrs := &types.KeyAttributes{CN: "import-ok"}

		cert, err := certStore.ImportCertificate(attrs, certPEM)
		require.NoError(t, err)
		require.NotNil(t, cert)

		got, err := certStore.Get(attrs)
		require.NoError(t, err)
		assert.True(t, cert.Equal(got))
	})
}

// TestFileCertStore_SharesBackendWithKeyBlobs verifies a FileCertStore and a
// FileBackend built from the same storage.Backend see the same underlying
// storage -- the invariant openDeviceTPM's hardware branch relies on
// (go-xkms#1100): a certificate and the key blobs it certifies live under
// one storage root, not two independently configured stores.
func TestFileCertStore_SharesBackendWithKeyBlobs(t *testing.T) {
	backend := storage.NewMemory()
	certStore := NewFileCertStore(testCertLogger(), backend)
	keyBackend := NewFileBackend(testCertLogger(), backend)

	attrs := &types.KeyAttributes{CN: "shared-backend-device"}
	testCert := generateTestCertificate(t, "shared-backend-device")

	require.NoError(t, certStore.Save(attrs, testCert))
	require.NoError(t, keyBackend.Save(attrs, []byte("fake-public-blob"), types.FSExtPublicBlob, true))

	gotCert, err := certStore.Get(attrs)
	require.NoError(t, err)
	assert.True(t, testCert.Equal(gotCert))

	gotBlob, err := keyBackend.Get(attrs, types.FSExtPublicBlob)
	require.NoError(t, err)
	assert.Equal(t, []byte("fake-public-blob"), gotBlob)
}

func TestFileCertStore_InterfaceCompliance(t *testing.T) {
	var _ CertificateStorer = (*FileCertStore)(nil)
}

// TestFileCertStore_NotFoundIsStorePackageSentinel is a defensive check that
// Get never leaks the underlying storage.ErrNotFound unwrapped: callers
// (ProvisionIAKCert's IAKCertificate read path) match on the store package's
// own ErrCertNotFound.
func TestFileCertStore_NotFoundIsStorePackageSentinel(t *testing.T) {
	certStore := NewFileCertStore(testCertLogger(), storage.NewMemory())
	_, err := certStore.Get(&types.KeyAttributes{CN: "missing"})
	require.True(t, errors.Is(err, ErrCertNotFound))
	require.False(t, errors.Is(err, storage.ErrNotFound))
}
