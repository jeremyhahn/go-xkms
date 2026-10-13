// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC

package store

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertName(t *testing.T) {
	t.Run("nil attributes are refused", func(t *testing.T) {
		_, err := certName(nil)
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("empty CN is refused", func(t *testing.T) {
		_, err := certName(&types.KeyAttributes{})
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("attributes without parent", func(t *testing.T) {
		name, err := certName(&types.KeyAttributes{CN: "test-cert"})
		require.NoError(t, err)
		assert.Equal(t, "test-cert", name)
	})

	t.Run("attributes with parent", func(t *testing.T) {
		name, err := certName(&types.KeyAttributes{
			CN:     "child-cert",
			Parent: &types.KeyAttributes{CN: "parent-cert"},
		})
		require.NoError(t, err)
		assert.Equal(t, "parent-cert/child-cert", name)
	})
}

func TestBlobCertStore_SaveAndGet(t *testing.T) {
	certStore := NewBlobCertStore(testLogger(), newTestBlobStore(t))

	t.Run("save with nil attributes returns error", func(t *testing.T) {
		err := certStore.Save(nil, generateTestCertificate(t, "save-nil-attrs"))
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("save nil certificate returns error", func(t *testing.T) {
		err := certStore.Save(&types.KeyAttributes{CN: "nil-cert"}, nil)
		assert.ErrorContains(t, err, "certificate is nil")
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
		assert.NotErrorIs(t, err, ErrBlobNotFound)
	})

	t.Run("round trip", func(t *testing.T) {
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

	t.Run("parent-prefixed certificate is distinct from the unprefixed one", func(t *testing.T) {
		parented := generateTestCertificate(t, "child-cert")
		bare := generateTestCertificate(t, "child-cert-bare")
		child := &types.KeyAttributes{CN: "child-cert", Parent: &types.KeyAttributes{CN: "parent-cert"}}

		require.NoError(t, certStore.Save(child, parented))
		require.NoError(t, certStore.Save(&types.KeyAttributes{CN: "child-cert"}, bare))

		got, err := certStore.Get(child)
		require.NoError(t, err)
		assert.True(t, parented.Equal(got))
	})
}

func TestBlobCertStore_Get_CorruptData(t *testing.T) {
	blobs := newTestBlobStore(t)
	certStore := NewBlobCertStore(testLogger(), blobs)
	attrs := &types.KeyAttributes{CN: "corrupt-cert"}
	require.NoError(t, blobs.Save(attrs, []byte("not a certificate"), FSEXT_CERTIFICATE, true))

	cert, err := certStore.Get(attrs)
	assert.Nil(t, cert)
	assert.ErrorContains(t, err, "failed to parse certificate")
}

func TestBlobCertStore_Delete(t *testing.T) {
	certStore := NewBlobCertStore(testLogger(), newTestBlobStore(t))

	t.Run("delete with nil attributes returns error", func(t *testing.T) {
		assert.ErrorIs(t, certStore.Delete(nil), ErrEmptyKeyCN)
	})

	t.Run("delete non-existent certificate returns ErrCertNotFound", func(t *testing.T) {
		err := certStore.Delete(&types.KeyAttributes{CN: "never-saved"})
		assert.ErrorIs(t, err, ErrCertNotFound)
	})

	t.Run("delete removes a stored certificate", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "delete-cert"}

		require.NoError(t, certStore.Save(attrs, generateTestCertificate(t, "delete-cert")))
		require.NoError(t, certStore.Delete(attrs))

		_, err := certStore.Get(attrs)
		assert.ErrorIs(t, err, ErrCertNotFound)
	})
}

func TestBlobCertStore_ImportCertificate(t *testing.T) {
	certStore := NewBlobCertStore(testLogger(), newTestBlobStore(t))

	t.Run("import with nil attributes returns error", func(t *testing.T) {
		cert, err := certStore.ImportCertificate(nil, generateTestCertificatePEM(t, "import-nil-attrs"))
		assert.Nil(t, cert)
		assert.ErrorIs(t, err, ErrEmptyKeyCN)
	})

	t.Run("import invalid PEM returns error", func(t *testing.T) {
		cert, err := certStore.ImportCertificate(&types.KeyAttributes{CN: "import-bad-pem"}, []byte("not pem"))
		assert.Nil(t, cert)
		assert.ErrorContains(t, err, "failed to decode PEM block")
	})

	t.Run("import valid certificate persists it", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "import-ok"}

		cert, err := certStore.ImportCertificate(attrs, generateTestCertificatePEM(t, "import-ok"))
		require.NoError(t, err)

		got, err := certStore.Get(attrs)
		require.NoError(t, err)
		assert.True(t, cert.Equal(got))
	})
}

// TestBlobCertStore_SharesStoreWithKeyBlobs verifies a certificate and the
// key blobs it certifies live in one BlobStore -- the invariant
// openDeviceTPM's hardware branch relies on (go-xkms#1100) -- and that
// deleting the key's blobs leaves its certificate alone.
func TestBlobCertStore_SharesStoreWithKeyBlobs(t *testing.T) {
	blobs := newTestBlobStore(t)
	certStore := NewBlobCertStore(testLogger(), blobs)

	attrs := &types.KeyAttributes{CN: "shared-device"}
	testCert := generateTestCertificate(t, "shared-device")

	require.NoError(t, certStore.Save(attrs, testCert))
	require.NoError(t, blobs.Save(attrs, []byte("public-blob"), types.FSExtPublicBlob, true))

	der, err := blobs.Get(attrs, FSEXT_CERTIFICATE)
	require.NoError(t, err)
	assert.Equal(t, testCert.Raw, der)

	require.NoError(t, blobs.Delete(attrs))
	got, err := certStore.Get(attrs)
	require.NoError(t, err)
	assert.True(t, testCert.Equal(got))
}
