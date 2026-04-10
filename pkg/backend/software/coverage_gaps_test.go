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

package software

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewBackend_NilConfig ensures NewBackend fails with nil config.
func TestNewBackend_NilConfig(t *testing.T) {
	_, err := NewBackend(nil)
	assert.Error(t, err)
}

// TestNewBackend_EmptyConfig ensures NewBackend fails with empty config.
func TestNewBackend_EmptyConfig(t *testing.T) {
	_, err := NewBackend(&Config{})
	assert.Error(t, err)
}

// TestExportKey_NilAttrs exercises the nil attrs guard.
func TestExportKey_NilAttrs(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	_, err := be.ExportKey(nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
}

// TestSoftwareBackend_ListKeys_ClosedBackend exercises the closed guard.
func TestSoftwareBackend_ListKeys_ClosedBackend(t *testing.T) {
	be := createFullTestBackend(t)
	require.NoError(t, be.Close())

	_, err := be.ListKeys()
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestImportKey_InvalidPKCS8 exercises the importAsymmetricKey error path
// with invalid PKCS8 data.
func TestImportKey_InvalidPKCS8(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "bad-pkcs8",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
		KeyType:      types.KeyTypeEncryption,
		StoreType:    types.StoreSoftware,
		Exportable:   true,
	}

	// Generate import params and create a wrapped key with garbage inside.
	params, err := be.GetImportParameters(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// Use the wrapping key to wrap invalid PKCS8 data.
	wrapped, err := be.WrapKey([]byte("not-a-valid-pkcs8-key"), params)
	require.NoError(t, err)

	err = be.ImportKey(attrs, wrapped)
	assert.Error(t, err, "should fail to parse invalid PKCS8")
}

// TestSoftwareBackend_Seal_ClosedBackend exercises the closed guard.
func TestSoftwareBackend_Seal_ClosedBackend(t *testing.T) {
	be := createFullTestBackend(t)
	require.NoError(t, be.Close())

	_, err := be.Seal(context.Background(), []byte("data"), &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:           "seal-test",
			KeyAlgorithm: x509.ECDSA,
		},
	})
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestSoftwareBackend_Unseal_ClosedBackend exercises the closed guard.
func TestSoftwareBackend_Unseal_ClosedBackend(t *testing.T) {
	be := createFullTestBackend(t)
	require.NoError(t, be.Close())

	_, err := be.Unseal(context.Background(), &types.SealedData{}, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:           "unseal-test",
			KeyAlgorithm: x509.ECDSA,
		},
	})
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestSoftwareBackend_ExportKey_ClosedBackend exercises the closed guard.
func TestSoftwareBackend_ExportKey_ClosedBackend(t *testing.T) {
	keyStorage := storage.New()
	be, err := NewBackend(&Config{KeyStorage: keyStorage})
	require.NoError(t, err)

	sb := be.(*SoftwareBackend)

	attrs := createRSAAttrs("export-closed", 2048)
	attrs.Exportable = true
	_, err = sb.GenerateKey(attrs)
	require.NoError(t, err)

	require.NoError(t, sb.Close())

	_, err = sb.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrStorageClosed)
}
