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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createFullTestBackend creates a test SoftwareBackend with access to
// import/export methods that are not on the SymmetricKeyProvider interface.
func createFullTestBackend(t *testing.T) *SoftwareBackend {
	t.Helper()

	keyStorage := storage.New()
	config := &Config{
		KeyStorage: keyStorage,
	}

	be, err := NewBackend(config)
	require.NoError(t, err)
	sb, ok := be.(*SoftwareBackend)
	require.True(t, ok, "NewBackend should return *SoftwareBackend")
	return sb
}

// TestExportKey_InvalidWrappingAlgorithm verifies that ExportKey returns an
// error when an unsupported wrapping algorithm is specified.
func TestExportKey_InvalidWrappingAlgorithm(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("export-invalid-algo", 2048)
	attrs.Exportable = true

	_, err := be.GenerateKey(attrs)
	require.NoError(t, err)

	_, err = be.ExportKey(attrs, backend.WrappingAlgorithm("INVALID-ALGO"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
}

// TestClose_DoubleClose verifies that closing a backend twice does not error.
func TestClose_DoubleClose(t *testing.T) {
	be := createFullTestBackend(t)

	err := be.Close()
	require.NoError(t, err)

	err = be.Close()
	assert.NoError(t, err, "double close should be a no-op")
}

// TestListKeys_EmptyBackend verifies that ListKeys returns an empty list
// when no keys have been generated.
func TestListKeys_EmptyBackend(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	keys, err := be.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestImportKey_InvalidPKCS8Material verifies that ImportKey returns an error
// when the wrapped key material contains invalid PKCS8 data.
func TestImportKey_InvalidPKCS8Material(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	wrapAttrs := createRSAAttrs("wrap-key", 2048)
	_, err := be.GenerateKey(wrapAttrs)
	require.NoError(t, err)

	params, err := be.GetImportParameters(wrapAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := be.WrapKey([]byte("not-valid-pkcs8"), params)
	require.NoError(t, err)

	importAttrs := &types.KeyAttributes{
		CN:        "imported-key",
		StoreType: backend.STORE_SW,
	}
	err = be.ImportKey(importAttrs, wrapped)
	assert.Error(t, err)
}
