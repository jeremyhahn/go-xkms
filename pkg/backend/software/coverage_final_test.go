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
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListKeys_WhenClosed verifies that ListKeys returns ErrStorageClosed
// when the backend has been closed.
func TestListKeys_WhenClosed(t *testing.T) {
	be, _ := createTestBackend(t)

	err := be.Close()
	require.NoError(t, err)

	_, err = be.ListKeys()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStorageClosed))
}

// TestExportKey_WhenClosed verifies that ExportKey returns ErrStorageClosed
// when the backend has been closed.
func TestExportKey_WhenClosed(t *testing.T) {
	be, _ := createTestBackend(t)
	sb := be.(*SoftwareBackend)

	err := sb.Close()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:         "export-closed",
		Exportable: true,
	}

	_, err = sb.ExportKey(attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStorageClosed))
}

// TestSeal_WhenClosed verifies that Seal returns ErrStorageClosed
// when the backend has been closed.
func TestSeal_WhenClosed(t *testing.T) {
	be, _ := createTestBackend(t)
	sb := be.(*SoftwareBackend)

	err := sb.Close()
	require.NoError(t, err)

	_, err = sb.Seal(context.Background(), []byte("data"), &types.SealOptions{
		KeyAttributes: createRSAAttrs("seal-closed", 2048),
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStorageClosed))
}

// TestDetermineKeySpec_SymmetricDefault verifies the default AES_256 return
// when a symmetric algorithm has unknown/zero key size.
func TestDetermineKeySpec_SymmetricDefault(t *testing.T) {
	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAlgorithm("custom-unknown"),
	}
	spec := determineKeySpec(attrs)
	assert.Equal(t, "AES_256", spec)
}

// TestDetermineKeySpec_Nil verifies the UNKNOWN return for nil attrs.
func TestDetermineKeySpec_Nil(t *testing.T) {
	spec := determineKeySpec(nil)
	assert.Equal(t, "UNKNOWN", spec)
}

// TestValidateKeyType_PublicKeyError verifies that validateKeyType returns
// an error when given an RSA public key instead of a private key.
func TestValidateKeyType_PublicKeyError(t *testing.T) {
	be, _ := createTestBackend(t)
	sb := be.(*SoftwareBackend)

	rsaAttrs := createRSAAttrs("validate-key-type", 2048)
	key, err := sb.GenerateKey(rsaAttrs)
	require.NoError(t, err)

	// Get the public key from the private key
	rsaKey, ok := key.(*rsa.PrivateKey)
	require.True(t, ok)
	pubKey := crypto.PublicKey(&rsaKey.PublicKey)

	err = validateKeyType(pubKey, rsaAttrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected private key but got public key")
}
