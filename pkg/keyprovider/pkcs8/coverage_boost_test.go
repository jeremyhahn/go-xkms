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

package pkcs8

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnmarshalSealedData_InvalidJSON verifies that UnmarshalSealedData
// returns an error when given invalid JSON input.
func TestUnmarshalSealedData_InvalidJSON(t *testing.T) {
	_, err := UnmarshalSealedData([]byte("not json"))
	assert.Error(t, err)
}

// TestUnmarshalSealedData_EmptyInput verifies that UnmarshalSealedData
// returns an error when given an empty byte slice.
func TestUnmarshalSealedData_EmptyInput(t *testing.T) {
	_, err := UnmarshalSealedData([]byte{})
	assert.Error(t, err)
}

// TestRotateKey_NilAttributes verifies that RotateKey returns an error
// when given nil attributes.
func TestRotateKey_NilAttributes(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	err := be.RotateKey(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
}

// TestRotateKey_NonExistentKey verifies that RotateKey succeeds even when
// the key does not already exist, exercising the DeleteKey ErrKeyNotFound path.
func TestRotateKey_NonExistentKey(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "rotate-nonexistent",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}

	// RotateKey on a non-existent key should succeed (ignores key-not-found error)
	err := be.RotateKey(attrs)
	require.NoError(t, err)

	// Verify key now exists
	_, err = be.GetKey(attrs)
	require.NoError(t, err)
}

// TestSigner_Ed25519 verifies the Signer path for Ed25519 keys,
// exercising the ed25519 branch in the Signer method.
func TestSigner_Ed25519(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "signer-ed25519",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.Ed25519,
		Hash:         crypto.SHA256,
	}

	_, err := be.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := be.Signer(attrs)
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.NotNil(t, signer.Public())
}
