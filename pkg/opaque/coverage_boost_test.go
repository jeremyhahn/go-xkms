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

package opaque

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPublicKeysEqual_SameCustomPointer verifies the default branch of
// publicKeysEqual where two unknown-typed public keys point to the same
// object, exercising the fallback a == b comparison.
func TestPublicKeysEqual_SameCustomPointer(t *testing.T) {
	pub := &customPublicKey{data: []byte("same-pointer")}

	// Both arguments point to the same custom public key
	result := publicKeysEqual(pub, pub)
	assert.True(t, result, "same pointer should be equal via fallback comparison")
}

// TestPublicKeysEqual_DifferentCustomPointers verifies the default branch of
// publicKeysEqual where two unknown-typed public keys are distinct objects.
func TestPublicKeysEqual_DifferentCustomPointers(t *testing.T) {
	a := &customPublicKey{data: []byte("a")}
	b := &customPublicKey{data: []byte("b")}

	result := publicKeysEqual(a, b)
	assert.False(t, result, "different custom key pointers should not be equal")
}

// TestOpaqueEqual_GetKeyError verifies that Equal returns false when the
// key store's GetKey method fails.
func TestOpaqueEqual_GetKeyError(t *testing.T) {
	pub := &customPublicKey{data: []byte("test")}
	attrs := &types.KeyAttributes{
		CN:           "error-key",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
	}

	ks := &mockKeyStore{
		getKeyFunc: func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
			return nil, ErrKeyStoreRequired
		},
	}

	key, err := NewOpaqueKey(ks, attrs, pub)
	require.NoError(t, err)

	// Equal should return false when GetKey fails
	assert.False(t, key.Equal(nil))
}
