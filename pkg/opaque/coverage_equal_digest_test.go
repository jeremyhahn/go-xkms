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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpaqueEqual_ViaPublicKeyComparison exercises the Equal fallback path where
// the stored key does not implement Equal(crypto.PrivateKey) but the other
// key is a crypto.Signer, so public key comparison is used.
func TestOpaqueEqual_ViaPublicKeyComparison(t *testing.T) {
	// Generate two ECDSA keys — same curve for positive match via publicKeysEqual.
	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "equal-test",
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
	}

	// The mock returns a non-Equal-implementing key wrapper.
	ks := &mockKeyStore{
		getKeyFunc: func(a *types.KeyAttributes) (crypto.PrivateKey, error) {
			return &noEqualKey{pub: &priv1.PublicKey}, nil
		},
	}

	key, err := NewOpaqueKey(ks, attrs, &priv1.PublicKey)
	require.NoError(t, err)

	t.Run("same public key via signer comparison", func(t *testing.T) {
		// priv1 is a crypto.Signer — Equal should fall through to publicKeysEqual
		assert.True(t, key.Equal(priv1))
	})

	t.Run("different public key via signer comparison", func(t *testing.T) {
		priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		assert.False(t, key.Equal(priv2))
	})

	t.Run("non-signer argument returns false", func(t *testing.T) {
		assert.False(t, key.Equal(&noEqualKey{pub: &priv1.PublicKey}))
	})
}

// TestOpaqueDigest_UnavailableHash ensures Digest returns ErrInvalidHashFunction
// when the hash algorithm is not available.
func TestOpaqueDigest_UnavailableHash(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "digest-hash-err",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.Hash(0), // invalid / unavailable
	}

	ks := &mockKeyStore{}
	key, err := NewOpaqueKey(ks, attrs, &priv.PublicKey)
	require.NoError(t, err)

	_, err = key.Digest([]byte("test"))
	assert.ErrorIs(t, err, ErrInvalidHashFunction)
}

// TestPublicKeysEqual_RSAMismatchType covers the RSA branch where b is not *rsa.PublicKey.
func TestPublicKeysEqual_RSAMismatchType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	assert.False(t, publicKeysEqual(&rsaKey.PublicKey, &ecKey.PublicKey))
}

// TestPublicKeysEqual_ECDSAMismatchType covers the ECDSA branch where b is not *ecdsa.PublicKey.
func TestPublicKeysEqual_ECDSAMismatchType(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	assert.False(t, publicKeysEqual(&ecKey.PublicKey, &rsaKey.PublicKey))
}

// noEqualKey is a private key that does NOT implement Equal(crypto.PrivateKey).
type noEqualKey struct {
	pub crypto.PublicKey
}

func (n *noEqualKey) Public() crypto.PublicKey { return n.pub }
