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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSoftwareBackend_SupportedCurves(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	curves := sb.SupportedCurves()

	assert.Len(t, curves, 4)
	assert.Contains(t, curves, "P-256")
	assert.Contains(t, curves, "P-384")
	assert.Contains(t, curves, "P-521")
	assert.Contains(t, curves, "X25519")
}

func TestSoftwareBackend_DeriveKeyECDH_P256(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's key pair
	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.p256",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's key pair (external, just for public key)
	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Marshal Bob's public key to DER
	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	// Derive key using Alice's private key and Bob's public key
	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("test-salt"),
		Info:      []byte("test-info"),
		KeyLength: 32,
	}

	derivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	require.NoError(t, err)
	assert.Len(t, derivedKey, 32)

	// Verify deterministic: same inputs should produce same output
	derivedKey2, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	require.NoError(t, err)
	assert.Equal(t, derivedKey, derivedKey2)
}

func TestSoftwareBackend_DeriveKeyECDH_P384(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's P-384 key pair
	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.p384",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's P-384 key pair
	bobPrivate, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-384",
		KeyLength: 48,
	}

	derivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	require.NoError(t, err)
	assert.Len(t, derivedKey, 48)
}

func TestSoftwareBackend_DeriveKeyECDH_P521(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's P-521 key pair
	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.p521",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P521(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's P-521 key pair
	bobPrivate, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-512",
		KeyLength: 64,
	}

	derivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	require.NoError(t, err)
	assert.Len(t, derivedKey, 64)
}

func TestSoftwareBackend_DeriveKeyECDH_X25519(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's X25519 key pair
	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.x25519",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		KeyAlgorithm:     x509.PublicKeyAlgorithm(0), // X25519 doesn't have a standard algorithm
		X25519Attributes: &types.X25519Attributes{},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's X25519 key pair
	bobPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Use raw 32-byte public key
	bobPubRaw := bobPrivate.PublicKey().Bytes()

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("x25519-salt"),
		Info:      []byte("x25519-encryption"),
		KeyLength: 32,
	}

	derivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubRaw, kdfParams)
	require.NoError(t, err)
	assert.Len(t, derivedKey, 32)
}

func TestSoftwareBackend_DeriveKeyECDH_X25519_DERFormat(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's X25519 key pair
	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.x25519.der",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's X25519 key pair and encode to DER
	bobPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(bobPrivate.PublicKey())
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	derivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	require.NoError(t, err)
	assert.Len(t, derivedKey, 32)
}

func TestSoftwareBackend_DeriveKeyECDH_BidirectionalAgreement(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's key pair
	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.bidirectional",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	aliceKey, err := sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's key pair in the backend as well
	bobAttrs := &types.KeyAttributes{
		CN:           "bob.bidirectional",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	bobKey, err := sb.GenerateKey(bobAttrs)
	require.NoError(t, err)

	// Get public keys in DER format
	aliceECDSA := aliceKey.(*ecdsa.PrivateKey)
	bobECDSA := bobKey.(*ecdsa.PrivateKey)

	alicePubDER, err := x509.MarshalPKIXPublicKey(&aliceECDSA.PublicKey)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobECDSA.PublicKey)
	require.NoError(t, err)

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("bidirectional-test"),
		Info:      []byte("shared-encryption-key"),
		KeyLength: 32,
	}

	// Alice derives shared key using Bob's public key
	aliceDerivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	require.NoError(t, err)

	// Bob derives shared key using Alice's public key
	bobDerivedKey, err := sb.DeriveKeyECDH(ctx, bobAttrs, alicePubDER, kdfParams)
	require.NoError(t, err)

	// Both should derive the same key
	assert.Equal(t, aliceDerivedKey, bobDerivedKey, "bidirectional key agreement should produce identical keys")
}

func TestSoftwareBackend_DeriveKeyECDH_SHA3Hashes(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.sha3",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	testCases := []struct {
		name      string
		hash      string
		keyLength int
	}{
		{"SHA3-256", "SHA3-256", 32},
		{"SHA3-384", "SHA3-384", 48},
		{"SHA3-512", "SHA3-512", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kdfParams := &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      tc.hash,
				KeyLength: tc.keyLength,
			}

			derivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
			require.NoError(t, err)
			assert.Len(t, derivedKey, tc.keyLength)
		})
	}
}

// Error case tests

func TestSoftwareBackend_DeriveKeyECDH_NilPrivateKeyAttrs(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	kdfParams := types.DefaultKDFParams()

	_, err = sb.DeriveKeyECDH(ctx, nil, []byte("some-key"), kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
}

func TestSoftwareBackend_DeriveKeyECDH_EmptyPeerPublicKey(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.empty",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	_, err = sb.DeriveKeyECDH(ctx, aliceAttrs, []byte{}, kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestSoftwareBackend_DeriveKeyECDH_NilKDFParams(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.nilkdf",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	_, err = sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKDFParams)
}

func TestSoftwareBackend_DeriveKeyECDH_InvalidKDFKeyLength(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.invalidkdf",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: 0, // Invalid
	}

	_, err = sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKDFParams)
}

func TestSoftwareBackend_DeriveKeyECDH_CurveMismatch(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's P-256 key pair
	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.p256.mismatch",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's P-384 key pair (different curve)
	bobPrivate, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	_, err = sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCurveMismatch)
}

func TestSoftwareBackend_DeriveKeyECDH_InvalidPublicKeyFormat(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.invalid",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	// Invalid public key data
	_, err = sb.DeriveKeyECDH(ctx, aliceAttrs, []byte("not a valid public key"), kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestSoftwareBackend_DeriveKeyECDH_KeyNotFound(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Use attrs for a non-existent key
	nonExistentAttrs := &types.KeyAttributes{
		CN:           "nonexistent.key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	_, err = sb.DeriveKeyECDH(ctx, nonExistentAttrs, bobPubDER, kdfParams)
	assert.Error(t, err)
}

func TestSoftwareBackend_DeriveKeyECDH_X25519_InvalidPublicKeyLength(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.x25519.invalid",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	// Invalid X25519 public key (wrong length)
	_, err = sb.DeriveKeyECDH(ctx, aliceAttrs, []byte("not-32-bytes"), kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPublicKey)
}

func TestSoftwareBackend_DeriveKeyECDH_BackendClosed(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.closed",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	// Close the backend
	err = sb.Close()
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	_, err = sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

func TestSoftwareBackend_DeriveKeyECDH_UnsupportedKeyType(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate an RSA key (not supported for ECDH)
	rsaAttrs := &types.KeyAttributes{
		CN:           "rsa.unsupported",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	_, err = sb.GenerateKey(rsaAttrs)
	require.NoError(t, err)

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	_, err = sb.DeriveKeyECDH(ctx, rsaAttrs, bobPubDER, kdfParams)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}

func TestSoftwareBackend_DeriveKeyECDH_UncompressedPointFormat(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.uncompressed",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's key and convert to ECDH to get uncompressed format
	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Get the uncompressed point format via crypto/ecdh
	ecdhPub, err := bobPrivate.PublicKey.ECDH()
	require.NoError(t, err)

	bobPubUncompressed := ecdhPub.Bytes()

	kdfParams := types.DefaultKDFParams()

	derivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubUncompressed, kdfParams)
	require.NoError(t, err)
	assert.Len(t, derivedKey, 32)
}

func TestSoftwareBackend_DeriveKeyECDH_X25519_BidirectionalAgreement(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's X25519 key pair
	aliceAttrs := &types.KeyAttributes{
		CN:               "alice.x25519.bi",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
	}
	aliceKey, err := sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's X25519 key pair
	bobAttrs := &types.KeyAttributes{
		CN:               "bob.x25519.bi",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		X25519Attributes: &types.X25519Attributes{},
	}
	bobKey, err := sb.GenerateKey(bobAttrs)
	require.NoError(t, err)

	// Get public keys
	aliceWrapped := aliceKey.(*x25519.PrivateKeyStorage)
	bobWrapped := bobKey.(*x25519.PrivateKeyStorage)

	alicePubRaw := aliceWrapped.PrivateKey().PublicKey().Bytes()
	bobPubRaw := bobWrapped.PrivateKey().PublicKey().Bytes()

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("x25519-bidirectional"),
		Info:      []byte("shared-key"),
		KeyLength: 32,
	}

	// Alice derives shared key using Bob's public key
	aliceDerivedKey, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubRaw, kdfParams)
	require.NoError(t, err)

	// Bob derives shared key using Alice's public key
	bobDerivedKey, err := sb.DeriveKeyECDH(ctx, bobAttrs, alicePubRaw, kdfParams)
	require.NoError(t, err)

	// Both should derive the same key
	assert.Equal(t, aliceDerivedKey, bobDerivedKey, "X25519 bidirectional key agreement should produce identical keys")
}

func TestSoftwareBackend_DeriveKeyECDH_DifferentInfoProducesDifferentKeys(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.different.info",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	// Derive key with info "encryption"
	kdfParams1 := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("same-salt"),
		Info:      []byte("encryption"),
		KeyLength: 32,
	}

	key1, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams1)
	require.NoError(t, err)

	// Derive key with info "authentication"
	kdfParams2 := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("same-salt"),
		Info:      []byte("authentication"),
		KeyLength: 32,
	}

	key2, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams2)
	require.NoError(t, err)

	// Keys should be different
	assert.NotEqual(t, key1, key2, "different info should produce different keys")
}

func TestSoftwareBackend_DeriveKeyECDH_DifferentSaltProducesDifferentKeys(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.different.salt",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	// Derive key with salt1
	kdfParams1 := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("salt-one"),
		Info:      []byte("same-info"),
		KeyLength: 32,
	}

	key1, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams1)
	require.NoError(t, err)

	// Derive key with salt2
	kdfParams2 := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("salt-two"),
		Info:      []byte("same-info"),
		KeyLength: 32,
	}

	key2, err := sb.DeriveKeyECDH(ctx, aliceAttrs, bobPubDER, kdfParams2)
	require.NoError(t, err)

	// Keys should be different
	assert.NotEqual(t, key1, key2, "different salt should produce different keys")
}

func TestSoftwareBackend_KeyAgreementBackend_InterfaceCompliance(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	// Verify SoftwareBackend implements KeyAgreementBackend
	var _ types.KeyAgreementProvider = b.(*SoftwareBackend)
}

// =============================================================================
// SecureKeyAgreementBackend Tests
// =============================================================================

func TestSoftwareBackend_SupportedDerivationModes(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	modes := sb.SupportedDerivationModes()

	// Software backend only supports EXPORT mode
	assert.Len(t, modes, 1)
	assert.Contains(t, modes, types.KeyDerivationModeExport)
}

func TestSoftwareBackend_DeriveKeyECDHSecure_ExportMode(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate Alice's key pair
	aliceAttrs := &types.KeyAttributes{
		CN:           "alice.secure.p256",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(aliceAttrs)
	require.NoError(t, err)

	// Generate Bob's key pair (external, just for public key)
	bobPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bobPubDER, err := x509.MarshalPKIXPublicKey(&bobPrivate.PublicKey)
	require.NoError(t, err)

	// Derive key using EXPORT mode
	kdfParams := &types.KDFParams{
		Algorithm:      types.KDFAlgorithmHKDF,
		Hash:           "SHA-256",
		KeyLength:      32,
		DerivationMode: types.KeyDerivationModeExport,
	}

	result, err := sb.DeriveKeyECDHSecure(ctx, aliceAttrs, bobPubDER, kdfParams)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result
	assert.Equal(t, types.KeyDerivationModeExport, result.Mode)
	assert.True(t, result.IsExported())
	assert.False(t, result.IsResident())
	assert.Len(t, result.DerivedKey, 32)
	assert.Nil(t, result.Handle)
}

func TestSoftwareBackend_DeriveKeyECDHSecure_DefaultMode(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate key pair
	attrs := &types.KeyAttributes{
		CN:           "test.default.mode",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(attrs)
	require.NoError(t, err)

	// Generate peer key
	peerPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerPubDER, err := x509.MarshalPKIXPublicKey(&peerPrivate.PublicKey)
	require.NoError(t, err)

	// Derive key with default mode (0 = EXPORT)
	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: 32,
		// DerivationMode not set - defaults to 0 (EXPORT)
	}

	result, err := sb.DeriveKeyECDHSecure(ctx, attrs, peerPubDER, kdfParams)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, types.KeyDerivationModeExport, result.Mode)
	assert.True(t, result.HasKey())
}

func TestSoftwareBackend_DeriveKeyECDHSecure_UnsupportedModes(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	// Generate key pair
	attrs := &types.KeyAttributes{
		CN:           "test.unsupported.mode",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
	_, err = sb.GenerateKey(attrs)
	require.NoError(t, err)

	// Generate peer key
	peerPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerPubDER, err := x509.MarshalPKIXPublicKey(&peerPrivate.PublicKey)
	require.NoError(t, err)

	unsupportedModes := []types.KeyDerivationMode{
		types.KeyDerivationModeHSMResident,
		types.KeyDerivationModeHSMKDF,
		types.KeyDerivationModeTPMWrapped,
	}

	for _, mode := range unsupportedModes {
		t.Run(mode.String(), func(t *testing.T) {
			kdfParams := &types.KDFParams{
				Algorithm:      types.KDFAlgorithmHKDF,
				Hash:           "SHA-256",
				KeyLength:      32,
				DerivationMode: mode,
			}

			result, err := sb.DeriveKeyECDHSecure(ctx, attrs, peerPubDER, kdfParams)
			assert.Error(t, err)
			assert.Nil(t, result)
			assert.ErrorIs(t, err, ErrDerivationModeNotSupported)
		})
	}
}

func TestSoftwareBackend_UseResidentKey_NotSupported(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	handle := &types.DerivedKeyHandle{
		ID:      "test-handle",
		Backend: "software",
	}
	params := &types.OperationParams{
		Algorithm: "AES-GCM",
	}

	result, err := sb.UseResidentKey(ctx, handle, types.ResidentKeyOpEncrypt, []byte("test"), params)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrDerivationModeNotSupported)
}

func TestSoftwareBackend_DestroyResidentKey_NotSupported(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	ctx := context.Background()

	handle := &types.DerivedKeyHandle{
		ID:      "test-handle",
		Backend: "software",
	}

	err = sb.DestroyResidentKey(ctx, handle)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDerivationModeNotSupported)
}

func TestSoftwareBackend_SecureKeyAgreementBackend_InterfaceCompliance(t *testing.T) {
	stor := storage.New()
	config := &Config{KeyStorage: stor}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	// Verify SoftwareBackend implements SecureKeyAgreementBackend
	var _ types.SecureKeyAgreementProvider = b.(*SoftwareBackend)
}

// =============================================================================
// Internal Helper Function Tests
// =============================================================================

func TestNistCurveToECDH_AllCurves(t *testing.T) {
	tests := []struct {
		name        string
		curveName   string
		shouldError bool
	}{
		{"P-256", "P-256", false},
		{"P-384", "P-384", false},
		{"P-521", "P-521", false},
		{"unsupported", "P-224", true},
		{"invalid", "invalid-curve", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curve, err := nistCurveToECDH(tt.curveName)
			if tt.shouldError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrUnsupportedCurve)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, curve)
			}
		})
	}
}

func TestGetHashFunc_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		shouldError bool
	}{
		{"SHA-256", "SHA-256", false},
		{"SHA-384", "SHA-384", false},
		{"SHA-512", "SHA-512", false},
		{"SHA3-256", "SHA3-256", false},
		{"SHA3-384", "SHA3-384", false},
		{"SHA3-512", "SHA3-512", false},
		{"unsupported", "MD5", true},
		{"empty", "", true},
		{"invalid", "invalid-hash", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashFunc, err := getHashFunc(tt.algorithm)
			if tt.shouldError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, hashFunc)
			}
		})
	}
}

func TestApplyHKDF_Success(t *testing.T) {
	params := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("test-salt"),
		Info:      []byte("test-info"),
		KeyLength: 32,
	}
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	derived, err := applyHKDF(sharedSecret, params)
	require.NoError(t, err)
	assert.Len(t, derived, 32)
}

func TestApplyHKDF_InvalidHash(t *testing.T) {
	params := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "invalid-hash",
		KeyLength: 32,
	}
	sharedSecret := make([]byte, 32)
	_, err := rand.Read(sharedSecret)
	require.NoError(t, err)

	_, err = applyHKDF(sharedSecret, params)
	assert.Error(t, err)
}

func TestApplyKDF_UnsupportedAlgorithm(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)

	params := &types.KDFParams{
		Algorithm: "unsupported-kdf",
		Hash:      "SHA-256",
		KeyLength: 32,
	}
	sharedSecret := make([]byte, 32)
	_, err = rand.Read(sharedSecret)
	require.NoError(t, err)

	_, err = sb.applyKDF(sharedSecret, params)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedKDFAlgorithm)
}

func TestApplyKDF_HKDF(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)

	params := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Salt:      []byte("test-salt"),
		Info:      []byte("test-info"),
		KeyLength: 32,
	}
	sharedSecret := make([]byte, 32)
	_, err = rand.Read(sharedSecret)
	require.NoError(t, err)

	derived, err := sb.applyKDF(sharedSecret, params)
	require.NoError(t, err)
	assert.Len(t, derived, 32)
}

func TestParseNISTPublicKey_EmptyData(t *testing.T) {
	_, err := parseNISTPublicKey([]byte{}, elliptic.P256())
	assert.Error(t, err)
}

func TestParseNISTPublicKey_InvalidFormat(t *testing.T) {
	invalidData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	_, err := parseNISTPublicKey(invalidData, elliptic.P256())
	assert.Error(t, err)
}

func TestParseNISTPublicKey_ValidDER(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	derBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	require.NoError(t, err)

	pubKey, err := parseNISTPublicKey(derBytes, elliptic.P256())
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

func TestParseNISTPublicKey_UncompressedPoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create uncompressed point format (0x04 || X || Y)
	curveParams := elliptic.P256().Params()
	keySize := (curveParams.BitSize + 7) / 8
	uncompressed := make([]byte, 1+2*keySize)
	uncompressed[0] = 0x04
	key.X.FillBytes(uncompressed[1 : 1+keySize])
	key.Y.FillBytes(uncompressed[1+keySize:])

	pubKey, err := parseNISTPublicKey(uncompressed, elliptic.P256())
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

func TestParseNISTPublicKey_AllCurves(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)

			derBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			require.NoError(t, err)

			pubKey, err := parseNISTPublicKey(derBytes, curve)
			require.NoError(t, err)
			assert.NotNil(t, pubKey)
		})
	}
}

func TestParseX25519PublicKey_EmptyData(t *testing.T) {
	_, err := parseX25519PublicKey([]byte{})
	assert.Error(t, err)
}

func TestParseX25519PublicKey_InvalidLength(t *testing.T) {
	invalidData := make([]byte, 16)
	_, err := parseX25519PublicKey(invalidData)
	assert.Error(t, err)
}

func TestParseX25519PublicKey_ValidRaw(t *testing.T) {
	rawKey := make([]byte, 32)
	_, err := rand.Read(rawKey)
	require.NoError(t, err)

	pubKey, err := parseX25519PublicKey(rawKey)
	require.NoError(t, err)
	assert.NotNil(t, pubKey)
}

func TestSoftwareBackend_ListKeys_Empty(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	require.NoError(t, err)
	defer func() { _ = b.Close() }()

	sb := b.(*SoftwareBackend)
	keys, err := sb.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestSoftwareBackend_Close_Idempotent(t *testing.T) {
	s := storage.New()
	config := &Config{KeyStorage: s}
	b, err := NewBackend(config)
	require.NoError(t, err)

	// Close once
	err = b.Close()
	require.NoError(t, err)

	// Close again - should not error
	err = b.Close()
	assert.NoError(t, err)
}
