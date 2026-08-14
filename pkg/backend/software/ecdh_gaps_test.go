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
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/x25519"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Coverage-gap tests for ecdh.go: real behavior + error paths not
// exercised elsewhere.
// ============================================================================

func newGapsBackend(t *testing.T) *SoftwareBackend {
	t.Helper()
	be, err := NewBackend(&Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	return be.(*SoftwareBackend)
}

// TestDeriveECDHWithNIST_UnsupportedCurveByECDH verifies deriveECDHWithNIST
// surfaces a real error when the private key's curve (P-224) is not one
// crypto/ecdsa.PrivateKey.ECDH() supports (only P-256/P-384/P-521 are).
func TestDeriveECDHWithNIST_UnsupportedCurveByECDH(t *testing.T) {
	sb := newGapsBackend(t)
	defer func() { _ = sb.Close() }()

	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	peerDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	_, err = sb.deriveECDHWithNIST(priv, peerDER)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert private key to ECDH")
}

// TestDeriveECDHWithX25519_LowOrderPoint verifies deriveECDHWithX25519
// rejects a peer public key that is a known low-order point (the all-zero
// 32-byte value), which crypto/ecdh's X25519 implementation refuses to
// compute a shared secret with as a defense against small-subgroup
// attacks.
func TestDeriveECDHWithX25519_LowOrderPoint(t *testing.T) {
	sb := newGapsBackend(t)
	defer func() { _ = sb.Close() }()

	rawPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	wrapped, err := x25519.NewPrivateKeyStorage(rawPriv)
	require.NoError(t, err)

	lowOrderPeer := make([]byte, 32) // all-zero peer key: a known low-order point

	_, err = sb.deriveECDHWithX25519(wrapped, lowOrderPeer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "X25519 ECDH operation failed")
}

// TestApplyKDF_KeyLengthExceedsHKDFMax verifies applyKDF surfaces the real
// HKDF "output too long" failure when the caller requests more derived key
// material than is available for the given hash (255 * hash size).
func TestApplyKDF_KeyLengthExceedsHKDFMax(t *testing.T) {
	sb := newSoftwareBackendForKDF(t)

	_, err := sb.applyKDF([]byte("shared-secret-material"), &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: 255*32 + 1, // one byte past HKDF-SHA256's maximum output
	})
	require.Error(t, err)
}

// TestParseNISTPublicKey_DERNonECDSAKey verifies parseNISTPublicKey
// rejects DER-encoded SubjectPublicKeyInfo data that parses successfully
// but is not an ECDSA public key (an RSA key, in this case).
func TestParseNISTPublicKey_DERNonECDSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	_, err = parseNISTPublicKey(der, elliptic.P256())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-ECDSA key")
}

// TestParseNISTPublicKey_UnsupportedCurveName verifies parseNISTPublicKey
// rejects a raw uncompressed-point buffer whose expected curve
// (P-224) has no crypto/ecdh mapping in nistCurveToECDH.
func TestParseNISTPublicKey_UnsupportedCurveName(t *testing.T) {
	// P-224 uncompressed point: 1-byte prefix + 2*28-byte coordinates.
	raw := make([]byte, 1+2*28)
	raw[0] = 0x04

	_, err := parseNISTPublicKey(raw, elliptic.P224())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedCurve)
}

// TestParseNISTPublicKey_InvalidPointNotOnCurve verifies parseNISTPublicKey
// rejects a raw uncompressed-point buffer of the correct length whose
// coordinates do not correspond to a valid point on the curve.
func TestParseNISTPublicKey_InvalidPointNotOnCurve(t *testing.T) {
	// P-256 uncompressed point: 1-byte prefix + 2*32-byte coordinates,
	// but all-zero coordinates are not a valid curve point.
	raw := make([]byte, 1+2*32)
	raw[0] = 0x04

	_, err := parseNISTPublicKey(raw, elliptic.P256())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse uncompressed point")
}

// TestParseX25519PublicKey_DERNonX25519Key verifies parseX25519PublicKey
// rejects DER-encoded SubjectPublicKeyInfo data that parses successfully
// but is not an X25519 key (an RSA key, in this case).
func TestParseX25519PublicKey_DERNonX25519Key(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	_, err = parseX25519PublicKey(der)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-X25519 key")
}

// TestDeriveKeyECDHSecure_UnderlyingDeriveError verifies
// DeriveKeyECDHSecure propagates a failure from the delegated
// DeriveKeyECDH call (nonexistent key).
func TestDeriveKeyECDHSecure_UnderlyingDeriveError(t *testing.T) {
	sb := newGapsBackend(t)
	defer func() { _ = sb.Close() }()

	attrs := &types.KeyAttributes{
		CN:            "ecdh-secure-missing-key.com",
		KeyType:       types.KeyTypeTLS,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}

	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerDER, err := x509.MarshalPKIXPublicKey(peer.PublicKey())
	require.NoError(t, err)

	_, err = sb.DeriveKeyECDHSecure(context.Background(), attrs, peerDER, &types.KDFParams{
		Algorithm:      types.KDFAlgorithmHKDF,
		Hash:           "SHA-256",
		KeyLength:      32,
		DerivationMode: types.KeyDerivationModeExport,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get private key")
}
