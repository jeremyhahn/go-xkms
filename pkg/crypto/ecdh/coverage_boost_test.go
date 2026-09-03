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

package ecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeriveSharedSecret_CurveMismatch verifies that DeriveSharedSecret returns
// an error when the private and public keys use different curves.
func TestDeriveSharedSecret_CurveMismatch(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	otherKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	_, err = DeriveSharedSecret(privKey, &otherKey.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "curve mismatch")
}

// TestEcdsaPublicToECDH_ValidCurves exercises the ecdsaPublicToECDH conversion
// for all supported NIST curves.
func TestEcdsaPublicToECDH_ValidCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{name: "P-256", curve: elliptic.P256()},
		{name: "P-384", curve: elliptic.P384()},
		{name: "P-521", curve: elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			ecdhKey, err := ecdsaPublicToECDH(&key.PublicKey)
			require.NoError(t, err)
			assert.NotNil(t, ecdhKey)
		})
	}
}

// TestDeriveSharedSecret_NilPrivateKey verifies that a nil private key returns
// an appropriate error.
func TestDeriveSharedSecret_NilPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = DeriveSharedSecret(nil, &key.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key cannot be nil")
}

// TestDeriveSharedSecret_NilPublicKey verifies that a nil public key returns
// an appropriate error.
func TestDeriveSharedSecret_NilPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = DeriveSharedSecret(key, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key cannot be nil")
}

// TestDeriveSharedSecret_InvalidPrivateKeyD verifies that DeriveSharedSecret
// returns an error when the private key has an invalid D value (zero), which
// causes the ECDSA-to-ECDH conversion to fail.
func TestDeriveSharedSecret_InvalidPrivateKeyD(t *testing.T) {
	validKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// D is assigned raw, and staticcheck's SA1019 for that is suppressed here
	// deliberately: the test needs a scalar of ZERO, which is outside [1, N-1]
	// and therefore not a key any supported constructor will build --
	// ecdsa.ParseRawPrivateKey rejects it, which is the whole point. The
	// deprecated raw field is the only way to construct the invalid input this
	// error path exists to handle.
	invalidPriv := &ecdsa.PrivateKey{
		PublicKey: validKey.PublicKey,
		D:         big.NewInt(0), //nolint:staticcheck // SA1019: see above
	}

	_, err = DeriveSharedSecret(invalidPriv, &validKey.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert private key")
}

// TestDeriveSharedSecret_InvalidPublicKeyPoint verifies that DeriveSharedSecret
// returns an error when the public key has an invalid point (not on the curve),
// which causes the ecdsaPublicToECDH conversion to fail.
func TestDeriveSharedSecret_InvalidPublicKeyPoint(t *testing.T) {
	validKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a public key with an invalid point (not on the P-256 curve).
	// X and Y are assigned raw and SA1019 is suppressed deliberately: (1, 1)
	// is off the curve, so ecdsa.ParseUncompressedPublicKey rejects it -- an
	// off-curve point is exactly what this error path is being handed, and the
	// deprecated raw fields are the only way to build one.
	invalidPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1), //nolint:staticcheck // SA1019: see above
		Y:     big.NewInt(1), //nolint:staticcheck // SA1019: see above
	}

	_, err = DeriveSharedSecret(validKey, invalidPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert public key")
}

// TestEcdsaPublicToECDH_InvalidPoint verifies that ecdsaPublicToECDH returns
// an error for a public key with coordinates not on the curve.
func TestEcdsaPublicToECDH_InvalidPoint(t *testing.T) {
	// Raw X/Y with SA1019 suppressed, same reason as above: (1, 1) is not on
	// P-256, so no validating constructor will produce this key, and an
	// off-curve point is the input under test.
	invalidPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(1), //nolint:staticcheck // SA1019: see above
		Y:     big.NewInt(1), //nolint:staticcheck // SA1019: see above
	}

	_, err := ecdsaPublicToECDH(invalidPub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert ECDSA to ECDH public key")
}
