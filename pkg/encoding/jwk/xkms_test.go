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

package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testRSAKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	testECKey, _  = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
)

// TestXKMSGetterTypes verifies the getter function types are satisfiable by
// ordinary closures, matching the dependency-injection pattern consumers
// (e.g. the jwt package) rely on.
func TestXKMSGetterTypes(t *testing.T) {
	var getKey XKMSKeyGetter = func(keyID string) (crypto.PrivateKey, error) {
		return testRSAKey, nil
	}
	var getSigner XKMSSignerGetter = func(keyID string) (crypto.Signer, error) {
		return testRSAKey, nil
	}

	key, err := getKey("software:signing:rsa:test-key")
	require.NoError(t, err)
	assert.Equal(t, testRSAKey, key)

	signer, err := getSigner("software:signing:rsa:test-key")
	require.NoError(t, err)
	assert.Equal(t, testRSAKey.Public(), signer.Public())
}

// TestJWK_NoPrivateKeyMaterial verifies that JWKs derived from key material
// never contain private key components.
func TestJWK_NoPrivateKeyMaterial(t *testing.T) {
	tests := []struct {
		name   string
		pubKey crypto.PublicKey
	}{
		{
			name:   "RSA key",
			pubKey: testRSAKey.Public(),
		},
		{
			name:   "ECDSA key",
			pubKey: testECKey.Public(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwk, err := FromPublicKey(tt.pubKey)
			require.NoError(t, err)

			// Verify NO private key material
			assert.Empty(t, jwk.D, "Private exponent D should be empty")
			assert.Empty(t, jwk.P, "Prime P should be empty")
			assert.Empty(t, jwk.Q, "Prime Q should be empty")
			assert.Empty(t, jwk.DP, "DP should be empty")
			assert.Empty(t, jwk.DQ, "DQ should be empty")
			assert.Empty(t, jwk.QI, "QI should be empty")
			assert.Empty(t, jwk.K, "Symmetric key should be empty")
		})
	}
}
