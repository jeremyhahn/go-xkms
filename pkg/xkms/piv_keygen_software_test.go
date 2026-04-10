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

package xkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSoftwarePIVKeyGenerator_GenerateAllAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		checkType func(t *testing.T, signer crypto.Signer)
	}{
		{
			name:      "rsa2048",
			algorithm: "rsa2048",
			checkType: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				pub, ok := signer.Public().(*rsa.PublicKey)
				require.True(t, ok, "expected *rsa.PublicKey, got %T", signer.Public())
				assert.Equal(t, 2048, pub.N.BitLen())
			},
		},
		{
			name:      "rsa4096",
			algorithm: "rsa4096",
			checkType: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				pub, ok := signer.Public().(*rsa.PublicKey)
				require.True(t, ok, "expected *rsa.PublicKey, got %T", signer.Public())
				assert.Equal(t, 4096, pub.N.BitLen())
			},
		},
		{
			name:      "ecdsap256",
			algorithm: "ecdsap256",
			checkType: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				pub, ok := signer.Public().(*ecdsa.PublicKey)
				require.True(t, ok, "expected *ecdsa.PublicKey, got %T", signer.Public())
				assert.Equal(t, elliptic.P256(), pub.Curve)
			},
		},
		{
			name:      "ecdsap384",
			algorithm: "ecdsap384",
			checkType: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				pub, ok := signer.Public().(*ecdsa.PublicKey)
				require.True(t, ok, "expected *ecdsa.PublicKey, got %T", signer.Public())
				assert.Equal(t, elliptic.P384(), pub.Curve)
			},
		},
		{
			name:      "ed25519",
			algorithm: "ed25519",
			checkType: func(t *testing.T, signer crypto.Signer) {
				t.Helper()
				_, ok := signer.Public().(ed25519.PublicKey)
				require.True(t, ok, "expected ed25519.PublicKey, got %T", signer.Public())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewSoftwarePIVKeyGenerator()
			signer, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, tt.algorithm, "test-cn")
			require.NoError(t, err)
			require.NotNil(t, signer)
			tt.checkType(t, signer)
		})
	}
}

func TestSoftwarePIVKeyGenerator_DefaultAlgorithm(t *testing.T) {
	gen := NewSoftwarePIVKeyGenerator()

	signer, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "", "default-cn")
	require.NoError(t, err)
	require.NotNil(t, signer)

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "expected *ecdsa.PublicKey for default algorithm, got %T", signer.Public())
	assert.Equal(t, elliptic.P256(), pub.Curve)
}

func TestSoftwarePIVKeyGenerator_InvalidAlgorithm(t *testing.T) {
	gen := NewSoftwarePIVKeyGenerator()

	signer, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "invalid-algo", "test-cn")
	assert.Nil(t, signer)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVInvalidAlgorithm)
}

func TestSoftwarePIVKeyGenerator_GetSignerAfterGenerate(t *testing.T) {
	gen := NewSoftwarePIVKeyGenerator()

	cn := "piv-9a"
	original, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", cn)
	require.NoError(t, err)

	retrieved, err := gen.GetPIVSigner(pivcert.PIVSlotAuthentication, cn)
	require.NoError(t, err)
	assert.Equal(t, original, retrieved)
}

func TestSoftwarePIVKeyGenerator_GetSignerNotFound(t *testing.T) {
	gen := NewSoftwarePIVKeyGenerator()

	signer, err := gen.GetPIVSigner(pivcert.PIVSlotAuthentication, "nonexistent-cn")
	assert.Nil(t, signer)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVSignerNotAvailable)
}

func TestSoftwarePIVKeyGenerator_SignAndVerify(t *testing.T) {
	gen := NewSoftwarePIVKeyGenerator()

	signer, err := gen.GeneratePIVKey(pivcert.PIVSlotAuthentication, "ecdsap256", "sign-test-cn")
	require.NoError(t, err)

	// Sign test data
	data := []byte("test data for signing")
	digest := sha256.Sum256(data)

	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Verify signature with the public key
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok)

	valid := ecdsa.VerifyASN1(pub, digest[:], sig)
	assert.True(t, valid, "signature verification failed")
}
