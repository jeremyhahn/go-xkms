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

package agent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePublicKey_Ed25519_RawBytes(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Parse raw Ed25519 public key (32 bytes)
	result, err := parsePublicKey([]byte(pub), "ed25519")
	require.NoError(t, err)

	parsed, ok := result.(ed25519.PublicKey)
	require.True(t, ok)
	assert.Equal(t, pub, parsed)
}

func TestParsePublicKey_Ed25519_PKIX(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Encode as PKIX
	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	// Parse PKIX-encoded Ed25519 key
	result, err := parsePublicKey(pkixBytes, "ed25519")
	require.NoError(t, err)

	parsed, ok := result.(ed25519.PublicKey)
	require.True(t, ok)
	assert.Equal(t, pub, parsed)
}

func TestParsePublicKey_Ed25519_CaseVariants(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	variants := []string{"ed25519", "Ed25519", "ED25519"}

	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			result, err := parsePublicKey([]byte(pub), variant)
			require.NoError(t, err)

			parsed, ok := result.(ed25519.PublicKey)
			require.True(t, ok)
			assert.Equal(t, pub, parsed)
		})
	}
}

func TestParsePublicKey_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode as PKIX
	pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	// Parse PKIX-encoded RSA key
	result, err := parsePublicKey(pkixBytes, "rsa")
	require.NoError(t, err)

	parsed, ok := result.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.N, parsed.N)
	assert.Equal(t, priv.PublicKey.E, parsed.E)
}

func TestParsePublicKey_RSA_CaseVariants(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	variants := []string{"rsa", "RSA"}

	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			result, err := parsePublicKey(pkixBytes, variant)
			require.NoError(t, err)

			_, ok := result.(*rsa.PublicKey)
			require.True(t, ok)
		})
	}
}

func TestParsePublicKey_ECDSA(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			// Encode as PKIX
			pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			require.NoError(t, err)

			// Parse PKIX-encoded ECDSA key
			result, err := parsePublicKey(pkixBytes, "ecdsa")
			require.NoError(t, err)

			parsed, ok := result.(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, priv.PublicKey.X, parsed.X)
			assert.Equal(t, priv.PublicKey.Y, parsed.Y)
		})
	}
}

func TestParsePublicKey_ECDSA_CurveVariants(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	variants := []string{"ecdsa", "ECDSA", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"}

	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			result, err := parsePublicKey(pkixBytes, variant)
			require.NoError(t, err)

			_, ok := result.(*ecdsa.PublicKey)
			require.True(t, ok)
		})
	}
}

func TestParsePublicKey_UnsupportedKeyType(t *testing.T) {
	_, err := parsePublicKey([]byte("data"), "unsupported-type")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestParsePublicKey_InvalidData(t *testing.T) {
	// Invalid data should fail for all key types
	invalidData := []byte("this is not valid key data")

	tests := []string{"rsa", "ecdsa", "ed25519"}

	for _, keyType := range tests {
		t.Run(keyType, func(t *testing.T) {
			_, err := parsePublicKey(invalidData, keyType)
			assert.Error(t, err)
		})
	}
}

func TestParseSubjectPublicKeyInfo_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	result, err := parseSubjectPublicKeyInfo(pkixBytes)
	require.NoError(t, err)

	parsed, ok := result.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.N, parsed.N)
}

func TestParseSubjectPublicKeyInfo_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	result, err := parseSubjectPublicKeyInfo(pkixBytes)
	require.NoError(t, err)

	parsed, ok := result.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.X, parsed.X)
}

func TestParseSubjectPublicKeyInfo_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	result, err := parseSubjectPublicKeyInfo(pkixBytes)
	require.NoError(t, err)

	parsed, ok := result.(ed25519.PublicKey)
	require.True(t, ok)
	assert.Equal(t, pub, parsed)
}

func TestParseSubjectPublicKeyInfo_InvalidData(t *testing.T) {
	_, err := parseSubjectPublicKeyInfo([]byte("invalid data"))
	assert.Error(t, err)
}

func TestParseRSAPublicKey_Valid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Marshal to PKCS#1 format
	pub := rsaPublicKey{
		N: priv.PublicKey.N,
		E: priv.PublicKey.E,
	}
	pkcs1Bytes, err := asn1.Marshal(pub)
	require.NoError(t, err)

	result, err := parseRSAPublicKey(pkcs1Bytes)
	require.NoError(t, err)

	assert.Equal(t, priv.PublicKey.N, result.N)
	assert.Equal(t, priv.PublicKey.E, result.E)
}

func TestParseRSAPublicKey_InvalidASN1(t *testing.T) {
	_, err := parseRSAPublicKey([]byte("invalid asn1"))
	assert.Error(t, err)
}

func TestParseRSAPublicKey_TrailingData(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub := rsaPublicKey{
		N: priv.PublicKey.N,
		E: priv.PublicKey.E,
	}
	pkcs1Bytes, err := asn1.Marshal(pub)
	require.NoError(t, err)

	// Add trailing data
	pkcs1Bytes = append(pkcs1Bytes, []byte("trailing data")...)

	_, err = parseRSAPublicKey(pkcs1Bytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trailing data")
}

func TestParseRSAPublicKey_InvalidN(t *testing.T) {
	// N with negative sign
	pub := rsaPublicKey{
		N: big.NewInt(-1),
		E: 65537,
	}
	pkcs1Bytes, err := asn1.Marshal(pub)
	require.NoError(t, err)

	_, err = parseRSAPublicKey(pkcs1Bytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid RSA public key")
}

func TestParseRSAPublicKey_InvalidE(t *testing.T) {
	// E with zero value
	pub := rsaPublicKey{
		N: big.NewInt(12345),
		E: 0,
	}
	pkcs1Bytes, err := asn1.Marshal(pub)
	require.NoError(t, err)

	_, err = parseRSAPublicKey(pkcs1Bytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid RSA public key")
}

func TestParseRSAPublicKey_ZeroN(t *testing.T) {
	// N with zero value
	pub := rsaPublicKey{
		N: big.NewInt(0),
		E: 65537,
	}
	pkcs1Bytes, err := asn1.Marshal(pub)
	require.NoError(t, err)

	_, err = parseRSAPublicKey(pkcs1Bytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid RSA public key")
}

func TestParsePublicKeyPKIX_PKIX(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkixBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	result, err := parsePublicKeyPKIX(pkixBytes)
	require.NoError(t, err)

	parsed, ok := result.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.N, parsed.N)
}

func TestParsePublicKeyPKIX_PKCS1(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Marshal to PKCS#1 format
	pub := rsaPublicKey{
		N: priv.PublicKey.N,
		E: priv.PublicKey.E,
	}
	pkcs1Bytes, err := asn1.Marshal(pub)
	require.NoError(t, err)

	result, err := parsePublicKeyPKIX(pkcs1Bytes)
	require.NoError(t, err)

	parsed, ok := result.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.N, parsed.N)
}

func TestParsePublicKeyPKIX_InvalidData(t *testing.T) {
	_, err := parsePublicKeyPKIX([]byte("completely invalid data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse public key")
}

func TestRSAPublicKeyStruct(t *testing.T) {
	// Test the rsaPublicKey struct directly
	pub := rsaPublicKey{
		N: big.NewInt(12345),
		E: 65537,
	}

	assert.Equal(t, big.NewInt(12345), pub.N)
	assert.Equal(t, 65537, pub.E)
}

func TestParsePublicKey_Ed25519_WrongSize(t *testing.T) {
	// Ed25519 key that's not 32 bytes should fall back to PKIX parsing
	wrongSizeData := make([]byte, 16)
	_, err := rand.Read(wrongSizeData)
	require.NoError(t, err)

	// This should fail because it's not valid PKIX either
	_, err = parsePublicKey(wrongSizeData, "ed25519")
	assert.Error(t, err)
}

func TestParsePublicKey_EmptyData(t *testing.T) {
	tests := []string{"ed25519", "rsa", "ecdsa"}

	for _, keyType := range tests {
		t.Run(keyType, func(t *testing.T) {
			_, err := parsePublicKey([]byte{}, keyType)
			assert.Error(t, err)
		})
	}
}

func TestParsePublicKey_NilData(t *testing.T) {
	tests := []string{"ed25519", "rsa", "ecdsa"}

	for _, keyType := range tests {
		t.Run(keyType, func(t *testing.T) {
			_, err := parsePublicKey(nil, keyType)
			assert.Error(t, err)
		})
	}
}

func TestParseSubjectPublicKeyInfo_EmptyData(t *testing.T) {
	_, err := parseSubjectPublicKeyInfo([]byte{})
	assert.Error(t, err)
}

func TestParseRSAPublicKey_EmptyData(t *testing.T) {
	_, err := parseRSAPublicKey([]byte{})
	assert.Error(t, err)
}

func TestParsePublicKeyPKIX_EmptyData(t *testing.T) {
	_, err := parsePublicKeyPKIX([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse public key")
}
