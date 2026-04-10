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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// TestSupportedCurves_Default tests that SupportedCurves returns default curves
// when the PKCS#11 context is not initialized.
func TestSupportedCurves_Default(t *testing.T) {
	b := &Backend{
		config: &Config{
			Library:    "/usr/lib/softhsm/libsofthsm2.so",
			TokenLabel: "test-token",
		},
		p11ctx: nil, // Not initialized
	}

	curves := b.SupportedCurves()

	// Should return default NIST curves
	assert.Contains(t, curves, "P-256")
	assert.Contains(t, curves, "P-384")
	assert.Contains(t, curves, "P-521")
	assert.Len(t, curves, 3)
}

// TestDeriveKeyECDH_InvalidInputs tests DeriveKeyECDH with various invalid inputs.
func TestDeriveKeyECDH_InvalidInputs(t *testing.T) {
	b := &Backend{
		config: &Config{
			Library:    "/usr/lib/softhsm/libsofthsm2.so",
			TokenLabel: "test-token",
		},
	}

	ctx := context.Background()

	tests := []struct {
		name            string
		privateKeyAttrs *types.KeyAttributes
		peerPublicKey   []byte
		kdfParams       *types.KDFParams
		expectedErr     error
	}{
		{
			name:            "nil private key attributes",
			privateKeyAttrs: nil,
			peerPublicKey:   []byte{0x04, 0x01, 0x02},
			kdfParams:       types.DefaultKDFParams(),
			expectedErr:     ErrInvalidKeyAttributes,
		},
		{
			name: "empty peer public key",
			privateKeyAttrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.ECDSA,
			},
			peerPublicKey: []byte{},
			kdfParams:     types.DefaultKDFParams(),
			expectedErr:   ErrInvalidPeerPublicKey,
		},
		{
			name: "nil peer public key",
			privateKeyAttrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.ECDSA,
			},
			peerPublicKey: nil,
			kdfParams:     types.DefaultKDFParams(),
			expectedErr:   ErrInvalidPeerPublicKey,
		},
		{
			name: "nil KDF params",
			privateKeyAttrs: &types.KeyAttributes{
				CN:           "test-key",
				KeyAlgorithm: x509.ECDSA,
			},
			peerPublicKey: []byte{0x04, 0x01, 0x02},
			kdfParams:     nil,
			expectedErr:   ErrInvalidKDFParams,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.DeriveKeyECDH(ctx, tt.privateKeyAttrs, tt.peerPublicKey, tt.kdfParams)
			assert.True(t, errors.Is(err, tt.expectedErr), "expected %v, got %v", tt.expectedErr, err)
		})
	}
}

// TestDeriveKeyECDH_NotInitialized tests that DeriveKeyECDH returns an error
// when the backend is not initialized.
func TestDeriveKeyECDH_NotInitialized(t *testing.T) {
	b := &Backend{
		config: &Config{
			Library:    "/usr/lib/softhsm/libsofthsm2.so",
			TokenLabel: "test-token",
		},
	}

	ctx := context.Background()
	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	// Generate a valid peer public key for the test
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerPubBytes, err := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	_, err = b.DeriveKeyECDH(ctx, attrs, peerPubBytes, kdfParams)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// TestDeriveKeyECDH_InvalidKDFParams tests validation of KDF parameters.
func TestDeriveKeyECDH_InvalidKDFParams(t *testing.T) {
	b := &Backend{
		config: &Config{
			Library:    "/usr/lib/softhsm/libsofthsm2.so",
			TokenLabel: "test-token",
		},
	}

	ctx := context.Background()
	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerPubBytes, err := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	require.NoError(t, err)

	// Invalid KDF params - negative key length
	invalidParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: -1,
	}

	_, err = b.DeriveKeyECDH(ctx, attrs, peerPubBytes, invalidParams)
	assert.ErrorIs(t, err, ErrInvalidKDFParams)
}

// TestParsePeerPublicKey_DERFormat tests parsing DER-encoded public keys.
func TestParsePeerPublicKey_DERFormat(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		curveName string
	}{
		{"P-256", elliptic.P256(), "P-256"},
		{"P-384", elliptic.P384(), "P-384"},
		{"P-521", elliptic.P521(), "P-521"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a key pair
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			// Marshal to DER
			derBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			require.NoError(t, err)

			// Parse the DER bytes
			point, curve, err := parsePeerPublicKey(derBytes)
			require.NoError(t, err)

			// Verify the curve matches
			assert.Equal(t, tt.curve.Params().Name, curve.Params().Name)

			// Verify the point is in uncompressed format
			assert.Equal(t, byte(0x04), point[0])

			// Verify point size matches curve (uncompressed format: 0x04 || X || Y)
			// P-256: 1 + 32 + 32 = 65 bytes
			// P-384: 1 + 48 + 48 = 97 bytes
			// P-521: 1 + 66 + 66 = 133 bytes
			coordSize := (curve.Params().BitSize + 7) / 8
			expectedLen := 1 + 2*coordSize
			assert.Len(t, point, expectedLen)
		})
	}
}

// TestParsePeerPublicKey_RawFormat tests parsing raw EC point format.
func TestParsePeerPublicKey_RawFormat(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		pointSize int
	}{
		{"P-256", elliptic.P256(), 65},
		{"P-384", elliptic.P384(), 97},
		{"P-521", elliptic.P521(), 133},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a key pair
			key, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			// Marshal to uncompressed point
			rawPoint := elliptic.Marshal(tt.curve, key.PublicKey.X, key.PublicKey.Y)
			assert.Len(t, rawPoint, tt.pointSize)

			// Parse the raw point
			point, curve, err := parsePeerPublicKey(rawPoint)
			require.NoError(t, err)

			// Verify the curve matches
			assert.Equal(t, tt.curve.Params().Name, curve.Params().Name)

			// Verify the point is unchanged
			assert.Equal(t, rawPoint, point)
		})
	}
}

// TestParsePeerPublicKey_InvalidFormat tests parsing invalid public key formats.
func TestParsePeerPublicKey_InvalidFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "invalid prefix",
			input:   []byte{0x02, 0x01, 0x02, 0x03}, // Compressed format not supported
			wantErr: true,
		},
		{
			name:    "wrong size for uncompressed",
			input:   append([]byte{0x04}, make([]byte, 10)...), // Too short
			wantErr: true,
		},
		{
			name:    "invalid point - not on curve",
			input:   append([]byte{0x04}, make([]byte, 64)...), // P-256 size but invalid coordinates
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parsePeerPublicKey(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestApplyHKDF tests the HKDF implementation.
func TestApplyHKDF(t *testing.T) {
	secret := []byte("shared-secret-from-ecdh")
	salt := []byte("optional-salt")
	info := []byte("application-specific-info")
	keyLen := 32

	// Apply our HKDF
	derivedKey, err := applyHKDF(secret, salt, info, keyLen, sha256.New)
	require.NoError(t, err)
	assert.Len(t, derivedKey, keyLen)

	// Verify against standard library
	reader := hkdf.New(sha256.New, secret, salt, info)
	expectedKey := make([]byte, keyLen)
	_, err = io.ReadFull(reader, expectedKey)
	require.NoError(t, err)

	assert.Equal(t, expectedKey, derivedKey)
}

// TestApplyHKDF_DifferentKeySizes tests HKDF with various key sizes.
func TestApplyHKDF_DifferentKeySizes(t *testing.T) {
	secret := []byte("shared-secret")
	salt := []byte("salt")
	info := []byte("info")

	keySizes := []int{16, 32, 48, 64, 128}

	for _, size := range keySizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			key, err := applyHKDF(secret, salt, info, size, sha256.New)
			require.NoError(t, err)
			assert.Len(t, key, size)
		})
	}
}

// TestApplyX963KDF tests the ANSI X9.63 KDF implementation.
func TestApplyX963KDF(t *testing.T) {
	secret := []byte("shared-secret-from-ecdh")
	sharedInfo := []byte("shared-info")
	keyLen := 32

	// Apply X9.63 KDF
	derivedKey, err := applyX963KDF(secret, sharedInfo, keyLen, sha256.New)
	require.NoError(t, err)
	assert.Len(t, derivedKey, keyLen)

	// Verify determinism - same inputs should produce same output
	derivedKey2, err := applyX963KDF(secret, sharedInfo, keyLen, sha256.New)
	require.NoError(t, err)
	assert.Equal(t, derivedKey, derivedKey2)
}

// TestApplyX963KDF_LargeKey tests X9.63 KDF with key size larger than hash output.
func TestApplyX963KDF_LargeKey(t *testing.T) {
	secret := []byte("shared-secret")
	sharedInfo := []byte("info")
	keyLen := 64 // Larger than SHA-256 output (32 bytes)

	key, err := applyX963KDF(secret, sharedInfo, keyLen, sha256.New)
	require.NoError(t, err)
	assert.Len(t, key, keyLen)
}

// TestApplySP80056AKDF tests the NIST SP 800-56A KDF implementation.
func TestApplySP80056AKDF(t *testing.T) {
	secret := []byte("shared-secret-from-ecdh")
	otherInfo := []byte("other-info")
	keyLen := 32

	// Apply SP 800-56A KDF
	derivedKey, err := applySP80056AKDF(secret, otherInfo, keyLen, sha256.New)
	require.NoError(t, err)
	assert.Len(t, derivedKey, keyLen)

	// Verify determinism
	derivedKey2, err := applySP80056AKDF(secret, otherInfo, keyLen, sha256.New)
	require.NoError(t, err)
	assert.Equal(t, derivedKey, derivedKey2)

	// Verify it differs from X9.63 (different counter position)
	x963Key, err := applyX963KDF(secret, otherInfo, keyLen, sha256.New)
	require.NoError(t, err)
	assert.NotEqual(t, derivedKey, x963Key, "SP800-56A and X9.63 should produce different outputs")
}

// TestApplyKDF_SupportedAlgorithms tests that applyKDF supports the expected algorithms.
func TestApplyKDF_SupportedAlgorithms(t *testing.T) {
	secret := []byte("shared-secret")

	tests := []struct {
		name      string
		algorithm types.KDFAlgorithm
		wantErr   bool
	}{
		{
			name:      "HKDF",
			algorithm: types.KDFAlgorithmHKDF,
			wantErr:   false,
		},
		{
			name:      "X9.63",
			algorithm: types.KDFAlgorithmX963,
			wantErr:   false,
		},
		{
			name:      "SP800-56A",
			algorithm: types.KDFAlgorithmSP80056A,
			wantErr:   false,
		},
		{
			name:      "SP800-108-COUNTER (unsupported for ECDH)",
			algorithm: types.KDFAlgorithmSP800108Counter,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &types.KDFParams{
				Algorithm: tt.algorithm,
				Hash:      "SHA-256",
				KeyLength: 32,
			}

			_, err := applyKDF(secret, params)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGetHashFunc tests hash function lookup.
func TestGetHashFunc(t *testing.T) {
	tests := []struct {
		name        string
		hashName    string
		wantErr     bool
		expectedLen int // Hash output length
	}{
		{"SHA-256", "SHA-256", false, 32},
		{"SHA-384", "SHA-384", false, 48},
		{"SHA-512", "SHA-512", false, 64},
		{"Unknown", "SHA-1", true, 0},
		{"Empty", "", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashFunc, err := getHashFunc(tt.hashName)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, hashFunc)
			} else {
				require.NoError(t, err)
				require.NotNil(t, hashFunc)

				// Verify the hash produces expected length
				h := hashFunc()
				h.Write([]byte("test"))
				assert.Len(t, h.Sum(nil), tt.expectedLen)
			}
		})
	}
}

// TestBuildECDH1DeriveParams tests the ECDH parameter builder.
func TestBuildECDH1DeriveParams(t *testing.T) {
	publicData := []byte{0x04, 0x01, 0x02, 0x03}

	// Test with CKD_NULL and no shared data
	params := buildECDH1DeriveParams(CKD_NULL, nil, publicData)
	assert.NotEmpty(t, params)

	// Verify structure:
	// - 4 bytes: kdf (CKD_NULL = 1)
	// - 4 bytes: shared data length (0)
	// - 4 bytes: public data length (4)
	// - public data
	expectedLen := 4 + 4 + 4 + len(publicData)
	assert.Len(t, params, expectedLen)

	// Verify KDF type (little-endian)
	assert.Equal(t, byte(CKD_NULL), params[0])

	// Verify shared data length is 0
	assert.Equal(t, byte(0), params[4])

	// Verify public data length (little-endian)
	assert.Equal(t, byte(len(publicData)), params[8])
}

// TestBuildECDH1DeriveParams_WithSharedData tests parameter builder with shared data.
func TestBuildECDH1DeriveParams_WithSharedData(t *testing.T) {
	sharedData := []byte("shared-info")
	publicData := []byte{0x04, 0x01, 0x02, 0x03}

	params := buildECDH1DeriveParams(CKD_SHA256_KDF, sharedData, publicData)

	expectedLen := 4 + 4 + len(sharedData) + 4 + len(publicData)
	assert.Len(t, params, expectedLen)

	// Verify KDF type (little-endian)
	assert.Equal(t, byte(CKD_SHA256_KDF), params[0])
}

// TestSupportedCurves_Returns3Curves verifies the expected curve count.
func TestSupportedCurves_Returns3Curves(t *testing.T) {
	b := &Backend{
		config: &Config{
			Library:    "/usr/lib/softhsm/libsofthsm2.so",
			TokenLabel: "test-token",
		},
	}

	curves := b.SupportedCurves()
	assert.Len(t, curves, 3, "Expected exactly 3 supported curves (P-256, P-384, P-521)")
}

// TestDeriveKeyECDH_NilContext tests behavior with nil context parameter.
func TestDeriveKeyECDH_NilContext(t *testing.T) {
	b := &Backend{
		config: &Config{
			Library:    "/usr/lib/softhsm/libsofthsm2.so",
			TokenLabel: "test-token",
		},
	}

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
	}

	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerPubBytes, err := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	require.NoError(t, err)

	// Should handle nil context gracefully (use background)
	_, err = b.DeriveKeyECDH(nil, attrs, peerPubBytes, types.DefaultKDFParams())
	// Will fail at NotInitialized check, which is expected
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// TestKDFParamsValidation tests KDF parameter validation edge cases.
func TestKDFParamsValidation(t *testing.T) {
	tests := []struct {
		name    string
		params  *types.KDFParams
		wantErr bool
	}{
		{
			name: "valid default params",
			params: &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      "SHA-256",
				KeyLength: 32,
			},
			wantErr: false,
		},
		{
			name: "key length too large",
			params: &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      "SHA-256",
				KeyLength: 2000, // Exceeds 1024 byte limit
			},
			wantErr: true,
		},
		{
			name: "invalid hash algorithm",
			params: &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      "MD5", // Not supported
				KeyLength: 32,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.params.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestECDHMechanismConstants verifies the PKCS#11 constants are correct.
func TestECDHMechanismConstants(t *testing.T) {
	// Verify mechanism constants match PKCS#11 v2.40/v3.0 specification
	assert.Equal(t, uint(0x00001050), uint(CKM_ECDH1_DERIVE))
	assert.Equal(t, uint(0x00001051), uint(CKM_ECDH1_COFACTOR_DERIVE))

	// Verify KDF constants
	assert.Equal(t, uint(0x00000001), uint(CKD_NULL))
	assert.Equal(t, uint(0x00000002), uint(CKD_SHA1_KDF))
	assert.Equal(t, uint(0x00000006), uint(CKD_SHA256_KDF))
	assert.Equal(t, uint(0x00000007), uint(CKD_SHA384_KDF))
	assert.Equal(t, uint(0x00000008), uint(CKD_SHA512_KDF))
}
