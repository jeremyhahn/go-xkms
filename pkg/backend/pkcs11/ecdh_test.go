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
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
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
			rawPoint := elliptic.Marshal(tt.curve, key.X, key.Y) //nolint:staticcheck // SA1019: builds the uncompressed-point wire format parsePeerPublicKey (pkcs11_ecdh.go) accepts; crypto/ecdh migration is a separate, behavior-sensitive change
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

// Convergence anchors. These literals are duplicated verbatim in the KDF
// tests of pkg/types, pkg/backend/tpm2, pkg/backend/software, and
// pkg/backend/phone. Four independently asserted copies are the point: they
// prove the backends share one KDF implementation rather than four that
// happen to be close. Their correctness is established by the NIST CAVP
// vectors in pkg/crypto/kdf/sp800108_test.go.
//
// Inputs: sharedSecret = 32 bytes of 0x42, Label = "xkms-convergence",
// Context = "backend-parity", SHA-256, 64-byte output. The length spans two
// SHA-256 PRF blocks so counter mode and feedback mode diverge.
const (
	convergenceLabel     = "xkms-convergence"
	convergenceContext   = "backend-parity"
	convergenceKeyLength = 64

	convergenceSP800108Counter = "b2b1c48c1f3282fe4be0e659653963733359b841e176e7bd39dac36bc31a7a37" +
		"79bc86106be0de29d2a74eb0b87ba4a0e2de5da0150c7e2a2c56c3a957e7e855"

	convergenceSP800108Feedback = "b2b1c48c1f3282fe4be0e659653963733359b841e176e7bd39dac36bc31a7a37" +
		"08ef3fb21ccf13af443722edfd6a91bc9c0b7286da80d4b269ee2156590d0706"
)

func convergenceSecret() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func convergenceParams(algorithm types.KDFAlgorithm) *types.KDFParams {
	return &types.KDFParams{
		Algorithm: algorithm,
		Hash:      "SHA-256",
		KeyLength: convergenceKeyLength,
		Label:     []byte(convergenceLabel),
		Context:   []byte(convergenceContext),
	}
}

// TestApplyKDF_SP800108ConvergesWithOtherBackends asserts the PKCS#11 backend
// derives the same bytes as every other backend for the same inputs.
func TestApplyKDF_SP800108ConvergesWithOtherBackends(t *testing.T) {
	for _, tc := range []struct {
		algorithm types.KDFAlgorithm
		want      string
	}{
		{types.KDFAlgorithmSP800108Counter, convergenceSP800108Counter},
		{types.KDFAlgorithmSP800108Feedback, convergenceSP800108Feedback},
	} {
		t.Run(tc.algorithm.String(), func(t *testing.T) {
			key, err := applyKDF(convergenceSecret(), convergenceParams(tc.algorithm))
			require.NoError(t, err)

			want, err := hex.DecodeString(tc.want)
			require.NoError(t, err)
			assert.Equal(t, want, key, "backend diverged from the canonical KDF")
		})
	}
}

// TestApplyKDF_SP800108IsNotHKDF is the regression that catches a return to
// deriving these algorithm labels with HKDF.
func TestApplyKDF_SP800108IsNotHKDF(t *testing.T) {
	secret := convergenceSecret()

	bareHKDF := make([]byte, convergenceKeyLength)
	_, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, nil), bareHKDF)
	require.NoError(t, err)

	for _, algorithm := range []types.KDFAlgorithm{types.KDFAlgorithmSP800108Counter, types.KDFAlgorithmSP800108Feedback} {
		t.Run(algorithm.String(), func(t *testing.T) {
			key, err := applyKDF(secret, convergenceParams(algorithm))
			require.NoError(t, err)
			assert.NotEqual(t, bareHKDF, key, "the SP 800-108 construction has regressed to HKDF")
		})
	}
}

// TestApplyKDF_LabelAndContextReachTheKDF proves the backend forwards the
// caller's SP 800-108 inputs rather than dropping them.
func TestApplyKDF_LabelAndContextReachTheKDF(t *testing.T) {
	secret := convergenceSecret()

	reference, err := applyKDF(secret, convergenceParams(types.KDFAlgorithmSP800108Counter))
	require.NoError(t, err)

	changedLabel := convergenceParams(types.KDFAlgorithmSP800108Counter)
	changedLabel.Label = []byte("a different label")
	key, err := applyKDF(secret, changedLabel)
	require.NoError(t, err)
	assert.NotEqual(t, reference, key, "changing Label did not change the derived key")

	changedContext := convergenceParams(types.KDFAlgorithmSP800108Counter)
	changedContext.Context = []byte("a different context")
	key, err = applyKDF(secret, changedContext)
	require.NoError(t, err)
	assert.NotEqual(t, reference, key, "changing Context did not change the derived key")
}

// TestApplyKDF_HKDFMatchesRFC5869 pins the HKDF branch against the reference
// implementation so the shared derivation path cannot drift.
func TestApplyKDF_HKDFMatchesRFC5869(t *testing.T) {
	secret := []byte("shared-secret-from-ecdh")
	salt := []byte("optional-salt")
	info := []byte("application-specific-info")

	for _, keyLen := range []int{16, 32, 48, 64} {
		derived, err := applyKDF(secret, &types.KDFParams{
			Algorithm: types.KDFAlgorithmHKDF,
			Hash:      "SHA-256",
			Salt:      salt,
			Info:      info,
			KeyLength: keyLen,
		})
		require.NoError(t, err)

		expected := make([]byte, keyLen)
		_, err = io.ReadFull(hkdf.New(sha256.New, secret, salt, info), expected)
		require.NoError(t, err)
		assert.Equal(t, expected, derived)
	}
}

// TestApplyKDF_ConcatKDFsDiffer confirms the X9.63 and SP 800-56A
// concatenation KDFs remain distinct constructions on this backend.
func TestApplyKDF_ConcatKDFsDiffer(t *testing.T) {
	secret := []byte("shared-secret-from-ecdh")

	params := func(algorithm types.KDFAlgorithm) *types.KDFParams {
		return &types.KDFParams{
			Algorithm: algorithm,
			Hash:      "SHA-256",
			Info:      []byte("shared-info"),
			KeyLength: 32,
		}
	}

	x963, err := applyKDF(secret, params(types.KDFAlgorithmX963))
	require.NoError(t, err)
	assert.Len(t, x963, 32)

	concat, err := applyKDF(secret, params(types.KDFAlgorithmSP80056A))
	require.NoError(t, err)
	assert.Len(t, concat, 32)

	assert.NotEqual(t, x963, concat, "X9.63 and SP 800-56A should differ in counter position")

	// Both must be deterministic.
	again, err := applyKDF(secret, params(types.KDFAlgorithmX963))
	require.NoError(t, err)
	assert.Equal(t, x963, again)
}

// TestApplyKDF_SupportedAlgorithms tests that applyKDF supports every
// algorithm the canonical KDF implements, including the SP 800-108 modes that
// this backend used to reject.
func TestApplyKDF_SupportedAlgorithms(t *testing.T) {
	secret := []byte("shared-secret")

	supported := []types.KDFAlgorithm{
		types.KDFAlgorithmHKDF,
		types.KDFAlgorithmX963,
		types.KDFAlgorithmSP80056A,
		types.KDFAlgorithmSP800108Counter,
		types.KDFAlgorithmSP800108Feedback,
	}

	for _, algorithm := range supported {
		t.Run(algorithm.String(), func(t *testing.T) {
			key, err := applyKDF(secret, &types.KDFParams{
				Algorithm: algorithm,
				Hash:      "SHA-256",
				KeyLength: 32,
			})
			require.NoError(t, err)
			assert.Len(t, key, 32)
		})
	}

	for _, algorithm := range []types.KDFAlgorithm{"PBKDF2", "Argon2id", ""} {
		t.Run("rejects "+string(algorithm), func(t *testing.T) {
			_, err := applyKDF(secret, &types.KDFParams{
				Algorithm: algorithm,
				Hash:      "SHA-256",
				KeyLength: 32,
			})
			assert.ErrorIs(t, err, types.ErrUnsupportedKDFAlgorithm)
		})
	}
}

// TestApplyKDF_RejectsInapplicableParameters proves a parameter the selected
// algorithm does not consume is rejected rather than silently dropped.
func TestApplyKDF_RejectsInapplicableParameters(t *testing.T) {
	cases := []struct {
		name   string
		params *types.KDFParams
	}{
		{"SP800-108 with HKDF salt", &types.KDFParams{Algorithm: types.KDFAlgorithmSP800108Counter, Hash: "SHA-256", KeyLength: 32, Salt: []byte("salt")}},
		{"SP800-108 with HKDF info", &types.KDFParams{Algorithm: types.KDFAlgorithmSP800108Counter, Hash: "SHA-256", KeyLength: 32, Info: []byte("info")}},
		{"X9.63 with a salt", &types.KDFParams{Algorithm: types.KDFAlgorithmX963, Hash: "SHA-256", KeyLength: 32, Salt: []byte("salt")}},
		{"counter mode with a feedback IV", &types.KDFParams{Algorithm: types.KDFAlgorithmSP800108Counter, Hash: "SHA-256", KeyLength: 32, IV: []byte("iv")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := applyKDF(convergenceSecret(), tc.params)
			assert.ErrorIs(t, err, types.ErrKDFParamNotApplicable)
		})
	}
}

// TestApplyKDF_NilParams rejects a missing parameter set.
func TestApplyKDF_NilParams(t *testing.T) {
	_, err := applyKDF([]byte("shared-secret"), nil)
	assert.ErrorIs(t, err, ErrInvalidKDFParams)
}

// TestApplyKDF_HashAlgorithms covers the approved and unapproved hash names.
func TestApplyKDF_HashAlgorithms(t *testing.T) {
	secret := []byte("shared-secret")

	for _, tt := range []struct {
		hash        string
		expectedLen int
	}{
		{"SHA-256", 32},
		{"SHA-384", 48},
		{"SHA-512", 64},
		{"SHA3-256", 32},
	} {
		t.Run(tt.hash, func(t *testing.T) {
			key, err := applyKDF(secret, &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      tt.hash,
				KeyLength: tt.expectedLen,
			})
			require.NoError(t, err)
			assert.Len(t, key, tt.expectedLen)
		})
	}

	// SHA-1 and MD5 name real hashes but are not approved KDF pseudorandom
	// functions.
	for _, hash := range []string{"SHA-1", "MD5", "", "sha256", "invalid"} {
		t.Run("rejects "+hash, func(t *testing.T) {
			_, err := applyKDF(secret, &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      hash,
				KeyLength: 32,
			})
			assert.ErrorIs(t, err, types.ErrUnsupportedKDFHash)
		})
	}
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
	_, err = b.DeriveKeyECDH(nil, attrs, peerPubBytes, types.DefaultKDFParams()) //nolint:staticcheck // SA1012: deliberately proving the nil-tolerant contract DeriveKeyECDH documents
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

// =============================================================================
// Real-token ECDH key agreement (SoftHSM2)
//
// A derived shared secret is only meaningful if both parties compute the same
// value, so every test below runs the peer half in software with crypto/ecdh
// and compares. Round-tripping a value through the token alone would agree with
// itself no matter what the token actually computed.
// =============================================================================

// provisionDerivableECKey generates an EC key pair on the token through the
// production path and returns the attributes that address it.
//
// Every ECDH test below drives Backend.GenerateECDSAWithCurve rather than
// building its own templates, so the objects under test are byte for byte the
// ones a caller gets. This helper used to hand-roll the key pair to add
// CKA_DERIVE, which the backend's own generation template omitted; that kept
// the suite green while the only combination a caller can actually reach --
// generate here, then derive here -- failed on the token with
// CKR_KEY_FUNCTION_NOT_PERMITTED.
func provisionDerivableECKey(t *testing.T, b *Backend, cn string, curve elliptic.Curve) *types.KeyAttributes {
	t.Helper()

	attrs := &types.KeyAttributes{
		CN:            cn,
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_PKCS11,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: curve},
	}

	_, err := b.GenerateECDSAWithCurve(attrs, curve)
	require.NoError(t, err, "the backend must generate a derivable EC key pair")

	return attrs
}

// tokenECDHPublicKey reads the token key's public half back out through the
// backend's own accessor and converts it for use with crypto/ecdh.
func tokenECDHPublicKey(t *testing.T, b *Backend, attrs *types.KeyAttributes) *ecdh.PublicKey {
	t.Helper()

	der, err := b.GetPublicKeyBytes(attrs)
	require.NoError(t, err, "the backend must export the token key's public half")

	parsed, err := x509.ParsePKIXPublicKey(der)
	require.NoError(t, err, "GetPublicKeyBytes must emit valid SubjectPublicKeyInfo")

	ecdsaPub, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok, "an EC key must export as an ECDSA public key")

	ecdhPub, err := ecdsaPub.ECDH()
	require.NoError(t, err)
	return ecdhPub
}

// ecdhCurveFor maps a NIST curve to its crypto/ecdh counterpart.
func ecdhCurveFor(t *testing.T, curve elliptic.Curve) ecdh.Curve {
	t.Helper()

	switch curve.Params().Name {
	case elliptic.P256().Params().Name:
		return ecdh.P256()
	case elliptic.P384().Params().Name:
		return ecdh.P384()
	case elliptic.P521().Params().Name:
		return ecdh.P521()
	}
	t.Fatalf("no crypto/ecdh curve for %s", curve.Params().Name)
	return nil
}

// TestDeriveKeyECDH_MatchesPeerComputedSecret is the core correctness test for
// hardware ECDH: the token derives from its private key and the caller's peer
// point, crypto/ecdh derives from the peer private key and the token's public
// point, and the two must agree on every supported curve.
func TestDeriveKeyECDH_MatchesPeerComputedSecret(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			b := newProvisionedBackend(t, "ecdh-agree")
			attrs := provisionDerivableECKey(t, b, "ecdh-agree-"+curve.Params().Name, curve)

			peerPrivate, err := ecdhCurveFor(t, curve).GenerateKey(rand.Reader)
			require.NoError(t, err)

			peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
			require.NoError(t, err)

			kdfParams := &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      "SHA-256",
				Info:      []byte("pkcs11-ecdh-agreement"),
				KeyLength: 32,
			}

			derived, err := b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, kdfParams)
			require.NoError(t, err, "the token must derive against a valid peer key")

			// Oracle: the same agreement computed entirely in software from the
			// other side.
			peerSecret, err := peerPrivate.ECDH(tokenECDHPublicKey(t, b, attrs))
			require.NoError(t, err)
			expected, err := applyKDF(peerSecret, kdfParams)
			require.NoError(t, err)

			assert.Equal(t, expected, derived,
				"the HSM and the peer disagree on the ECDH shared secret")

			// A shared secret the size of the field element is what CKD_NULL
			// promises; anything shorter means the token stripped leading zero
			// bytes and the two sides would disagree intermittently.
			assert.Len(t, peerSecret, (curve.Params().BitSize+7)/8)
		})
	}
}

// TestDeriveKeyECDH_AcceptsRawPointAndSPKI proves the two accepted peer key
// encodings name the same key. A caller that sends a bare uncompressed point
// must get the identical derived key as one that sends SubjectPublicKeyInfo.
func TestDeriveKeyECDH_AcceptsRawPointAndSPKI(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-encodings")
	attrs := provisionDerivableECKey(t, b, "ecdh-encodings-key", elliptic.P256())

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)
	peerPoint := peerPrivate.PublicKey().Bytes() // uncompressed 0x04 || X || Y

	kdfParams := types.DefaultKDFParams()

	fromSPKI, err := b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, kdfParams)
	require.NoError(t, err)

	fromPoint, err := b.DeriveKeyECDH(context.Background(), attrs, peerPoint, kdfParams)
	require.NoError(t, err)

	assert.Equal(t, fromSPKI, fromPoint, "peer key encoding must not change the derived key")

	peerSecret, err := peerPrivate.ECDH(tokenECDHPublicKey(t, b, attrs))
	require.NoError(t, err)
	expected, err := applyKDF(peerSecret, kdfParams)
	require.NoError(t, err)
	assert.Equal(t, expected, fromSPKI)
}

// TestDeriveKeyECDH_CurveMismatch verifies the backend refuses to derive
// against a peer key from a different curve.
//
// types.KeyAgreementProvider documents ErrCurveMismatch for this case and the
// software backend already returns it. Leaving the decision to the token is not
// acceptable: the peer point is not a member of the private key's group, so
// whatever comes back is not a shared secret.
func TestDeriveKeyECDH_CurveMismatch(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-mismatch")
	attrs := provisionDerivableECKey(t, b, "ecdh-mismatch-key", elliptic.P256())

	for _, tc := range []struct {
		name      string
		peerCurve ecdh.Curve
	}{
		{"P-384 peer", ecdh.P384()},
		{"P-521 peer", ecdh.P521()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			peerPrivate, err := tc.peerCurve.GenerateKey(rand.Reader)
			require.NoError(t, err)
			peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
			require.NoError(t, err)

			_, err = b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, types.DefaultKDFParams())
			assert.ErrorIs(t, err, ErrCurveMismatch)
		})
	}
}

// TestDeriveKeyECDH_KeyNotFound verifies a missing private key surfaces the
// canonical backend.ErrKeyNotFound rather than a PKCS#11 error code.
func TestDeriveKeyECDH_KeyNotFound(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-missing")

	attrs := &types.KeyAttributes{
		CN:            "ecdh-key-that-was-never-created",
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_PKCS11,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)

	_, err = b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, types.DefaultKDFParams())
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// TestDeriveKeyECDH_MalformedPeerKey verifies that peer key bytes which are
// neither SubjectPublicKeyInfo nor a valid uncompressed point are rejected
// before any token operation.
func TestDeriveKeyECDH_MalformedPeerKey(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-malformed")
	attrs := provisionDerivableECKey(t, b, "ecdh-malformed-key", elliptic.P256())

	// A 65-byte buffer with the uncompressed marker but coordinates that are
	// not on P-256. Rejecting this is what stops an invalid-curve attack, in
	// which a peer submits a point on a weaker curve to leak private key bits
	// through the derived secret.
	offCurve := make([]byte, 65)
	offCurve[0] = 0x04
	offCurve[64] = 0x01

	for _, tc := range []struct {
		name string
		peer []byte
	}{
		{"point not on the curve", offCurve},
		{"truncated point", []byte{0x04, 0x01, 0x02, 0x03}},
		{"random bytes", []byte("this is not a public key at all")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.DeriveKeyECDH(context.Background(), attrs, tc.peer, types.DefaultKDFParams())
			require.Error(t, err)
			assert.NotErrorIs(t, err, backend.ErrKeyNotFound,
				"a malformed peer key must fail parsing, not key lookup")
		})
	}
}

// TestDeriveKeyECDH_KDFParamsChangeTheKey proves the KDF is actually applied to
// the shared secret rather than the raw secret being returned. Two derivations
// from one agreement must differ when only the KDF inputs differ.
func TestDeriveKeyECDH_KDFParamsChangeTheKey(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-kdf")
	attrs := provisionDerivableECKey(t, b, "ecdh-kdf-key", elliptic.P256())

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)

	base := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Info:      []byte("context-a"),
		KeyLength: 32,
	}
	other := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		Info:      []byte("context-b"),
		KeyLength: 32,
	}

	first, err := b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, base)
	require.NoError(t, err)
	second, err := b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, other)
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "the KDF info string did not reach the derivation")

	// The same inputs must be reproducible, or the agreement is not usable for
	// establishing a channel key.
	repeat, err := b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, base)
	require.NoError(t, err)
	assert.Equal(t, first, repeat)

	// And the raw secret must not be what is handed back.
	rawSecret, err := peerPrivate.ECDH(tokenECDHPublicKey(t, b, attrs))
	require.NoError(t, err)
	assert.NotEqual(t, rawSecret, first, "the raw ECDH secret escaped without a KDF")
}

// TestGetPublicKeyBytes_RoundTrips verifies the exported public key parses as
// SubjectPublicKeyInfo and names the curve the key was generated on.
func TestGetPublicKeyBytes_RoundTrips(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-pubkey")

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			attrs := provisionDerivableECKey(t, b, "pubkey-"+curve.Params().Name, curve)

			der, err := b.GetPublicKeyBytes(attrs)
			require.NoError(t, err)

			parsed, err := x509.ParsePKIXPublicKey(der)
			require.NoError(t, err)

			pub, ok := parsed.(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, curve.Params().Name, pub.Curve.Params().Name)
			assert.True(t, pub.IsOnCurve(pub.X, pub.Y), "the exported point must be on the curve") //nolint:staticcheck // SA1019: on-curve validation of the parsed point; crypto/ecdh migration is a separate, behavior-sensitive change
		})
	}
}

// TestGetPublicKeyBytes_KeyNotFound verifies the error path for a key that does
// not exist on the token.
func TestGetPublicKeyBytes_KeyNotFound(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-pubkey-missing")

	attrs := &types.KeyAttributes{
		CN:           "public-key-that-does-not-exist",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_PKCS11,
		KeyAlgorithm: x509.ECDSA,
	}

	_, err := b.GetPublicKeyBytes(attrs)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// TestRequireMatchingCurve_AcceptsAndRejects exercises the curve comparison
// directly against CKA_EC_PARAMS as the token stores it.
func TestRequireMatchingCurve_AcceptsAndRejects(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-curvecheck")
	attrs := provisionDerivableECKey(t, b, "curvecheck-key", elliptic.P256())

	session := openIntrospectionSession(t, b)
	handle, err := b.findPrivateKeyHandle(session, attrs)
	require.NoError(t, err)

	assert.NoError(t, b.requireMatchingCurve(session, handle, elliptic.P256()),
		"the key's own curve must be accepted")

	assert.ErrorIs(t, b.requireMatchingCurve(session, handle, elliptic.P384()), ErrCurveMismatch)

	// A curve the backend has no OID for cannot be compared, so it must be
	// refused rather than assumed to match.
	assert.ErrorIs(t, b.requireMatchingCurve(session, handle, elliptic.P224()), ErrECDHNotSupported)
}

// TestFindPrivateKeyHandle_FoundAndMissing covers both outcomes of the private
// key lookup used by every ECDH derivation.
func TestFindPrivateKeyHandle_FoundAndMissing(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-findpriv")
	attrs := provisionDerivableECKey(t, b, "findpriv-key", elliptic.P256())

	session := openIntrospectionSession(t, b)

	handle, err := b.findPrivateKeyHandle(session, attrs)
	require.NoError(t, err)
	assert.NotZero(t, handle, "a found object must have a non-zero handle")

	missing := &types.KeyAttributes{
		CN:           "findpriv-key-absent",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_PKCS11,
		KeyAlgorithm: x509.ECDSA,
	}
	_, err = b.findPrivateKeyHandle(session, missing)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}

// TestDeriveKeyECDH_HonoursTokenLabel is the regression test for slot
// resolution. DeriveKeyECDH used to take the first slot the module enumerated
// whenever no explicit slot was configured, which silently ignored the
// configured token label; on a host with more than one token that derives
// against the wrong device. Pointing the backend at a label no token carries
// must therefore fail, not fall through to slot zero.
func TestDeriveKeyECDH_HonoursTokenLabel(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-tokenlabel")
	attrs := provisionDerivableECKey(t, b, "tokenlabel-key", elliptic.P256())

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)

	// Sanity: the derivation works while the label is correct.
	_, err = b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, types.DefaultKDFParams())
	require.NoError(t, err)

	b.config.TokenLabel = "a-token-that-is-not-present"
	_, err = b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, types.DefaultKDFParams())
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

// TestDeriveKeyECDH_ExplicitSlotWins verifies that a slot pinned in the
// configuration overrides label discovery, since PKCS#11 slot IDs are assigned
// by the module and an operator who pins one means it.
func TestDeriveKeyECDH_ExplicitSlotWins(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-explicitslot")
	attrs := provisionDerivableECKey(t, b, "explicitslot-key", elliptic.P256())

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)

	b.mu.Lock()
	slot, err := b.resolveSlot()
	b.mu.Unlock()
	require.NoError(t, err)

	pinned := int(slot)
	b.config.Slot = &pinned
	b.config.TokenLabel = "a-token-that-is-not-present"

	_, err = b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, types.DefaultKDFParams())
	assert.NoError(t, err, "an explicitly configured slot must bypass label lookup")
}

// TestEnsureP11Context_IdempotentAndFailsOnBadLibrary covers both outcomes of
// lazy context initialization.
func TestEnsureP11Context_IdempotentAndFailsOnBadLibrary(t *testing.T) {
	t.Run("reuses an existing context", func(t *testing.T) {
		b := newProvisionedBackend(t, "ecdh-ctx")

		b.mu.Lock()
		defer b.mu.Unlock()

		existing := b.p11ctx
		require.NotNil(t, existing)
		require.NoError(t, b.ensureP11Context())
		assert.Same(t, existing, b.p11ctx,
			"re-initializing would orphan the sessions already open on the old context")
	})

	t.Run("rejects a library that cannot be loaded", func(t *testing.T) {
		b := &Backend{config: &Config{
			Library:    filepath.Join(t.TempDir(), "libnotreal.so"),
			TokenLabel: "absent",
		}}

		err := b.ensureP11Context()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load PKCS#11 library")
		assert.Nil(t, b.p11ctx, "a failed load must not leave a context behind")
	})
}

// TestSupportedCurves_RealToken verifies curve discovery against a token that
// actually reports its mechanism list, rather than the hard-coded fallback.
func TestSupportedCurves_RealToken(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-curves")

	curves := b.SupportedCurves()
	assert.Equal(t, []string{"P-256", "P-384", "P-521"}, curves,
		"SoftHSM2 advertises CKM_ECDH1_DERIVE and CKM_EC_KEY_PAIR_GEN")
}

// TestParsePeerPublicKey_NonECPublicKey verifies an RSA SubjectPublicKeyInfo is
// rejected. It parses cleanly as PKIX, so only the type check stops it from
// reaching the token as if it were an EC point.
func TestParsePeerPublicKey_NonECPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)

	_, _, err = parsePeerPublicKey(der)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an ECDSA key")
}

// TestParsePeerPublicKey_OctetStringWrapped verifies the ASN.1 OCTET STRING
// unwrapping path. CKA_EC_POINT is stored that way by most tokens, so a peer
// that copies the attribute value verbatim sends a wrapped point.
func TestParsePeerPublicKey_OctetStringWrapped(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rawPoint := elliptic.Marshal(elliptic.P256(), key.X, key.Y) //nolint:staticcheck // SA1019: builds the uncompressed-point wire format under test; crypto/ecdh migration is a separate, behavior-sensitive change
	wrapped, err := asn1.Marshal(rawPoint)
	require.NoError(t, err)

	point, curve, err := parsePeerPublicKey(wrapped)
	require.NoError(t, err)
	assert.Equal(t, rawPoint, point, "unwrapping must yield the bare point")
	assert.Equal(t, elliptic.P256().Params().Name, curve.Params().Name)
}

// TestRequireMatchingCurve_NonECKey verifies a non-EC private key is refused.
// An RSA key has no CKA_EC_PARAMS, and deriving against it is meaningless, so
// the read failure must surface rather than be treated as a match.
func TestRequireMatchingCurve_NonECKey(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-rsakey")

	attrs := &types.KeyAttributes{
		CN:            "rsa-not-for-ecdh",
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_PKCS11,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
	_, err := b.GenerateRSAWithSize(attrs, 2048)
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)
	handle, err := b.findPrivateKeyHandle(session, attrs)
	require.NoError(t, err)

	err = b.requireMatchingCurve(session, handle, elliptic.P256())
	require.Error(t, err, "an RSA private key must not pass the EC curve check")
}

// TestDeriveKeyECDH_KeyWithoutDeriveAttribute verifies that a private key
// generated without CKA_DERIVE cannot be used for key agreement.
//
// PKCS#11 gates C_DeriveKey on CKA_DERIVE of the base key, so a key created
// for signing only is not an ECDH key. The failure must be reported, never
// worked around.
//
// The sign-only key is built here with an explicit template because this is no
// longer what Backend.GenerateECDSA produces; it stands in for a key some other
// tool put on the token.
func TestDeriveKeyECDH_KeyWithoutDeriveAttribute(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-noderive")

	attrs := &types.KeyAttributes{
		CN:            "sign-only-key",
		KeyType:       backend.KEY_TYPE_TLS,
		StoreType:     backend.STORE_PKCS11,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}

	oid := namedCurveOIDs[elliptic.P256().Params().Name]
	encodedOID, err := asn1.Marshal(oid)
	require.NoError(t, err)
	id := []byte(createKeyID(attrs))

	require.NoError(t, b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		_, _, err := b.p11ctx.GenerateKeyPair(session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
				pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, encodedOID),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
				pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			},
			[]*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
				pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
				pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
				pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			})
		return err
	}))

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)

	_, err = b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, types.DefaultKDFParams())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ECDH derivation failed")
}

// TestDeriveKeyECDH_ContextInitializationFailure verifies that a backend whose
// PKCS#11 library cannot be loaded reports that, instead of proceeding with a
// nil context.
func TestDeriveKeyECDH_ContextInitializationFailure(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-ctxfail")
	attrs := provisionDerivableECKey(t, b, "ctxfail-key", elliptic.P256())

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)

	// Drop the context and point the configuration at a library that does not
	// exist, then restore both so the backend can still be closed.
	original := b.p11ctx
	originalLibrary := b.config.Library
	b.p11ctx = nil
	b.config.Library = filepath.Join(t.TempDir(), "libmissing.so")
	t.Cleanup(func() {
		b.p11ctx = original
		b.config.Library = originalLibrary
	})

	_, err = b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, types.DefaultKDFParams())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load PKCS#11 library")
}

// TestEnsureP11Context_CreatesContext covers the lazy creation path, including
// the CKR_CRYPTOKI_ALREADY_INITIALIZED result that C_Initialize returns when
// another context in the same process got there first. That status is normal,
// not an error.
func TestEnsureP11Context_CreatesContext(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-ctxcreate")

	original := b.p11ctx
	require.NotNil(t, original)
	t.Cleanup(func() { b.p11ctx = original })

	b.mu.Lock()
	b.p11ctx = nil
	err := b.ensureP11Context()
	created := b.p11ctx
	b.mu.Unlock()

	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotSame(t, original, created, "a new context must have been constructed")
}

// TestSupportedCurves_ExplicitSlot covers curve discovery when the slot is
// pinned in the configuration rather than discovered.
func TestSupportedCurves_ExplicitSlot(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-curveslot")

	b.mu.Lock()
	slot, err := b.resolveSlot()
	b.mu.Unlock()
	require.NoError(t, err)

	pinned := int(slot)
	b.config.Slot = &pinned

	assert.Equal(t, []string{"P-256", "P-384", "P-521"}, b.SupportedCurves())
}

// TestDeriveKeyECDH_OctetStringWrappedPeerKey verifies a peer key sent as a
// raw CKA_EC_POINT attribute value derives the same secret as the same key sent
// as SubjectPublicKeyInfo.
//
// PKCS#11 tokens store CKA_EC_POINT as an ASN.1 OCTET STRING, whose tag byte is
// 0x04 -- the same byte that marks an uncompressed point. Discriminating on
// that byte alone rejected every wrapped point with an "unsupported EC point
// size" error; only the length distinguishes the two encodings.
func TestDeriveKeyECDH_OctetStringWrappedPeerKey(t *testing.T) {
	b := newProvisionedBackend(t, "ecdh-wrapped")
	attrs := provisionDerivableECKey(t, b, "wrapped-peer-key", elliptic.P256())

	peerPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	peerSPKI, err := x509.MarshalPKIXPublicKey(peerPrivate.PublicKey())
	require.NoError(t, err)
	wrappedPoint, err := asn1.Marshal(peerPrivate.PublicKey().Bytes())
	require.NoError(t, err)

	kdfParams := types.DefaultKDFParams()

	fromSPKI, err := b.DeriveKeyECDH(context.Background(), attrs, peerSPKI, kdfParams)
	require.NoError(t, err)

	fromWrapped, err := b.DeriveKeyECDH(context.Background(), attrs, wrappedPoint, kdfParams)
	require.NoError(t, err, "a CKA_EC_POINT attribute value must be accepted as a peer key")
	assert.Equal(t, fromSPKI, fromWrapped)

	// And it agrees with the peer's own software computation.
	peerSecret, err := peerPrivate.ECDH(tokenECDHPublicKey(t, b, attrs))
	require.NoError(t, err)
	expected, err := applyKDF(peerSecret, kdfParams)
	require.NoError(t, err)
	assert.Equal(t, expected, fromWrapped)
}

// TestParsePeerPublicKey_TypedRejection verifies malformed peer keys carry
// ErrInvalidPeerPublicKey so callers can distinguish a bad request from a
// token failure.
func TestParsePeerPublicKey_TypedRejection(t *testing.T) {
	longNonPoint := make([]byte, 200)
	longNonPoint[0] = 0x04

	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"compressed point", append([]byte{0x02}, make([]byte, 32)...)},
		{"leading 0x04 but no valid encoding", longNonPoint},
		{"random bytes", []byte("not a key")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parsePeerPublicKey(tc.input)
			assert.ErrorIs(t, err, ErrInvalidPeerPublicKey)
		})
	}
}

// TestParsePeerPublicKey_WrappedPointWrongSize verifies that an OCTET STRING
// carrying something that is not a point of a supported size is rejected with
// the size named in the message, rather than being passed to the token.
func TestParsePeerPublicKey_WrappedPointWrongSize(t *testing.T) {
	payload := make([]byte, 10)
	payload[0] = 0x04

	wrapped, err := asn1.Marshal(payload)
	require.NoError(t, err)

	_, _, err = parsePeerPublicKey(wrapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported EC point size: 10")
}
