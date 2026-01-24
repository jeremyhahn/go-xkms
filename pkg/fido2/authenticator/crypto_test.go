// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestGenerateCredentialKey_ES256(t *testing.T) {
	privateKey, coseKey, err := GenerateCredentialKey(COSEAlgES256)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.NotEmpty(t, coseKey)

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P256(), ecKey.Curve)
}

func TestGenerateCredentialKey_ES384(t *testing.T) {
	privateKey, coseKey, err := GenerateCredentialKey(COSEAlgES384)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.NotEmpty(t, coseKey)

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P384(), ecKey.Curve)
}

func TestGenerateCredentialKey_ES512(t *testing.T) {
	privateKey, coseKey, err := GenerateCredentialKey(COSEAlgES512)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.NotEmpty(t, coseKey)

	ecKey, ok := privateKey.(*ecdsa.PrivateKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P521(), ecKey.Curve)
}

func TestGenerateCredentialKey_EdDSA(t *testing.T) {
	privateKey, coseKey, err := GenerateCredentialKey(COSEAlgEdDSA)
	require.NoError(t, err)
	require.NotNil(t, privateKey)
	require.NotEmpty(t, coseKey)

	_, ok := privateKey.(ed25519.PrivateKey)
	require.True(t, ok)
}

func TestGenerateCredentialKey_UnsupportedAlgorithm(t *testing.T) {
	privateKey, coseKey, err := GenerateCredentialKey(9999)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedCryptoAlgorithm)
	require.Nil(t, privateKey)
	require.Nil(t, coseKey)
}

func TestEncodeCOSEPublicKey_NilKey(t *testing.T) {
	coseKey, err := EncodeCOSEPublicKey(nil, COSEAlgES256)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
	require.Nil(t, coseKey)
}

func TestEncodeCOSEPublicKey_UnsupportedAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(&key.PublicKey, 9999)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedCryptoAlgorithm)
	require.Nil(t, coseKey)
}

func TestEncodeCOSEPublicKey_WrongKeyTypeForAlgorithm(t *testing.T) {
	// Generate Ed25519 key but try to encode as ES256
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(pub, COSEAlgES256)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
	require.Nil(t, coseKey)
}

func TestEncodeCOSEPublicKey_ES384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(&key.PublicKey, COSEAlgES384)
	require.NoError(t, err)
	require.NotEmpty(t, coseKey)

	// Verify COSE structure
	var keyMap map[int]interface{}
	err = cbor.Unmarshal(coseKey, &keyMap)
	require.NoError(t, err)

	kty, _ := toInt(keyMap[coseKeyLabelKty])
	require.Equal(t, COSEKeyTypeEC2, kty)

	crv, _ := toInt(keyMap[coseKeyLabelCrv])
	require.Equal(t, COSECurveP384, crv)

	xBytes := keyMap[coseKeyLabelX].([]byte)
	require.Len(t, xBytes, 48) // P-384 coordinate size
}

func TestEncodeCOSEPublicKey_ES512(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(&key.PublicKey, COSEAlgES512)
	require.NoError(t, err)
	require.NotEmpty(t, coseKey)

	// Verify COSE structure
	var keyMap map[int]interface{}
	err = cbor.Unmarshal(coseKey, &keyMap)
	require.NoError(t, err)

	crv, _ := toInt(keyMap[coseKeyLabelCrv])
	require.Equal(t, COSECurveP521, crv)

	xBytes := keyMap[coseKeyLabelX].([]byte)
	require.Len(t, xBytes, 66) // P-521 coordinate size
}

func TestEncodeCOSEPublicKey_EdDSA(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(pub, COSEAlgEdDSA)
	require.NoError(t, err)
	require.NotEmpty(t, coseKey)

	// Verify COSE structure
	var keyMap map[int]interface{}
	err = cbor.Unmarshal(coseKey, &keyMap)
	require.NoError(t, err)

	kty, _ := toInt(keyMap[coseKeyLabelKty])
	require.Equal(t, COSEKeyTypeOKP, kty)

	crv, _ := toInt(keyMap[coseKeyLabelCrv])
	require.Equal(t, COSECurveEd25519, crv)

	xBytes := keyMap[coseKeyLabelX].([]byte)
	require.Len(t, xBytes, 32)
}

func TestEncodeCOSEPublicKey_EdDSA_WrongType(t *testing.T) {
	// Try to encode ECDSA key as EdDSA
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(&key.PublicKey, COSEAlgEdDSA)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
	require.Nil(t, coseKey)
}

func TestDecodeCOSEPublicKey_EmptyData(t *testing.T) {
	pubKey, alg, err := DecodeCOSEPublicKey(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)

	pubKey, alg, err = DecodeCOSEPublicKey([]byte{})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)
}

func TestDecodeCOSEPublicKey_InvalidCBOR(t *testing.T) {
	pubKey, alg, err := DecodeCOSEPublicKey([]byte{0xFF, 0xFF, 0xFF})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)
}

func TestDecodeCOSEPublicKey_MissingKty(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, alg, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingKeyParameter)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)
}

func TestDecodeCOSEPublicKey_MissingAlg(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, alg, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingKeyParameter)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)
}

func TestDecodeCOSEPublicKey_InvalidKtyType(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: "not an int",
		coseKeyLabelAlg: COSEAlgES256,
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, alg, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)
}

func TestDecodeCOSEPublicKey_InvalidAlgType(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: "not an int",
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, alg, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)
}

func TestDecodeCOSEPublicKey_UnsupportedKty(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeRSA, // RSA not supported
		coseKeyLabelAlg: COSEAlgRS256,
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, alg, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedCryptoAlgorithm)
	require.Nil(t, pubKey)
	require.Equal(t, 0, alg)
}

func TestDecodeEC2Key_MissingCrv(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingKeyParameter)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_InvalidCrvType(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: "not an int",
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_MissingX(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingKeyParameter)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_InvalidXType(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   "not bytes",
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_MissingY(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingKeyParameter)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_InvalidYType(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   "not bytes",
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_UnsupportedCurve(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: 99, // Unknown curve
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCurve)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_PointNotOnCurve(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgES256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32), // Zero is not on curve
		coseKeyLabelY:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
	require.Nil(t, pubKey)
}

func TestDecodeEC2Key_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(&key.PublicKey, COSEAlgES384)
	require.NoError(t, err)

	pubKey, alg, err := DecodeCOSEPublicKey(coseKey)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.Equal(t, COSEAlgES384, alg)

	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P384(), ecPub.Curve)
}

func TestDecodeEC2Key_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(&key.PublicKey, COSEAlgES512)
	require.NoError(t, err)

	pubKey, alg, err := DecodeCOSEPublicKey(coseKey)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.Equal(t, COSEAlgES512, alg)

	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, elliptic.P521(), ecPub.Curve)
}

func TestDecodeOKPKey_MissingCrv(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeOKP,
		coseKeyLabelAlg: COSEAlgEdDSA,
		coseKeyLabelX:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingKeyParameter)
	require.Nil(t, pubKey)
}

func TestDecodeOKPKey_InvalidCrvType(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeOKP,
		coseKeyLabelAlg: COSEAlgEdDSA,
		coseKeyLabelCrv: "not an int",
		coseKeyLabelX:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
}

func TestDecodeOKPKey_UnsupportedCurve(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeOKP,
		coseKeyLabelAlg: COSEAlgEdDSA,
		coseKeyLabelCrv: 99, // Unknown curve
		coseKeyLabelX:   make([]byte, 32),
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCurve)
	require.Nil(t, pubKey)
}

func TestDecodeOKPKey_MissingX(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeOKP,
		coseKeyLabelAlg: COSEAlgEdDSA,
		coseKeyLabelCrv: COSECurveEd25519,
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMissingKeyParameter)
	require.Nil(t, pubKey)
}

func TestDecodeOKPKey_InvalidXType(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeOKP,
		coseKeyLabelAlg: COSEAlgEdDSA,
		coseKeyLabelCrv: COSECurveEd25519,
		coseKeyLabelX:   "not bytes",
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidCOSEKey)
	require.Nil(t, pubKey)
}

func TestDecodeOKPKey_InvalidKeySize(t *testing.T) {
	keyMap := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeOKP,
		coseKeyLabelAlg: COSEAlgEdDSA,
		coseKeyLabelCrv: COSECurveEd25519,
		coseKeyLabelX:   make([]byte, 16), // Wrong size
	}
	data, _ := cbor.Marshal(keyMap)

	pubKey, _, err := DecodeCOSEPublicKey(data)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPublicKey)
	require.Nil(t, pubKey)
}

func TestDecodeOKPKey_Success(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	coseKey, err := EncodeCOSEPublicKey(pub, COSEAlgEdDSA)
	require.NoError(t, err)

	pubKey, alg, err := DecodeCOSEPublicKey(coseKey)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.Equal(t, COSEAlgEdDSA, alg)

	edPub, ok := pubKey.(ed25519.PublicKey)
	require.True(t, ok)
	require.Equal(t, pub, edPub)
}

func TestToInt_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int
		hasError bool
	}{
		{"int", int(42), 42, false},
		{"int8", int8(42), 42, false},
		{"int16", int16(42), 42, false},
		{"int32", int32(42), 42, false},
		{"int64", int64(42), 42, false},
		{"uint", uint(42), 42, false},
		{"uint8", uint8(42), 42, false},
		{"uint16", uint16(42), 42, false},
		{"uint32", uint32(42), 42, false},
		{"uint64", uint64(42), 42, false},
		{"string", "42", 0, true},
		{"float", 42.0, 0, true},
		{"nil", nil, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := toInt(tt.input)
			if tt.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestSign_NilKey(t *testing.T) {
	sig, err := Sign(nil, COSEAlgES256, []byte("data"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPrivateKey)
	require.Nil(t, sig)
}

func TestSign_UnsupportedAlgorithm(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sig, err := Sign(key, 9999, []byte("data"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedCryptoAlgorithm)
	require.Nil(t, sig)
}

func TestSign_ES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := Sign(key, COSEAlgES256, data)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify ASN.1/DER structure
	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err, "signature should be valid ASN.1/DER")
	require.Empty(t, rest, "no trailing bytes expected")
	require.NotNil(t, parsed.R)
	require.NotNil(t, parsed.S)

	// Verify signature with public key
	digest := sha256.Sum256(data)
	require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig))
}

func TestSign_ES256_LowS_Normalization(t *testing.T) {
	// Test that ES256 signatures are normalized to low-S form (S <= n/2)
	// This is required by WebAuthn/CTAP2 to prevent signature malleability
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	curve := elliptic.P256()
	n := curve.Params().N
	halfN := new(big.Int).Rsh(n, 1)

	// Sign multiple times to statistically verify normalization
	// Without normalization, ~50% of signatures would have S > n/2
	data := []byte("test data for low-S normalization")
	for i := 0; i < 20; i++ {
		sig, err := Sign(key, COSEAlgES256, data)
		require.NoError(t, err)

		// Parse S from ASN.1/DER signature
		var parsed ecdsaSignature
		_, err = asn1.Unmarshal(sig, &parsed)
		require.NoError(t, err)

		// Verify S is in low-S form
		require.True(t, parsed.S.Cmp(halfN) <= 0,
			"signature S value should be <= n/2 for low-S normalization, got S=%x", parsed.S)
	}
}

func TestSign_ES384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := Sign(key, COSEAlgES384, data)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify ASN.1/DER structure
	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err, "signature should be valid ASN.1/DER")
	require.Empty(t, rest)

	// Verify signature with public key
	digest := sha512.Sum384(data)
	require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig))
}

func TestSign_ES512(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := Sign(key, COSEAlgES512, data)
	require.NoError(t, err)
	require.NotNil(t, sig)

	// Verify ASN.1/DER structure
	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(sig, &parsed)
	require.NoError(t, err, "signature should be valid ASN.1/DER")
	require.Empty(t, rest)

	// Verify signature with public key
	digest := sha512.Sum512(data)
	require.True(t, ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig))
}

func TestSign_EdDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	data := []byte("test data to sign")
	sig, err := Sign(priv, COSEAlgEdDSA, data)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.Len(t, sig, 64) // Ed25519 signature size
}

func TestSign_EdDSA_WrongKeyType(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sig, err := Sign(key, COSEAlgEdDSA, []byte("data"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPrivateKey)
	require.Nil(t, sig)
}

func TestSignECDSA_WrongKeyType(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sig, err := Sign(priv, COSEAlgES256, []byte("data"))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPrivateKey)
	require.Nil(t, sig)
}

func TestPadCoordinate(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		size     int
		expected int
	}{
		{"no padding needed", make([]byte, 32), 32, 32},
		{"needs padding", make([]byte, 30), 32, 32},
		{"empty input", []byte{}, 32, 32},
		{"single byte", []byte{0x01}, 32, 32},
		{"larger than size", make([]byte, 40), 32, 40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := padCoordinate(tt.input, tt.size)
			require.Len(t, result, tt.expected)

			// Verify padding is at the beginning (leading zeros)
			if len(tt.input) < tt.size && len(tt.input) > 0 {
				padding := tt.size - len(tt.input)
				for i := 0; i < padding; i++ {
					require.Equal(t, byte(0), result[i])
				}
			}
		})
	}
}

func TestGenerateCredentialID(t *testing.T) {
	id1, err := GenerateCredentialID()
	require.NoError(t, err)
	require.Len(t, id1, CredentialIDSize)

	id2, err := GenerateCredentialID()
	require.NoError(t, err)
	require.Len(t, id2, CredentialIDSize)

	// Two generated IDs should be different
	require.False(t, bytes.Equal(id1, id2))
}

func TestGenerateHMACSecretKey(t *testing.T) {
	key1, err := GenerateHMACSecretKey()
	require.NoError(t, err)
	require.Len(t, key1, HMACSecretKeySize)

	key2, err := GenerateHMACSecretKey()
	require.NoError(t, err)
	require.Len(t, key2, HMACSecretKeySize)

	// Two generated keys should be different
	require.False(t, bytes.Equal(key1, key2))
}

func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		algorithm int
		expected  string
	}{
		{COSEAlgES256, "ES256"},
		{COSEAlgES384, "ES384"},
		{COSEAlgES512, "ES512"},
		{COSEAlgRS256, "RS256"},
		{COSEAlgEdDSA, "EdDSA"},
		{9999, "unknown"},
		{0, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := AlgorithmName(tt.algorithm)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestCurveForAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm int
		expected  elliptic.Curve
		hasError  bool
	}{
		{"ES256", COSEAlgES256, elliptic.P256(), false},
		{"ES384", COSEAlgES384, elliptic.P384(), false},
		{"ES512", COSEAlgES512, elliptic.P521(), false},
		{"EdDSA unsupported", COSEAlgEdDSA, nil, true},
		{"RS256 unsupported", COSEAlgRS256, nil, true},
		{"unknown", 9999, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curve, err := CurveForAlgorithm(tt.algorithm)
			if tt.hasError {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedCryptoAlgorithm)
				require.Nil(t, curve)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, curve)
			}
		})
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		algorithm int
		genKey    func() (crypto.PrivateKey, crypto.PublicKey, error)
	}{
		{
			"ES256",
			COSEAlgES256,
			func() (crypto.PrivateKey, crypto.PublicKey, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
		},
		{
			"ES384",
			COSEAlgES384,
			func() (crypto.PrivateKey, crypto.PublicKey, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
		},
		{
			"ES512",
			COSEAlgES512,
			func() (crypto.PrivateKey, crypto.PublicKey, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
		},
		{
			"EdDSA",
			COSEAlgEdDSA,
			func() (crypto.PrivateKey, crypto.PublicKey, error) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, pub, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, pub, err := tt.genKey()
			require.NoError(t, err)

			// Encode public key
			coseKey, err := EncodeCOSEPublicKey(pub, tt.algorithm)
			require.NoError(t, err)

			// Decode public key
			decodedPub, decodedAlg, err := DecodeCOSEPublicKey(coseKey)
			require.NoError(t, err)
			require.Equal(t, tt.algorithm, decodedAlg)
			require.NotNil(t, decodedPub)

			// Sign data
			data := []byte("test data to sign")
			sig, err := Sign(priv, tt.algorithm, data)
			require.NoError(t, err)
			require.NotNil(t, sig)
		})
	}
}

// TestEncodeCOSEPublicKey_CanonicalCBOR verifies that COSE keys are encoded
// with canonical CBOR ordering as required by CTAP2 specification.
// Keys must be sorted in ascending order by their encoded byte representation.
func TestEncodeCOSEPublicKey_CanonicalCBOR(t *testing.T) {
	// Generate multiple keys and verify each has canonical ordering
	for i := 0; i < 10; i++ {
		t.Run("iteration", func(t *testing.T) {
			// Generate ES256 key
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			coseKey, err := EncodeCOSEPublicKey(&key.PublicKey, COSEAlgES256)
			require.NoError(t, err)
			require.NotEmpty(t, coseKey)

			// Verify canonical key ordering in CBOR
			// For ES256 COSE key, the canonical order should be:
			// 1 (kty), 3 (alg), -1 (crv), -2 (x), -3 (y)
			// In CBOR byte encoding: 0x01, 0x03, 0x20, 0x21, 0x22

			// First byte should be map header (0xa5 for map with 5 elements)
			require.Equal(t, byte(0xa5), coseKey[0], "expected map(5) header")

			// Extract key bytes from the encoded CBOR
			// Key 1 at position 1: 0x01
			require.Equal(t, byte(0x01), coseKey[1], "first key should be 1")

			// Key 3 at position 3 (after key 1 and value 0x02): 0x03
			require.Equal(t, byte(0x03), coseKey[3], "second key should be 3")

			// Key -1 at position 5 (after key 3 and value 0x26 for -7): 0x20
			require.Equal(t, byte(0x20), coseKey[5], "third key should be -1 (0x20)")

			// Key -2 at position 7 (after key -1 and value 0x01): 0x21
			require.Equal(t, byte(0x21), coseKey[7], "fourth key should be -2 (0x21)")

			// Key -3 appears after 32 bytes of X coordinate: position 7 + 1 + 2 + 32 = 42
			require.Equal(t, byte(0x22), coseKey[42], "fifth key should be -3 (0x22)")
		})
	}
}
