// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
)

// eccPublicAreaCurves are the NIST curves a TPM ECC public area can name.
var eccPublicAreaCurves = []struct {
	name    string
	curve   elliptic.Curve
	curveID tpm2.TPMECCCurve
	size    int
}{
	{"P-256", elliptic.P256(), tpm2.TPMECCNistP256, 32},
	{"P-384", elliptic.P384(), tpm2.TPMECCNistP384, 48},
	{"P-521", elliptic.P521(), tpm2.TPMECCNistP521, 66},
}

// rawECCPublicArea builds a TPMT_PUBLIC ECC public area carrying the supplied
// raw coordinate buffers, exactly as a TPM reports them.
func rawECCPublicArea(curveID tpm2.TPMECCCurve, x, y []byte) *tpm2.TPMTPublic {
	return &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt: true,
			FixedTPM:    true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{CurveID: curveID},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: x},
				Y: tpm2.TPM2BECCParameter{Buffer: y},
			},
		),
	}
}

// shortCoordinateECCKey returns the first key on curve, walking private
// scalars upward from one, whose X or Y coordinate has a zero high byte and
// therefore arrives in a TPM2B_ECC_PARAMETER buffer short of the field size.
// Deterministic: no RNG, identical on every run.
func shortCoordinateECCKey(t *testing.T, curve elliptic.Curve, size int) *ecdsa.PrivateKey {
	t.Helper()
	scalar := make([]byte, size)
	for i := 1; i < 4096; i++ {
		new(big.Int).SetInt64(int64(i)).FillBytes(scalar)
		key, err := ecdsa.ParseRawPrivateKey(curve, scalar)
		require.NoError(t, err)
		if len(key.X.Bytes()) < size || len(key.Y.Bytes()) < size {
			return key
		}
	}
	t.Fatalf("no short-coordinate key found on %s within 4096 scalars", curve.Params().Name)
	return nil
}

// TestECCPublicKeyAcceptsShortCoordinateBuffer is the regression test for the
// left-padding trap. TPM2B_ECC_PARAMETER does not carry leading zero bytes, so
// roughly one coordinate in 256 arrives shorter than the curve's field size.
// Assembling 0x04 || X || Y from those buffers without left-padding yields a
// point of the wrong length and rejects a perfectly valid EK / SRK / IDevID
// key at random. A test built only from randomly generated keys passes ~99.2%
// of the time and hides exactly this.
func TestECCPublicKeyAcceptsShortCoordinateBuffer(t *testing.T) {
	for _, tc := range eccPublicAreaCurves {
		t.Run(tc.name, func(t *testing.T) {
			key := shortCoordinateECCKey(t, tc.curve, tc.size)
			x := key.X.Bytes()
			y := key.Y.Bytes()
			require.True(t, len(x) < tc.size || len(y) < tc.size,
				"fixture is not short: both coordinates are full width")

			// The naive assembly this change replaces rejects the key.
			naive := append([]byte{4}, append(append([]byte{}, x...), y...)...)
			_, naiveErr := ecdsa.ParseUncompressedPublicKey(tc.curve, naive)
			require.Error(t, naiveErr, "naive unpadded assembly accepted; fixture no longer proves the trap")

			pub, err := eccPublicKey(rawECCPublicArea(tc.curveID, x, y))
			require.NoError(t, err, "valid key with a short coordinate buffer was rejected")
			assert.True(t, pub.Equal(&key.PublicKey))
		})
	}
}

func TestECCPublicKeyRejectsOffCurvePoint(t *testing.T) {
	for _, tc := range eccPublicAreaCurves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			x := make([]byte, tc.size)
			y := make([]byte, tc.size)
			key.X.FillBytes(x)
			key.Y.FillBytes(y)
			y[tc.size-1] ^= 0x01

			_, err = eccPublicKey(rawECCPublicArea(tc.curveID, x, y))
			assert.ErrorIs(t, err, ErrECCPublicArea)
			assert.ErrorIs(t, err, ecpoint.ErrInvalidPoint,
				"the underlying cause must survive to the caller")
		})
	}
}

func TestECCPublicKeyRejectsPointAtInfinity(t *testing.T) {
	zeros := make([]byte, 32)
	_, err := eccPublicKey(rawECCPublicArea(tpm2.TPMECCNistP256, zeros, zeros))
	assert.ErrorIs(t, err, ErrECCPublicArea)
}

func TestECCPublicKeyRejectsUnknownCurveID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = eccPublicKey(rawECCPublicArea(tpm2.TPMECCNone, key.X.Bytes(), key.Y.Bytes()))
	assert.ErrorIs(t, err, ErrECCPublicArea)
}

// TestExtractPublicKeyFromTPMPublicRejectsOffCurvePoint proves the validation
// reaches the exported server-side verification surface, not just the helper.
func TestExtractPublicKeyFromTPMPublicRejectsOffCurvePoint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	y[31] ^= 0x01

	area := rawECCPublicArea(tpm2.TPMECCNistP256, x, y)
	marshalled := tpm2.Marshal(*area)

	_, err = ExtractPublicKeyFromTPMPublic(marshalled)
	assert.ErrorIs(t, err, ErrECCPublicArea)
}

// TestECDSAPublicFromAreaWrapsAsCertifyMalformed keeps the certify surface's
// error identity: a caller distinguishing a forged attestation from a
// malformed one still sees ErrCertifyMalformed.
func TestECDSAPublicFromAreaWrapsAsCertifyMalformed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	y[31] ^= 0x01

	_, err = ecdsaPublicFromArea(rawECCPublicArea(tpm2.TPMECCNistP256, x, y))
	assert.ErrorIs(t, err, ErrCertifyMalformed)
	assert.ErrorIs(t, err, ErrECCPublicArea)
}
