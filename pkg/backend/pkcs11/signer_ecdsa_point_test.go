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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/stretchr/testify/require"
)

// The two points below are real public keys whose X coordinate begins with the
// byte that the previous DER-unwrap heuristic mistook for an OCTET STRING
// length. That heuristic accepted an attribute value as DER-wrapped when
//
//	ecPoint[0] == 0x04 && int(ecPoint[1]) == len(ecPoint)-2
//
// and 0x04 is the uncompressed-point marker of every bare point, so the whole
// test reduced to "does X start with len-2?". On P-256 that byte is 63 (0x3f)
// and on P-384 it is 95 (0x5f), each of which occurs in 1 of 256 keys. When it
// occurred, two bytes of X were discarded as a phantom DER header and the
// export failed.
//
// P-521 cannot reach the collision at all: its len-2 is 131 (0x83) while the
// first byte of a 66-byte P-521 X coordinate never exceeds 0x01.
const (
	// p256TriggerPoint is 0x04 || X || Y with X[0] == 0x3f == 65-2.
	p256TriggerPoint = "043f5985033d37358620c331628976b0b237bf83249858b9b70c2466603476b1db" +
		"d561f957bc005c2daf0381de55debdbec183d5f081939fb8a09cfa9e23cd6c18"

	// p384TriggerPoint is 0x04 || X || Y with X[0] == 0x5f == 97-2.
	p384TriggerPoint = "045f98ef5af501abfb34ee0989162a108505f99125bc009287db432d5d43a982f5" +
		"7432c18ce6e4f0e85f74c24ff8d85b65caa5a1e9d8c68af3418c97abe114fd7a9" +
		"dedb7ce3cd08ef254d9cbe52d310a89c548b4243b17cd9cf55d8f3315c6d36a"
)

// decodeHex returns the bytes of a hex literal used as a test vector.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()

	raw, err := hex.DecodeString(s)
	require.NoError(t, err, "test vector must be valid hex")

	return raw
}

// wrapInOctetString returns point wrapped in a DER OCTET STRING, the encoding
// PKCS#11 v3.2 §6.3.3 Table 64 prescribes for CKA_EC_POINT.
func wrapInOctetString(t *testing.T, point []byte) []byte {
	t.Helper()

	wrapped, err := asn1.Marshal(point)
	require.NoError(t, err)

	return wrapped
}

// TestUncompressedPointLen pins the encoded size of a bare uncompressed point
// for every curve this backend supports. These are the lengths decodeECPoint
// discriminates on, so a wrong value here would silently reintroduce the
// ambiguity the length test exists to remove.
func TestUncompressedPointLen(t *testing.T) {
	require.Equal(t, 65, uncompressedPointLen(elliptic.P256()))
	require.Equal(t, 97, uncompressedPointLen(elliptic.P384()))
	// P-521's field is 521 bits, so each coordinate is padded to 66 bytes.
	require.Equal(t, 133, uncompressedPointLen(elliptic.P521()))
}

// TestDecodeECPoint_BarePointWithHeaderLikePrefix is the regression test for
// the DER-unwrap heuristic. Each point here is a real public key whose first
// two bytes are exactly the pattern the old code read as an OCTET STRING
// header, so it fails on the old code and passes on the new one — no random
// generation, no repeat count.
func TestDecodeECPoint_BarePointWithHeaderLikePrefix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
		point string
	}{
		{"P-256", elliptic.P256(), p256TriggerPoint},
		{"P-384", elliptic.P384(), p384TriggerPoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			point := decodeHex(t, tc.point)

			// The exact shape that defeated the heuristic: a bare point whose
			// second byte equals its own length minus the two header bytes an
			// OCTET STRING would have used.
			require.Equal(t, byte(0x04), point[0])
			require.Equal(t, byte(len(point)-2), point[1])

			decoded, err := decodeECPoint(tc.curve, point)
			require.NoError(t, err, "a bare uncompressed point must not be unwrapped")
			require.Equal(t, point, decoded, "no byte of a bare point may be stripped")

			x, y := elliptic.Unmarshal(tc.curve, decoded) //nolint:staticcheck // SA1019: on-curve validation of the decoded point; crypto/ecdh migration is a separate, behavior-sensitive change
			require.NotNil(t, x, "the decoded point must still be on the curve")
			require.NotNil(t, y)
		})
	}
}

// TestDecodeECPoint_WrappedPointWithHeaderLikePrefix runs the same two points
// through the wrapped encoding. The decoder must reach identical coordinates
// whichever form the token stored, which is what makes the length test a
// disambiguation rather than a preference for one vendor.
func TestDecodeECPoint_WrappedPointWithHeaderLikePrefix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
		point string
	}{
		{"P-256", elliptic.P256(), p256TriggerPoint},
		{"P-384", elliptic.P384(), p384TriggerPoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			point := decodeHex(t, tc.point)

			decoded, err := decodeECPoint(tc.curve, wrapInOctetString(t, point))
			require.NoError(t, err)
			require.Equal(t, point, decoded, "the DER wrapper must be removed exactly once")
		})
	}
}

// TestDecodeECPoint_BothEncodingsAgree walks every supported curve in both
// encodings using generated keys, so the decoder is exercised against points
// whose leading bytes are ordinary as well as the crafted ones above.
func TestDecodeECPoint_BothEncodingsAgree(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			point := elliptic.Marshal(curve, key.X, key.Y) //nolint:staticcheck // SA1019: builds the uncompressed-point wire format decodeECPoint is tested against; crypto/ecdh migration is a separate, behavior-sensitive change

			bare, err := decodeECPoint(curve, point)
			require.NoError(t, err)

			wrapped, err := decodeECPoint(curve, wrapInOctetString(t, point))
			require.NoError(t, err)

			require.Equal(t, bare, wrapped, "both CKA_EC_POINT encodings must decode to the same point")
			require.Equal(t, point, bare)
		})
	}
}

// TestDecodeECPoint_UndecidableValuesAreRejected covers the attribute values
// that are neither encoding. Each must return a typed ErrInvalidKeyAttributes
// rather than a best guess: a public key assembled from misread bytes would
// accept no signature the key actually made, and the failure would surface far
// from its cause.
func TestDecodeECPoint_UndecidableValuesAreRejected(t *testing.T) {
	p256 := elliptic.P256()
	point := decodeHex(t, p256TriggerPoint)

	shortWrapped := wrapInOctetString(t, []byte{0x04, 0xaa, 0xbb})

	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
		value []byte
	}{
		{"empty", p256, nil},
		{"truncated bare point", p256, point[:len(point)-1]},
		{"bare point one byte too long", p256, append(append([]byte{}, point...), 0x00)},
		{"not DER at all", p256, []byte{0x04, 0x3f, 0x01, 0x02}},
		{"OCTET STRING of the wrong size", p256, shortWrapped},
		{"OCTET STRING with trailing bytes", p256, append(wrapInOctetString(t, point), 0x00)},
		{"P-256 point offered as P-384", elliptic.P384(), point},
		{"P-384 point offered as P-256", p256, decodeHex(t, p384TriggerPoint)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeECPoint(tc.curve, tc.value)
			require.Nil(t, decoded)
			require.ErrorIs(t, err, ErrInvalidKeyAttributes)

			var detail *errs.Detail
			require.True(t, errors.As(err, &detail), "the failure must carry a typed detail")
			require.NotEmpty(t, detail.Detail)
		})
	}
}
