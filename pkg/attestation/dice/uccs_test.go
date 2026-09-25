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

package dice

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUccsEvidenceExtension(t *testing.T) {
	extension, err := CreateUccsEvidenceExtension(&ClaimsSet{Nonce: vecNonce()})
	require.NoError(t, err)

	assert.True(t, extension.Id.Equal(OIDUccsEvidence))
	assert.Equal(t, mustDecodeHex(t, vecUccsEvidenceNonceOnly), extension.Value)

	// Critical for the reason the TcbInfo extension is: the extension carries
	// the claims that make the certificate an attestation, and a relying party
	// that cannot read them must not read the certificate as one.
	assert.True(t, extension.Critical)
}

func TestCreateUccsEvidenceExtensionRejectsBadInput(t *testing.T) {
	tests := []struct {
		name   string
		claims *ClaimsSet
		want   error
	}{
		{"a nil claims set", nil, ErrNilClaimsSet},
		{"no nonce at all", &ClaimsSet{}, ErrNonceClaimLength},
		{"a nonce shorter than eight bytes", &ClaimsSet{Nonce: vecNonce()[:7]}, ErrNonceClaimLength},
		{
			name:   "the nonce supplied a second time as a raw claim",
			claims: &ClaimsSet{Nonce: vecNonce(), Other: map[int64][]byte{ClaimEatNonce: {0x40}}},
			want:   ErrDuplicateClaim,
		},
		{
			name:   "a raw claim that is not CBOR",
			claims: &ClaimsSet{Nonce: vecNonce(), Other: map[int64][]byte{256: {0xFF}}},
			want:   ErrMalformedClaimsSet,
		},
		{
			name:   "a raw claim with trailing bytes",
			claims: &ClaimsSet{Nonce: vecNonce(), Other: map[int64][]byte{256: {0x01, 0x02}}},
			want:   ErrMalformedClaimsSet,
		},
		{
			name:   "an empty raw claim",
			claims: &ClaimsSet{Nonce: vecNonce(), Other: map[int64][]byte{256: {}}},
			want:   ErrMalformedClaimsSet,
		},
		{
			name:   "a raw claim that is an indefinite-length string",
			claims: &ClaimsSet{Nonce: vecNonce(), Other: map[int64][]byte{256: mustDecodeHex(t, "5f4101ff")}},
			want:   ErrMalformedClaimsSet,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extension, err := CreateUccsEvidenceExtension(test.claims)
			require.Error(t, err)
			assert.ErrorIs(t, err, test.want)
			assert.Equal(t, pkix.Extension{}, extension)
		})
	}
}

// TestMarshalClaimsSetIsDeterministic is a requirement rather than a nicety.
// Section 6.1.4 says the issuer must make non-constant elements of this field
// contribute to the CDI that generated the subject key, which a field with
// more than one encoding cannot do: the contribution would depend on which
// encoder ran.
func TestMarshalClaimsSetIsDeterministic(t *testing.T) {
	claims := &ClaimsSet{
		Nonce: vecNonce(),
		Other: map[int64][]byte{
			256: mustDecodeHex(t, "480102030405060708"),
			259: mustDecodeHex(t, "63616272"), // "abr"
			-70: mustDecodeHex(t, "01"),
		},
	}

	first, err := MarshalClaimsSet(claims)
	require.NoError(t, err)
	for i := 0; i < 16; i++ {
		again, err := MarshalClaimsSet(claims)
		require.NoError(t, err)
		require.Equal(t, first, again,
			"Go map iteration order changed the encoding, so the CDI contribution is not stable")
	}

	// Core deterministic ordering is by encoded key bytes, shortest first, so
	// the one-byte keys precede the three-byte ones and 256 precedes 259.
	decoded, err := ParseClaimsSet(first)
	require.NoError(t, err)
	assert.Equal(t, claims.Nonce, decoded.Nonce)
	assert.Equal(t, claims.Other, decoded.Other)
}

func TestUccsFromCertificate(t *testing.T) {
	cert := &x509.Certificate{
		Extensions: []pkix.Extension{{
			Id:    OIDUccsEvidence,
			Value: mustDecodeHex(t, vecUccsEvidenceNonceOnly),
		}},
	}

	claims, err := UccsFromCertificate(cert)
	require.NoError(t, err)
	assert.Equal(t, vecNonce(), claims.Nonce)
}

func TestUccsFromCertificateRejectsBadInput(t *testing.T) {
	t.Run("a nil certificate", func(t *testing.T) {
		claims, err := UccsFromCertificate(nil)
		require.ErrorIs(t, err, ErrNilCertificate)
		assert.Nil(t, claims)
	})

	t.Run("a certificate with no UCCS extension", func(t *testing.T) {
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{{Id: OIDUeid, Value: mustDecodeHex(t, vecUeid)}},
		}
		claims, err := UccsFromCertificate(cert)
		require.ErrorIs(t, err, ErrUccsEvidenceNotFound)
		assert.Nil(t, claims)
	})

	t.Run("a UCCS extension carrying something else", func(t *testing.T) {
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{{Id: OIDUccsEvidence, Value: mustDecodeHex(t, vecUeid)}},
		}
		claims, err := UccsFromCertificate(cert)
		require.ErrorIs(t, err, ErrMalformedClaimsSet)
		assert.Nil(t, claims)
	})
}

// TestParseClaimsSetRejectsAnEmptyInput covers the boundary the head check
// looks at before it reads a byte that is not there.
func TestParseClaimsSetRejectsAnEmptyInput(t *testing.T) {
	claims, err := ParseClaimsSet(nil)
	require.ErrorIs(t, err, ErrMalformedClaimsSet)
	assert.Nil(t, claims)
}

// TestParseClaimsSetBoundsNesting keeps a claims set from costing more to
// parse than it costs to build. The evidence arrives inside a certificate an
// unauthenticated peer supplies, so the depth is bounded before it is walked.
func TestParseClaimsSetBoundsNesting(t *testing.T) {
	// A nonce claim whose value is an array nested past cborMaxNestedLevels:
	// a1 0a followed by N array-of-one heads and a final byte string.
	deep := []byte{0xA1, 0x0A}
	for i := 0; i < cborMaxNestedLevels+4; i++ {
		deep = append(deep, 0x81)
	}
	deep = append(deep, 0x48)
	deep = append(deep, vecNonce()[:8]...)

	claims, err := ParseClaimsSet(deep)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMalformedClaimsSet)
	assert.Nil(t, claims)
}

// TestParseClaimsSetKeepsClaimsItCannotInterpret is the same contract as the
// vector test, stated against a claim key nobody has registered. Refusing it
// would make this verifier the only one that cannot read the device; dropping
// it would make the verifier's report of what the device said untrue.
func TestParseClaimsSetKeepsClaimsItCannotInterpret(t *testing.T) {
	encoded, err := MarshalClaimsSet(&ClaimsSet{
		Nonce: vecNonce(),
		Other: map[int64][]byte{999999: mustDecodeHex(t, "f5")}, // true
	})
	require.NoError(t, err)

	claims, err := ParseClaimsSet(encoded)
	require.NoError(t, err)
	assert.Equal(t, vecNonce(), claims.Nonce)
	assert.Equal(t, map[int64][]byte{999999: {0xF5}}, claims.Other)
}

// TestParseClaimsSetCopiesTheClaimValues stops a caller's later edit of the
// buffer it supplied from rewriting evidence this package has already reported
// on.
func TestParseClaimsSetCopiesTheClaimValues(t *testing.T) {
	encoded, err := MarshalClaimsSet(&ClaimsSet{
		Nonce: vecNonce(),
		Other: map[int64][]byte{256: mustDecodeHex(t, "480102030405060708")},
	})
	require.NoError(t, err)

	claims, err := ParseClaimsSet(encoded)
	require.NoError(t, err)

	for i := range encoded {
		encoded[i] = 0xFF
	}
	assert.Equal(t, vecNonce(), claims.Nonce)
	assert.Equal(t, mustDecodeHex(t, "480102030405060708"), claims.Other[256])
}
