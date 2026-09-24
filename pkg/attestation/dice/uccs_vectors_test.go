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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UCCS wire vectors, byte for byte.
//
// These are LITERALS on purpose. The claims-set bytes were assembled by hand
// from the CBOR head encoding rules of RFC 8949 section 3 and the claim key
// assignments of the CWT claims registry; the DER around them from
// UccsEvidence as TCG DICE Attestation Architecture v1.00 r0.23 section 6.1.4
// declares it. They were checked by decoding them with an independent reader
// -- NOT with the codec in this package. A vector computed from the code it is
// meant to pin moves whenever the code moves, and would agree with a
// regression as readily as with the specification.
//
// A failure here is a WIRE BREAK, not a test to update. These bytes are what a
// device puts in a certificate and what every other DICE verifier reads out of
// one; changing them means every already-provisioned device stops verifying.
// Changing the contract means a new extension OID, not new literals.
//
// The claims-set layer, for reference:
//
//	a2                    map, 2 pairs
//	  0a                  key 10 = eat_nonce
//	  50 a0..af           byte string, 16 bytes: the verifier's nonce
//	  19 0100             key 256 = ueid
//	  48 01..08           byte string, 8 bytes
//
// and the extension value that carries it:
//
//	30 21                 SEQUENCE, 33 bytes    -- UccsEvidence
//	  04 1f               OCTET STRING, 31 bytes -- uccs
//	    a2 ...            the claims set above
const (
	// vecClaimsNonceOnly is the minimum claims set this profile accepts: one
	// pair, the eat_nonce claim carrying the 16-byte challenge a0..af.
	vecClaimsNonceOnly = "a1" + // map, 1 pair
		"0a" + // key 10, eat_nonce
		"50a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" // bstr(16)

	// vecClaimsNonceAndUeid adds the EAT ueid claim, key 256. It is here to
	// pin that a claim this profile does not model is kept rather than
	// refused: a CWT claims set is an open registry, and an attester that says
	// more about itself than this verifier reads is interoperating, not
	// malformed.
	//
	// Core deterministic encoding orders map keys by their encoded bytes, so
	// the one-byte key 10 precedes the three-byte key 256.
	vecClaimsNonceAndUeid = "a2" + // map, 2 pairs
		"0a50a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" + // 10 => nonce
		"19010048" + "0102030405060708" // 256 => ueid

	// vecUccsEvidenceNonceOnly wraps vecClaimsNonceOnly in the UccsEvidence
	// SEQUENCE, which is what the extension value is.
	vecUccsEvidenceNonceOnly = "3015" + "0413" + vecClaimsNonceOnly

	// vecUccsEvidenceNonceAndUeid wraps vecClaimsNonceAndUeid.
	vecUccsEvidenceNonceAndUeid = "3021" + "041f" + vecClaimsNonceAndUeid
)

// Negative vectors: claims sets that must be REFUSED.
//
// Each is a structure a permissive CBOR reader accepts and a verifier must
// not. They are literals for the same reason the positive vectors are: they
// pin what "malformed" means, and a parser that stops rejecting one of these
// has widened what it will treat as a live answer to a challenge.
const (
	// A claims set with no eat_nonce claim: ueid alone. The device said who it
	// is and not that it is answering now.
	vecBadClaimsNoNonce = "a1" + "190100" + "48" + "0102030405060708"

	// An empty map. Well-formed CBOR that states nothing.
	vecBadClaimsEmpty = "a0"

	// A seven-byte nonce, one short of the eight EAT requires. A challenge
	// that short is guessable, and a guessable challenge is not freshness.
	vecBadClaimsNonceShort = "a1" + "0a" + "47a0a1a2a3a4a5a6"

	// The eat_nonce key twice. Two readers of this claims set are free to
	// disagree about which value the device meant.
	vecBadClaimsDuplicateNonce = "a2" +
		"0a" + "48a0a1a2a3a4a5a6a7" +
		"0a" + "48a8a9aaabacadaeaf"

	// A well-formed claims set with a byte appended. The trailing byte is
	// something the encoder did not intend and the reader cannot account for.
	vecBadClaimsTrailing = vecClaimsNonceOnly + "00"

	// An indefinite-length map: head 0xbf, terminated by the 0xff break.
	// One claims set with two possible encodings, and the issuer must make
	// these bytes contribute to the CDI.
	vecBadClaimsIndefiniteMap = "bf" + "0a" + "50a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" + "ff"

	// A definite-length map whose nonce is an indefinite-length byte string,
	// two chunks of eight bytes and a break.
	vecBadClaimsIndefiniteNonce = "a1" + "0a" +
		"5f" + "48a0a1a2a3a4a5a6a7" + "48a8a9aaabacadaeaf" + "ff"

	// A claim keyed by the text string "nonce" rather than by a registry
	// number. A private key name is not something a verifier can weigh.
	vecBadClaimsTextKey = "a1" + "656e6f6e6365" + "50a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

	// An array where the claims set map belongs.
	vecBadClaimsNotAMap = "81" + "0a"

	// The claims set wrapped in CBOR tag 601, the UCCS tag. The extension OID
	// already says the content is a UCCS, so the tag is a second framing of
	// identical evidence.
	vecBadClaimsTagged = "d90259" + vecClaimsNonceOnly

	// eat_nonce carrying the text string "nonce" instead of a byte string.
	vecBadClaimsNonceText = "a1" + "0a" + "656e6f6e6365"

	// eat_nonce carrying EAT's array-of-nonces form, two eight-byte strings.
	// This profile issues one challenge, so a set of candidates leaves "did
	// the device answer me" without a single answer.
	vecBadClaimsNonceArray = "a1" + "0a" +
		"82" + "48a0a1a2a3a4a5a6a7" + "48a8a9aaabacadaeaf"
)

// Negative vectors at the DER layer: UccsEvidence structures that must be
// REFUSED before the CBOR inside is ever looked at.
const (
	// UccsEvidence whose uccs octet string is empty.
	vecBadUccsEmptyOctets = "30020400"

	// An INTEGER where the uccs OCTET STRING belongs.
	vecBadUccsWrongType = "3003020101"

	// A well-formed UccsEvidence with a byte appended.
	vecBadUccsTrailing = vecUccsEvidenceNonceOnly + "00"

	// Two octet strings in a SEQUENCE that declares one member, so which of
	// them is the evidence is undecidable.
	vecBadUccsTwoElements = "302a" + "0413" + vecClaimsNonceOnly + "0413" + vecClaimsNonceOnly
)

// vecNonce is the challenge a0..af that the positive vectors carry.
func vecNonce() []byte {
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}
	return nonce
}

func TestUccsEvidenceVectorDecodesToTheNonce(t *testing.T) {
	claims, err := ParseUccsEvidence(mustDecodeHex(t, vecUccsEvidenceNonceOnly))
	require.NoError(t, err)
	assert.Equal(t, vecNonce(), claims.Nonce)
	assert.Empty(t, claims.Other, "the vector carries no other claim")
}

// TestUccsEvidenceVectorKeepsUnmodelledClaims is the interoperability contract
// stated as a test. A CWT claims set is an open registry: an attester that
// carries a ueid beside its nonce is conforming, and a verifier that refused
// it would refuse most of the DICE devices this extension exists to read.
func TestUccsEvidenceVectorKeepsUnmodelledClaims(t *testing.T) {
	claims, err := ParseUccsEvidence(mustDecodeHex(t, vecUccsEvidenceNonceAndUeid))
	require.NoError(t, err)
	assert.Equal(t, vecNonce(), claims.Nonce)

	require.Len(t, claims.Other, 1)
	ueid, present := claims.Other[256]
	require.True(t, present, "the ueid claim must be kept, not discarded")
	assert.Equal(t, mustDecodeHex(t, "480102030405060708"), ueid,
		"an unmodelled claim is kept as the raw CBOR item it arrived as")
}

// TestUccsEvidenceVectorsRoundTrip pins the encoder against the same literals
// the decoder is pinned against. It is what makes the encoder usable for
// issuance: bytes it produces are bytes another DICE verifier reads.
func TestUccsEvidenceVectorsRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		claims *ClaimsSet
	}{
		{
			name:   "nonce alone",
			vector: vecUccsEvidenceNonceOnly,
			claims: &ClaimsSet{Nonce: vecNonce()},
		},
		{
			name:   "nonce and an unmodelled claim",
			vector: vecUccsEvidenceNonceAndUeid,
			claims: &ClaimsSet{
				Nonce: vecNonce(),
				Other: map[int64][]byte{256: mustDecodeHex(t, "480102030405060708")},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der, err := MarshalUccsEvidence(test.claims)
			require.NoError(t, err)
			assert.Equal(t, mustDecodeHex(t, test.vector), der,
				"the encoder no longer produces the bytes on the wire")

			decoded, err := ParseUccsEvidence(der)
			require.NoError(t, err)
			assert.Equal(t, test.claims.Nonce, decoded.Nonce)
			assert.Equal(t, test.claims.Other, decoded.Other)
		})
	}
}

// TestBadClaimsSetVectorsAreRefused walks every malformed claims set. Each
// asserts the specific sentinel, because "it failed" is not the same contract
// as "it failed for the reason the operator will be told".
func TestBadClaimsSetVectorsAreRefused(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   error
	}{
		{"no eat_nonce claim", vecBadClaimsNoNonce, ErrNonceClaimMissing},
		{"an empty claims set", vecBadClaimsEmpty, ErrMalformedClaimsSet},
		{"a nonce shorter than eight bytes", vecBadClaimsNonceShort, ErrNonceClaimLength},
		{"the eat_nonce key twice", vecBadClaimsDuplicateNonce, ErrDuplicateClaim},
		{"trailing bytes after the map", vecBadClaimsTrailing, ErrMalformedClaimsSet},
		{"an indefinite-length map", vecBadClaimsIndefiniteMap, ErrMalformedClaimsSet},
		{"an indefinite-length nonce", vecBadClaimsIndefiniteNonce, ErrMalformedClaimsSet},
		{"a claim keyed by text", vecBadClaimsTextKey, ErrMalformedClaimsSet},
		{"an array where the map belongs", vecBadClaimsNotAMap, ErrMalformedClaimsSet},
		{"a claims set tagged with the UCCS tag", vecBadClaimsTagged, ErrMalformedClaimsSet},
		{"a nonce that is not a byte string", vecBadClaimsNonceText, ErrMalformedNonceClaim},
		{"several nonces", vecBadClaimsNonceArray, ErrMalformedNonceClaim},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims, err := ParseClaimsSet(mustDecodeHex(t, test.vector))
			require.Error(t, err, "malformed evidence was accepted")
			assert.ErrorIs(t, err, test.want)
			assert.Nil(t, claims)
		})
	}
}

func TestBadUccsEvidenceVectorsAreRefused(t *testing.T) {
	tests := []struct {
		name   string
		vector string
	}{
		{"an empty uccs octet string", vecBadUccsEmptyOctets},
		{"an integer where the octet string belongs", vecBadUccsWrongType},
		{"trailing data after the sequence", vecBadUccsTrailing},
		{"two members in a one-member sequence", vecBadUccsTwoElements},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims, err := ParseUccsEvidence(mustDecodeHex(t, test.vector))
			require.Error(t, err, "malformed evidence was accepted")
			assert.ErrorIs(t, err, ErrMalformedUccsEvidence)
			assert.Nil(t, claims)
		})
	}
}
