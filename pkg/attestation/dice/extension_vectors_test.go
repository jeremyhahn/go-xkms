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
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DICE wire vectors, byte for byte.
//
// These are LITERALS on purpose. They were derived by hand from the ASN.1 in
// TCG DICE Attestation Architecture v1.00 r0.23 section 6.1 and checked
// structurally with an independent DER parser -- not produced by the encoder
// in this package. A vector computed from the code it is meant to pin moves
// whenever the code moves, and would agree with a regression as readily as
// with the specification.
//
// A failure here is a WIRE BREAK, not a test to update. These bytes are what a
// device puts in a certificate and what every other DICE implementation reads
// out of one; changing them means every already-provisioned device stops
// verifying. Changing the contract means a new extension OID, not new
// literals.
//
// vecTcbInfoFull is a DiceTcbInfo with all ten fields populated:
//
//	vendor     [0] "Automate The Things"
//	model      [1] "AVR-DICE"
//	version    [2] "1.0.0"
//	svn        [3] 1
//	layer      [4] 0          <- meaningful zero; see TestLayerZeroSurvivesTheWire
//	index      [5] 0          <- meaningful zero
//	fwids      [6] one FWID, sha-256 (2.16.840.1.101.3.4.2.1), digest 00..1f
//	flags      [7] notSecure only (bit 1)
//	vendorInfo [8] vendor-defined device state a0..af -- NOT the nonce, which
//	               travels in tcg-dice-UCCS-evidence; see uccs_vectors_test.go
//	type       [9] "avr"
const (
	vecTcbInfoFull = "307b" +
		"80134175746f6d61746520546865205468696e6773" + // [0] vendor
		"81084156522d44494345" + // [1] model
		"8205312e302e30" + // [2] version
		"830101" + // [3] svn = 1
		"840100" + // [4] layer = 0
		"850100" + // [5] index = 0
		"a62f302d060960864801650304020104200001020304050607" + // [6] fwids
		"08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"87020640" + // [7] flags = notSecure
		"8810a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" + // [8] vendorInfo
		"8903617672" // [9] type = "avr"

	// vecTcbInfoLayerZero is a DiceTcbInfo whose only field is layer 0, the
	// DICE core layer. It is a vector rather than a unit assertion because it
	// is the case Go's struct-tag encoder gets wrong: `asn1:"optional,tag:4"`
	// on an int drops the field when the value is zero, producing 3000 -- an
	// empty structure that claims nothing.
	vecTcbInfoLayerZero = "3003840100"

	// vecTcbInfoFlagsNone is a flags field that is PRESENT and carries no set
	// bit: a zero-length BIT STRING. It is not the same evidence as an absent
	// flags field, and re-encoding it must not turn it into one.
	vecTcbInfoFlagsNone = "3003870100"

	// vecTcbInfoFlagsAll has all four operational states active. The DER
	// minimal encoding of a named bit list makes this four bits: four unused
	// bits and the byte 0xF0.
	vecTcbInfoFlagsAll = "3004870204f0"

	// vecTcbInfoFlagsNotSecure has notSecure (bit 1) alone: two bits, six
	// unused, the byte 0x40. This is what the AVR profile emits when the
	// device reports a software-only tier.
	vecTcbInfoFlagsNotSecure = "300487020640"

	// vecTcbInfoFlagsDebug has debug (bit 3) alone, the highest named bit:
	// four bits, four unused, the byte 0x10.
	vecTcbInfoFlagsDebug = "300487020410"

	// vecUeid is a TcgUeid carrying the sixteen-byte identifier 01..10.
	vecUeid = "301204100102030405060708090a0b0c0d0e0f10"
)

// Negative vectors: malformed evidence that must be REFUSED.
//
// Each one is a structure a permissive parser accepts and a correct one does
// not. They are literals for the same reason the positive vectors are: they
// pin what "malformed" means, and a parser that stops rejecting one of these
// has widened what it will treat as attestation evidence.
const (
	// A context tag outside the ten DiceTcbInfo defines, here [10].
	vecBadUnknownField = "30038a0101"

	// The vendor field twice. Two readers of this structure are free to
	// disagree about which value the device meant.
	vecBadDuplicateTag = "3006800141800142"

	// model [1] before vendor [0]: DER requires ascending tag order.
	vecBadFieldOrder = "3006810141800142"

	// A universal UTF8String where a context-specific field belongs, so the
	// element names no DiceTcbInfo member at all.
	vecBadNotContextSpecific = "30030c0141"

	// vendor [0] whose content is not valid UTF-8.
	vecBadUTF8Vendor = "30048002fffe"

	// svn [3] = -1. Every one of svn, layer and index counts something.
	vecBadNegativeSVN = "30038301ff"

	// fwids [6] present and empty. FWIDLIST is SEQUENCE SIZE (1..MAX) OF FWID.
	vecBadEmptyFWIDs = "3002a600"

	// An FWID naming sha-256 with a zero-length digest: a measurement entry
	// that measures nothing.
	vecBadEmptyDigest = "3011a60f300d06096086480165030402010400"

	// flags [7] with five bits, so the device declares a fifth operational
	// state this verifier has no name for.
	vecBadFiveFlagBits = "3004870203f8"

	// vendor [0] encoded as constructed.
	vecBadConstructedString = "3002a000"

	// vendorInfo [8] encoded as constructed. An OCTET STRING field whose
	// constructed bit is set is not the primitive encoding DER requires.
	vecBadConstructedOctets = "3002a800"

	// svn [3] encoded as constructed, so the element cannot be an INTEGER.
	vecBadConstructedInteger = "3003a30101"

	// flags [7] encoded as constructed, so the element cannot be a BIT STRING.
	vecBadConstructedBitString = "3002a700"

	// fwids [6] encoded as primitive, so the element cannot be a SEQUENCE OF.
	vecBadPrimitiveFWIDs = "30028600"

	// A TcgUeid whose OCTET STRING is empty: it identifies no device.
	vecBadUeidEmpty = "30020400"

	// A TcgUeid carrying an INTEGER where the OCTET STRING belongs.
	vecBadUeidWrongType = "3003020101"

	// A well-formed TcgUeid with a byte appended.
	vecBadUeidTrailing = "301204100102030405060708090a0b0c0d0e0f1000"
)

// oidSHA256 is 2.16.840.1.101.3.4.2.1, the hash algorithm in vecTcbInfoFull.
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "vector is not valid hex")
	return b
}

// intPtr is the address-of dance the optional integers need. TcbInfo uses
// pointers because layer 0, index 0 and svn 0 are all meaningful values.
func intPtr(v int) *int { return &v }

// fullTcbInfo is the decoded form of vecTcbInfoFull.
func fullTcbInfo() *TcbInfo {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	vendorInfo := make([]byte, 16)
	for i := range vendorInfo {
		vendorInfo[i] = byte(0xA0 + i)
	}
	return &TcbInfo{
		Vendor:     "Automate The Things",
		Model:      "AVR-DICE",
		Version:    "1.0.0",
		SVN:        intPtr(1),
		Layer:      intPtr(0),
		Index:      intPtr(0),
		FWIDs:      []FWID{{HashAlg: oidSHA256, Digest: digest}},
		Flags:      &OperationalFlags{NotSecure: true},
		VendorInfo: vendorInfo,
		Type:       []byte("avr"),
	}
}

func TestTcbInfoFullVectorDecodesToEveryField(t *testing.T) {
	info, err := ParseTcbInfo(mustDecodeHex(t, vecTcbInfoFull))
	require.NoError(t, err)

	assert.Equal(t, "Automate The Things", info.Vendor)
	assert.Equal(t, "AVR-DICE", info.Model)
	assert.Equal(t, "1.0.0", info.Version)
	require.NotNil(t, info.SVN)
	assert.Equal(t, 1, *info.SVN)
	require.NotNil(t, info.Layer)
	assert.Equal(t, 0, *info.Layer, "layer 0 is the DICE core, not an absent field")
	require.NotNil(t, info.Index)
	assert.Equal(t, 0, *info.Index)

	require.Len(t, info.FWIDs, 1)
	assert.True(t, info.FWIDs[0].HashAlg.Equal(oidSHA256))
	assert.Len(t, info.FWIDs[0].Digest, 32)
	assert.Equal(t, byte(0x00), info.FWIDs[0].Digest[0])
	assert.Equal(t, byte(0x1f), info.FWIDs[0].Digest[31])

	require.NotNil(t, info.Flags)
	assert.Equal(t, OperationalFlags{NotSecure: true}, *info.Flags)

	assert.Equal(t, []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}, info.VendorInfo)
	assert.Equal(t, []byte("avr"), info.Type)
}

func TestTcbInfoFullVectorReEncodesToTheSameBytes(t *testing.T) {
	der, err := MarshalTcbInfo(fullTcbInfo())
	require.NoError(t, err)
	assert.Equal(t, vecTcbInfoFull, hex.EncodeToString(der),
		"the encoder no longer produces the DICE wire format")
}

// TestLayerZeroSurvivesTheWire pins the field encoding/asn1 gets wrong.
//
// A DiceTcbInfo modelled as a struct with `asn1:"optional,tag:4"` encodes
// layer 0 as an empty SEQUENCE, because encoding/asn1 omits any optional field
// holding its type's zero value. Layer 0 is the DICE core -- the first and most
// important layer a device measures -- so that is evidence silently dropped.
func TestLayerZeroSurvivesTheWire(t *testing.T) {
	der, err := MarshalTcbInfo(&TcbInfo{Layer: intPtr(0)})
	require.NoError(t, err)
	require.Equal(t, vecTcbInfoLayerZero, hex.EncodeToString(der))

	info, err := ParseTcbInfo(der)
	require.NoError(t, err)
	require.NotNil(t, info.Layer, "layer 0 decoded as an absent field")
	assert.Equal(t, 0, *info.Layer)

	// The defect this guards against, stated as the contrast it is: a
	// struct-tag encoding of the same value produces an empty SEQUENCE.
	type structTagged struct {
		Layer int `asn1:"optional,tag:4"`
	}
	dropped, err := asn1.Marshal(structTagged{Layer: 0})
	require.NoError(t, err)
	assert.Equal(t, "3000", hex.EncodeToString(dropped),
		"if encoding/asn1 has started preserving optional zeros, the manual encoder's rationale needs revisiting")
}

func TestOperationalFlagsVectorsRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		flags  OperationalFlags
	}{
		{
			name:   "present and all clear is not the same as absent",
			vector: vecTcbInfoFlagsNone,
			flags:  OperationalFlags{},
		},
		{
			name:   "all four operational states active",
			vector: vecTcbInfoFlagsAll,
			flags: OperationalFlags{
				NotConfigured: true,
				NotSecure:     true,
				Recovery:      true,
				Debug:         true,
			},
		},
		{
			name:   "notSecure alone, the software-only tier",
			vector: vecTcbInfoFlagsNotSecure,
			flags:  OperationalFlags{NotSecure: true},
		},
		{
			name:   "debug alone sets the highest named bit",
			vector: vecTcbInfoFlagsDebug,
			flags:  OperationalFlags{Debug: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der, err := MarshalTcbInfo(&TcbInfo{Flags: &test.flags})
			require.NoError(t, err)
			require.Equal(t, test.vector, hex.EncodeToString(der),
				"the flags encoding no longer matches the DICE wire format")

			info, err := ParseTcbInfo(mustDecodeHex(t, test.vector))
			require.NoError(t, err)
			require.NotNil(t, info.Flags, "a flags field that was written must decode as present")
			assert.Equal(t, test.flags, *info.Flags)
		})
	}
}

// TestAbsentFlagsIsNotPresentAndClear pins the distinction the pointer exists
// for. The specification says an omitted flags field means all states
// inactive, but "the device said nothing" and "the device said none" are
// different evidence and must not encode alike.
func TestAbsentFlagsIsNotPresentAndClear(t *testing.T) {
	absent, err := MarshalTcbInfo(&TcbInfo{Layer: intPtr(0)})
	require.NoError(t, err)

	presentAndClear, err := MarshalTcbInfo(&TcbInfo{Layer: intPtr(0), Flags: &OperationalFlags{}})
	require.NoError(t, err)

	assert.NotEqual(t, hex.EncodeToString(absent), hex.EncodeToString(presentAndClear))

	decodedAbsent, err := ParseTcbInfo(absent)
	require.NoError(t, err)
	assert.Nil(t, decodedAbsent.Flags)

	decodedPresent, err := ParseTcbInfo(presentAndClear)
	require.NoError(t, err)
	require.NotNil(t, decodedPresent.Flags)
	assert.False(t, decodedPresent.Flags.Any())
}

func TestUeidVectorRoundTrips(t *testing.T) {
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	ueid, err := ParseUeid(mustDecodeHex(t, vecUeid))
	require.NoError(t, err)
	assert.Equal(t, want, ueid.Value)

	der, err := MarshalUeid(want)
	require.NoError(t, err)
	assert.Equal(t, vecUeid, hex.EncodeToString(der))
}

func TestTcbInfoNegativeVectorsAreRefused(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   error
	}{
		{"unknown field tag", vecBadUnknownField, ErrUnknownTcbInfoField},
		{"repeated field tag", vecBadDuplicateTag, ErrTcbInfoFieldOrder},
		{"fields out of tag order", vecBadFieldOrder, ErrTcbInfoFieldOrder},
		{"field is not context specific", vecBadNotContextSpecific, ErrMalformedTcbInfo},
		{"vendor is not valid utf-8", vecBadUTF8Vendor, ErrMalformedTcbInfo},
		{"negative svn", vecBadNegativeSVN, ErrNegativeTcbInfoValue},
		{"fwids present but empty", vecBadEmptyFWIDs, ErrMalformedFWID},
		{"fwid with an empty digest", vecBadEmptyDigest, ErrMalformedFWID},
		{"flags declares a fifth state", vecBadFiveFlagBits, ErrUnknownOperationalFlag},
		{"utf8string encoded as constructed", vecBadConstructedString, ErrMalformedTcbInfo},
		{"octet string encoded as constructed", vecBadConstructedOctets, ErrMalformedTcbInfo},
		{"integer encoded as constructed", vecBadConstructedInteger, ErrMalformedTcbInfo},
		{"bit string encoded as constructed", vecBadConstructedBitString, ErrMalformedTcbInfo},
		{"fwids encoded as primitive", vecBadPrimitiveFWIDs, ErrMalformedTcbInfo},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := ParseTcbInfo(mustDecodeHex(t, test.vector))
			require.Error(t, err, "malformed evidence was accepted")
			assert.ErrorIs(t, err, test.want)
			assert.Nil(t, info)
		})
	}
}

// TestTruncatedTcbInfoIsRefused walks a truncation across the whole of the
// full vector. Every prefix is malformed, and a parser that accepts any of
// them is reading past the end of what the device actually sent.
func TestTruncatedTcbInfoIsRefused(t *testing.T) {
	full := mustDecodeHex(t, vecTcbInfoFull)

	for cut := 1; cut < len(full); cut++ {
		info, err := ParseTcbInfo(full[:cut])
		require.Error(t, err, "prefix of %d bytes was accepted as a DiceTcbInfo", cut)
		assert.Nil(t, info)
	}
}

func TestTrailingDataAfterTcbInfoIsRefused(t *testing.T) {
	withTrailer := append(mustDecodeHex(t, vecTcbInfoFull), 0x00)

	info, err := ParseTcbInfo(withTrailer)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMalformedTcbInfo)
	assert.Nil(t, info)
}

func TestUeidNegativeVectorsAreRefused(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   error
	}{
		{"empty ueid identifies no device", vecBadUeidEmpty, ErrEmptyUeid},
		{"integer where the octet string belongs", vecBadUeidWrongType, ErrMalformedUeid},
		{"trailing data after the sequence", vecBadUeidTrailing, ErrMalformedUeid},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ueid, err := ParseUeid(mustDecodeHex(t, test.vector))
			require.Error(t, err)
			assert.ErrorIs(t, err, test.want)
			assert.Nil(t, ueid)
		})
	}
}

func TestTruncatedUeidIsRefused(t *testing.T) {
	full := mustDecodeHex(t, vecUeid)

	for cut := 1; cut < len(full); cut++ {
		ueid, err := ParseUeid(full[:cut])
		require.Error(t, err, "prefix of %d bytes was accepted as a TcgUeid", cut)
		assert.Nil(t, ueid)
	}
}
