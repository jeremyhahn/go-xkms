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
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDICEOIDArcIsWhatTheSpecificationAssigns(t *testing.T) {
	// tcg-dice ::= {tcg(2 23 133) platformClass(5) 4}. Every identifier this
	// package defines has to sit under it, or a certificate this code writes
	// is not readable by any other DICE implementation.
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want string
	}{
		{"tcg-dice", OIDArc, "2.23.133.5.4"},
		{"tcg-dice-TcbInfo", OIDTcbInfo, "2.23.133.5.4.1"},
		{"tcg-dice-endorsement-manifest", OIDEndorsementManifest, "2.23.133.5.4.2"},
		{"tcg-dice-endorsement-manifest-uri", OIDEndorsementManifestURI, "2.23.133.5.4.3"},
		{"tcg-dice-Ueid", OIDUeid, "2.23.133.5.4.4"},
		{"tcg-dice-MultiTcbInfo", OIDMultiTcbInfo, "2.23.133.5.4.5"},
		{"tcg-dice-UCCS-evidence", OIDUccsEvidence, "2.23.133.5.4.6"},
		{"tcg-dice-manifest-evidence", OIDManifestEvidence, "2.23.133.5.4.7"},
		{"tcg-dice-kp", OIDKpArc, "2.23.133.5.4.100"},
		{"tcg-dice-kp-identityInit", OIDKpIdentityInit, "2.23.133.5.4.100.6"},
		{"tcg-dice-kp-identityLoc", OIDKpIdentityLoc, "2.23.133.5.4.100.7"},
		{"tcg-dice-kp-attestInit", OIDKpAttestInit, "2.23.133.5.4.100.8"},
		{"tcg-dice-kp-attestLoc", OIDKpAttestLoc, "2.23.133.5.4.100.9"},
		{"tcg-dice-kp-assertInit", OIDKpAssertInit, "2.23.133.5.4.100.10"},
		{"tcg-dice-kp-assertLoc", OIDKpAssertLoc, "2.23.133.5.4.100.11"},
		{"tcg-dice-kp-eca", OIDKpECA, "2.23.133.5.4.100.12"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, test.oid.String())
			assert.True(t, strings.HasPrefix(test.oid.String(), OIDArc.String()),
				"identifier is not under the tcg-dice arc")
		})
	}
}

func TestMarshalTcbInfoRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		info *TcbInfo
		want error
	}{
		{
			name: "nil",
			info: nil,
			want: ErrNilTcbInfo,
		},
		{
			name: "negative svn",
			info: &TcbInfo{SVN: intPtr(-1)},
			want: ErrNegativeTcbInfoValue,
		},
		{
			name: "negative layer",
			info: &TcbInfo{Layer: intPtr(-4)},
			want: ErrNegativeTcbInfoValue,
		},
		{
			name: "negative index",
			info: &TcbInfo{Index: intPtr(-1)},
			want: ErrNegativeTcbInfoValue,
		},
		{
			name: "fwid with no hash algorithm",
			info: &TcbInfo{FWIDs: []FWID{{Digest: []byte{1, 2, 3}}}},
			want: ErrMalformedFWID,
		},
		{
			name: "fwid with no digest",
			info: &TcbInfo{FWIDs: []FWID{{HashAlg: oidSHA256}}},
			want: ErrMalformedFWID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der, err := MarshalTcbInfo(test.info)
			require.Error(t, err)
			assert.ErrorIs(t, err, test.want)
			assert.Nil(t, der)
		})
	}
}

func TestMarshalTcbInfoOmitsAbsentFields(t *testing.T) {
	// An empty TcbInfo is a legitimate structure -- every field is OPTIONAL --
	// and must encode as an empty SEQUENCE rather than as zeros.
	der, err := MarshalTcbInfo(&TcbInfo{})
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x00}, der)

	info, err := ParseTcbInfo(der)
	require.NoError(t, err)
	assert.Empty(t, info.Vendor)
	assert.Nil(t, info.SVN)
	assert.Nil(t, info.Layer)
	assert.Nil(t, info.Index)
	assert.Nil(t, info.FWIDs)
	assert.Nil(t, info.Flags)
	assert.Nil(t, info.VendorInfo)
	assert.Nil(t, info.Type)
}

func TestMarshalTcbInfoRoundTripsEveryFieldIndependently(t *testing.T) {
	// Each field on its own. A field that only round-trips in the company of
	// the others is a field whose tag is being inferred from its neighbours.
	tests := []struct {
		name string
		info *TcbInfo
	}{
		{"vendor", &TcbInfo{Vendor: "Automate The Things"}},
		{"vendor with non-ascii", &TcbInfo{Vendor: "Ünïcodé Vendor æ"}},
		{"model", &TcbInfo{Model: "AVR-DICE"}},
		{"version", &TcbInfo{Version: "1.0.0"}},
		{"svn zero", &TcbInfo{SVN: intPtr(0)}},
		{"svn large", &TcbInfo{SVN: intPtr(1 << 30)}},
		{"layer zero", &TcbInfo{Layer: intPtr(0)}},
		{"index zero", &TcbInfo{Index: intPtr(0)}},
		{"single fwid", &TcbInfo{FWIDs: []FWID{{HashAlg: oidSHA256, Digest: []byte{1, 2, 3, 4}}}}},
		{"two fwids", &TcbInfo{FWIDs: []FWID{
			{HashAlg: oidSHA256, Digest: []byte{1}},
			{HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, Digest: []byte{2}},
		}}},
		{"flags absent", &TcbInfo{Vendor: "x"}},
		{"flags all clear", &TcbInfo{Flags: &OperationalFlags{}}},
		{"flags notConfigured", &TcbInfo{Flags: &OperationalFlags{NotConfigured: true}}},
		{"flags recovery", &TcbInfo{Flags: &OperationalFlags{Recovery: true}}},
		{"vendorInfo", &TcbInfo{VendorInfo: []byte{0xDE, 0xAD, 0xBE, 0xEF}}},
		{"type", &TcbInfo{Type: []byte("avr-firmware")}},
		{"everything", fullTcbInfo()},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			der, err := MarshalTcbInfo(test.info)
			require.NoError(t, err)

			decoded, err := ParseTcbInfo(der)
			require.NoError(t, err)
			assert.Equal(t, test.info, decoded)

			// Re-encoding the decoded form must reproduce the same bytes, or
			// the structure does not survive a store-and-forward hop.
			again, err := MarshalTcbInfo(decoded)
			require.NoError(t, err)
			assert.Equal(t, der, again)
		})
	}
}

func TestParseTcbInfoRejectsNonSequence(t *testing.T) {
	tests := []struct {
		name string
		der  []byte
	}{
		{"empty input", []byte{}},
		{"an octet string", []byte{0x04, 0x01, 0x00}},
		{"an integer", []byte{0x02, 0x01, 0x05}},
		{"a primitive with the sequence tag", []byte{0x10, 0x00}},
		{"a length that overruns the buffer", []byte{0x30, 0x7f, 0x00}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info, err := ParseTcbInfo(test.der)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrMalformedTcbInfo)
			assert.Nil(t, info)
		})
	}
}

func TestMarshalUeidRejectsEmpty(t *testing.T) {
	der, err := MarshalUeid(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyUeid)
	assert.Nil(t, der)

	der, err = MarshalUeid([]byte{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyUeid)
	assert.Nil(t, der)
}

func TestMarshalUeidRoundTrips(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{"one byte", []byte{0x01}},
		{"sixteen bytes", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
		{"thirty-three bytes", make([]byte, 33)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := test.value
			if len(value) == 33 {
				for i := range value {
					value[i] = byte(i + 1)
				}
			}

			der, err := MarshalUeid(value)
			require.NoError(t, err)

			ueid, err := ParseUeid(der)
			require.NoError(t, err)
			assert.Equal(t, value, ueid.Value)
		})
	}
}

func TestOperationalFlagsAnyAndString(t *testing.T) {
	tests := []struct {
		name  string
		flags OperationalFlags
		any   bool
		text  string
	}{
		{"none", OperationalFlags{}, false, "none"},
		{"notConfigured", OperationalFlags{NotConfigured: true}, true, "notConfigured"},
		{"notSecure", OperationalFlags{NotSecure: true}, true, "notSecure"},
		{"recovery", OperationalFlags{Recovery: true}, true, "recovery"},
		{"debug", OperationalFlags{Debug: true}, true, "debug"},
		{
			name:  "notSecure and debug together",
			flags: OperationalFlags{NotSecure: true, Debug: true},
			any:   true,
			text:  "notSecure|debug",
		},
		{
			name: "all four",
			flags: OperationalFlags{
				NotConfigured: true, NotSecure: true, Recovery: true, Debug: true,
			},
			any:  true,
			text: "notConfigured|notSecure|recovery|debug",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.any, test.flags.Any())
			assert.Equal(t, test.text, test.flags.String())
		})
	}
}

func TestOperationalFlagsBitStringIsDERMinimal(t *testing.T) {
	// DER requires the minimal encoding of a named bit list: trailing clear
	// bits are removed. Two encoders that disagree here produce certificates
	// that carry the same claim and different bytes, which breaks any
	// signature or digest computed over the extension.
	tests := []struct {
		name      string
		flags     OperationalFlags
		bitLength int
		bytes     []byte
	}{
		{"all clear is zero length", OperationalFlags{}, 0, nil},
		{"notConfigured needs one bit", OperationalFlags{NotConfigured: true}, 1, []byte{0x80}},
		{"notSecure needs two bits", OperationalFlags{NotSecure: true}, 2, []byte{0x40}},
		{"recovery needs three bits", OperationalFlags{Recovery: true}, 3, []byte{0x20}},
		{"debug needs four bits", OperationalFlags{Debug: true}, 4, []byte{0x10}},
		{
			name:      "notConfigured and debug still need four bits",
			flags:     OperationalFlags{NotConfigured: true, Debug: true},
			bitLength: 4,
			bytes:     []byte{0x90},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bits := test.flags.BitString()
			assert.Equal(t, test.bitLength, bits.BitLength)
			assert.Equal(t, test.bytes, bits.Bytes)

			back, err := operationalFlagsFromBitString(bits)
			require.NoError(t, err)
			assert.Equal(t, test.flags, *back)
		})
	}
}

func TestOperationalFlagsFromBitStringRejectsUnknownStates(t *testing.T) {
	// A fifth bit is the device declaring an operational state this verifier
	// has no name for. Ignoring it would report the device as sound on the
	// strength of a claim that was never read.
	flags, err := operationalFlagsFromBitString(asn1.BitString{Bytes: []byte{0xF8}, BitLength: 5})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownOperationalFlag)
	assert.Nil(t, flags)
}

func TestCreateTcbInfoExtensionIsCriticalAndParsesBack(t *testing.T) {
	info := fullTcbInfo()

	extension, err := CreateTcbInfoExtension(info)
	require.NoError(t, err)
	assert.True(t, extension.Id.Equal(OIDTcbInfo))
	assert.True(t, extension.Critical,
		"DICE Attestation Architecture 6.1.1 says the TcbInfo extension SHOULD be critical")

	decoded, err := ParseTcbInfo(extension.Value)
	require.NoError(t, err)
	assert.Equal(t, info, decoded)
}

func TestCreateTcbInfoExtensionRejectsBadInput(t *testing.T) {
	extension, err := CreateTcbInfoExtension(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNilTcbInfo)
	assert.Empty(t, extension.Value)

	extension, err = CreateTcbInfoExtension(&TcbInfo{Layer: intPtr(-1)})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNegativeTcbInfoValue)
	assert.Empty(t, extension.Value)
}

func TestCreateUeidExtensionIsNotCriticalAndParsesBack(t *testing.T) {
	value := []byte{9, 8, 7, 6, 5, 4, 3, 2}

	extension, err := CreateUeidExtension(value)
	require.NoError(t, err)
	assert.True(t, extension.Id.Equal(OIDUeid))
	assert.False(t, extension.Critical,
		"a critical UEID would make the certificate unusable to any client that does not know DICE")

	ueid, err := ParseUeid(extension.Value)
	require.NoError(t, err)
	assert.Equal(t, value, ueid.Value)
}

func TestCreateUeidExtensionRejectsEmpty(t *testing.T) {
	extension, err := CreateUeidExtension(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptyUeid)
	assert.Empty(t, extension.Value)
}

func TestExtensionsFromCertificate(t *testing.T) {
	leaf := newTestChain(t).leaf

	info, err := TcbInfoFromCertificate(leaf)
	require.NoError(t, err)
	assert.Equal(t, "Automate The Things", info.Vendor)

	ueid, err := UeidFromCertificate(leaf)
	require.NoError(t, err)
	assert.Equal(t, testUeid, ueid.Value)

	assert.True(t, HasExtensions(leaf))
}

func TestExtensionsFromCertificateRejectBadInput(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		info, err := TcbInfoFromCertificate(nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilCertificate)
		assert.Nil(t, info)

		ueid, err := UeidFromCertificate(nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilCertificate)
		assert.Nil(t, ueid)

		assert.False(t, HasExtensions(nil))
	})

	t.Run("certificate without the extensions", func(t *testing.T) {
		plain := newTestChain(t).root

		info, err := TcbInfoFromCertificate(plain)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTcbInfoNotFound)
		assert.Nil(t, info)

		ueid, err := UeidFromCertificate(plain)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUeidNotFound)
		assert.Nil(t, ueid)

		assert.False(t, HasExtensions(plain))
	})

	t.Run("certificate carrying a malformed extension", func(t *testing.T) {
		chain := newTestChain(t, withRawTcbInfo(mustDecodeHex(t, vecBadUnknownField)))

		info, err := TcbInfoFromCertificate(chain.leaf)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnknownTcbInfoField)
		assert.Nil(t, info)
	})
}

func TestChallengeReadsTheNonceFromTheUccsEvidence(t *testing.T) {
	chain := newTestChain(t)

	challenge, err := Challenge(chain.leaf)
	require.NoError(t, err)
	assert.Equal(t, testNonce, challenge)
}

// TestChallengeDoesNotFallBackToVendorInfo is the placement contract. The
// nonce travels in the eat_nonce claim of tcg-dice-UCCS-evidence, which is the
// mechanism the specification defines and the one another DICE verifier looks
// in. A device that puts it in vendorInfo instead gets a refusal, not a pass:
// a fallback would mean the move bought nothing, since evidence in the wrong
// place would keep verifying.
func TestChallengeDoesNotFallBackToVendorInfo(t *testing.T) {
	chain := newTestChain(t,
		withoutUccs(),
		withTcbInfo(&TcbInfo{Vendor: "Automate The Things", VendorInfo: testNonce}),
	)

	challenge, err := Challenge(chain.leaf)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUccsEvidenceNotFound)
	assert.Nil(t, challenge)
}

func TestChallengeRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		leaf func(*testing.T) *x509.Certificate
		want error
	}{
		{
			name: "nil certificate",
			leaf: func(*testing.T) *x509.Certificate { return nil },
			want: ErrNilCertificate,
		},
		{
			name: "no UCCS evidence to read the nonce from",
			leaf: func(t *testing.T) *x509.Certificate { return newTestChain(t).root },
			want: ErrUccsEvidenceNotFound,
		},
		{
			name: "UCCS evidence present but carrying no nonce",
			leaf: func(t *testing.T) *x509.Certificate {
				// Refused rather than reported as an empty challenge. The
				// device answered with a claims set that does not say it is
				// answering now, and that is not something to hand on to a
				// comparison against the expected value.
				return newTestChain(t, withRawUccs(mustDecodeHex(t,
					"300f"+"040d"+vecBadClaimsNoNonce))).leaf
			},
			want: ErrNonceClaimMissing,
		},
		{
			name: "a claims set framed in a way this profile does not read",
			leaf: func(t *testing.T) *x509.Certificate {
				return newTestChain(t, withRawUccs(mustDecodeHex(t,
					"3018"+"0416"+vecBadClaimsTagged))).leaf
			},
			want: ErrMalformedClaimsSet,
		},
		{
			name: "a UCCS extension that is not even DER",
			leaf: func(t *testing.T) *x509.Certificate {
				return newTestChain(t, withRawUccs(mustDecodeHex(t, vecClaimsNonceOnly))).leaf
			},
			want: ErrMalformedUccsEvidence,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			challenge, err := Challenge(test.leaf(t))
			require.Error(t, err)
			assert.ErrorIs(t, err, test.want)
			assert.Nil(t, challenge)
		})
	}
}

// TestDICECertificateParsesAsAnOrdinaryX509 checks that a certificate carrying
// these extensions is still a certificate. The TcbInfo extension is critical,
// so crypto/x509 records it as unhandled -- which is correct, and is exactly
// what verifyChain has to account for.
func TestDICECertificateRecordsTcbInfoAsUnhandledCritical(t *testing.T) {
	leaf := newTestChain(t).leaf

	var unhandled []string
	for _, oid := range leaf.UnhandledCriticalExtensions {
		unhandled = append(unhandled, oid.String())
	}
	assert.Contains(t, unhandled, OIDTcbInfo.String(),
		"crypto/x509 no longer reports the critical TcbInfo extension as unhandled; verifyChain's workaround needs revisiting")
	assert.NotContains(t, unhandled, OIDUeid.String(),
		"the UEID extension is not critical, so it should never appear here")

	// And the workaround itself: a copy with the DICE OIDs cleared, leaving
	// the caller's certificate untouched.
	cleared, err := withDICEExtensionsHandled(leaf)
	require.NoError(t, err)
	assert.Empty(t, cleared.UnhandledCriticalExtensions)
	assert.NotEmpty(t, leaf.UnhandledCriticalExtensions,
		"the caller's certificate was mutated")
}

// The certificate here now CARRIES the extension whose OID it lists as
// unhandled-critical. It used to list the OID alone, which was enough while
// clearing an entry meant only dropping it from a slice; it no longer is,
// because clearing now requires decoding the extension -- the fix for an
// intermediate whose critical DICE evidence nobody read. A bare OID with no
// extension behind it is exactly the case the decode refuses, and is asserted
// as such at the end.
func TestWithDICEExtensionsHandledKeepsForeignCriticalExtensions(t *testing.T) {
	foreign := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

	tcbInfo, err := CreateTcbInfoExtension(&TcbInfo{Vendor: "Automate The Things"})
	require.NoError(t, err)

	cert := &x509.Certificate{
		Extensions:                  []pkix.Extension{tcbInfo},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{OIDTcbInfo, foreign},
	}

	cleared, err := withDICEExtensionsHandled(cert)
	require.NoError(t, err)
	require.Len(t, cleared.UnhandledCriticalExtensions, 1)
	assert.True(t, cleared.UnhandledCriticalExtensions[0].Equal(foreign),
		"a critical extension this package does not handle must stay unhandled")

	// A certificate with nothing to clear is returned as-is.
	untouched := &x509.Certificate{}
	same, err := withDICEExtensionsHandled(untouched)
	require.NoError(t, err)
	assert.Same(t, untouched, same)

	onlyForeign := &x509.Certificate{UnhandledCriticalExtensions: []asn1.ObjectIdentifier{foreign}}
	same, err = withDICEExtensionsHandled(onlyForeign)
	require.NoError(t, err)
	assert.Same(t, onlyForeign, same)

	// An OID claimed critical with no extension behind it is not something
	// this verifier can say it handled.
	missing := &x509.Certificate{
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{OIDTcbInfo},
	}
	_, err = withDICEExtensionsHandled(missing)
	assert.ErrorIs(t, err, ErrCriticalEvidenceUnreadable)
}

// TestEveryClearedEvidenceOIDHasADecoder is why evidenceDecoders is a map
// rather than a switch. An OID added to diceEvidenceOIDs without a decoder
// would be cleared from the unhandled-critical set by a verifier that cannot
// read it, which is the defect the decode exists to close.
func TestEveryClearedEvidenceOIDHasADecoder(t *testing.T) {
	for _, oid := range diceEvidenceOIDs {
		_, known := evidenceDecoders[oid.String()]
		assert.True(t, known, "%s is cleared as handled but has no decoder", oid)
	}
}
