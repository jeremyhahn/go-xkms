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

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDICEOIDsMatchTheAttestationPackage pins this file's OID registry to the
// canonical definitions in pkg/attestation/dice.
//
// The same identifiers are stated in three places -- here, in
// pkg/certstore/types.go, and in the attestation package that owns the
// structures -- because each is a flat registry its own package reads. Three
// copies of a constant is three chances to mistype a digit, and a certificate
// carrying an extension under the wrong OID is one no other DICE
// implementation can find.
func TestDICEOIDsMatchTheAttestationPackage(t *testing.T) {
	tests := []struct {
		name string
		ca   asn1.ObjectIdentifier
		dice asn1.ObjectIdentifier
	}{
		{"tcg-dice", OIDTCGDice, dice.OIDArc},
		{"tcg-dice-TcbInfo", OIDTCGDiceTcbInfo, dice.OIDTcbInfo},
		{"tcg-dice-endorsement-manifest", OIDTCGDiceEndorsementManifest, dice.OIDEndorsementManifest},
		{"tcg-dice-endorsement-manifest-uri", OIDTCGDiceEndorsementManifestURI, dice.OIDEndorsementManifestURI},
		{"tcg-dice-Ueid", OIDTCGDiceUeid, dice.OIDUeid},
		{"tcg-dice-MultiTcbInfo", OIDTCGDiceMultiTcbInfo, dice.OIDMultiTcbInfo},
		{"tcg-dice-UCCS-evidence", OIDTCGDiceUccsEvidence, dice.OIDUccsEvidence},
		{"tcg-dice-manifest-evidence", OIDTCGDiceManifestEvidence, dice.OIDManifestEvidence},
		{"tcg-dice-kp", OIDTCGDiceKp, dice.OIDKpArc},
		{"tcg-dice-kp-identityInit", OIDTCGDiceKpIdentityInit, dice.OIDKpIdentityInit},
		{"tcg-dice-kp-identityLoc", OIDTCGDiceKpIdentityLoc, dice.OIDKpIdentityLoc},
		{"tcg-dice-kp-attestInit", OIDTCGDiceKpAttestInit, dice.OIDKpAttestInit},
		{"tcg-dice-kp-attestLoc", OIDTCGDiceKpAttestLoc, dice.OIDKpAttestLoc},
		{"tcg-dice-kp-assertInit", OIDTCGDiceKpAssertInit, dice.OIDKpAssertInit},
		{"tcg-dice-kp-assertLoc", OIDTCGDiceKpAssertLoc, dice.OIDKpAssertLoc},
		{"tcg-dice-kp-eca", OIDTCGDiceKpECA, dice.OIDKpECA},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.True(t, test.ca.Equal(test.dice),
				"pkg/ca says %s, pkg/attestation/dice says %s", test.ca, test.dice)
		})
	}
}

// diceTestTcbInfo is the evidence a device puts in its enrollment request.
func diceTestTcbInfo() *dice.TcbInfo {
	layer := 1
	svn := 3
	return &dice.TcbInfo{
		Vendor:  "Automate The Things",
		Model:   "AVR-DICE",
		Version: "1.0.0",
		SVN:     &svn,
		Layer:   &layer,
		FWIDs: []dice.FWID{{
			HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1},
			Digest:  make([]byte, 32),
		}},
	}
}

var diceTestUeid = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

// diceTestRequest builds a certificate request carrying DICE evidence in the
// CSR extensions, which is where a device's enrollment request puts it.
func diceTestRequest(t *testing.T, extensions ...pkix.Extension) *CertificateRequest {
	t.Helper()
	return &CertificateRequest{
		TenantID:      testTenant,
		Subject:       Subject{CommonName: "avr-device-0001"},
		CSRExtensions: extensions,
	}
}

func diceTcbInfoExtension(t *testing.T, info *dice.TcbInfo) pkix.Extension {
	t.Helper()
	extension, err := dice.CreateTcbInfoExtension(info)
	require.NoError(t, err)
	return extension
}

func diceUeidExtension(t *testing.T, value []byte) pkix.Extension {
	t.Helper()
	extension, err := dice.CreateUeidExtension(value)
	require.NoError(t, err)
	return extension
}

func TestNewDICEDeviceIdentityProfileShape(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()

	assert.Equal(t, ProfileNameDICEDeviceIdentity, profile.Name())
	assert.Equal(t, "dice-idevid", profile.Name())
	assert.Equal(t, x509.KeyUsageDigitalSignature, profile.KeyUsage(),
		"DICE Certificate Profiles Table 1: a non-ECA IDevID MUST NOT contain keyCertSign")
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		profile.ExtKeyUsage())
	assert.Equal(t, diceIdentityValidityDays, profile.DefaultValidity())
}

func TestDICEProfileIsRegisteredByDefault(t *testing.T) {
	registry := NewDefaultProfileRegistry()

	profile, err := registry.Get(ProfileNameDICEDeviceIdentity)
	require.NoError(t, err)
	require.NotNil(t, profile)
	assert.Equal(t, ProfileNameDICEDeviceIdentity, profile.Name())

	// Names are case-insensitive, as they are for every other profile.
	profile, err = registry.Get("DICE-IDevID")
	require.NoError(t, err)
	assert.Equal(t, ProfileNameDICEDeviceIdentity, profile.Name())
}

func TestDICEProfileAppliesTheMandatoryPolicyOID(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()
	template := &x509.Certificate{}
	request := diceTestRequest(t, diceTcbInfoExtension(t, diceTestTcbInfo()))

	require.NoError(t, profile.Apply(template, request))

	require.Len(t, template.UnknownExtKeyUsage, 1,
		"Table 1 makes tcg-dice-kp-identityInit mandatory and the other two optional")
	assert.True(t, template.UnknownExtKeyUsage[0].Equal(OIDTCGDiceKpIdentityInit))

	// Table 1: a certificate whose subject is not an embedded CA SHOULD NOT
	// contain BasicConstraints.
	assert.False(t, template.IsCA)
	assert.False(t, template.BasicConstraintsValid)
}

func TestDICEProfileCopiesEvidenceCanonically(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()
	info := diceTestTcbInfo()
	template := &x509.Certificate{}
	request := diceTestRequest(t,
		diceTcbInfoExtension(t, info),
		diceUeidExtension(t, diceTestUeid),
	)

	require.NoError(t, profile.Apply(template, request))

	tcbInfo, found := findExtension(template.ExtraExtensions, OIDTCGDiceTcbInfo)
	require.True(t, found, "the device's measurement did not reach the certificate")
	assert.True(t, tcbInfo.Critical)

	decoded, err := dice.ParseTcbInfo(tcbInfo.Value)
	require.NoError(t, err)
	assert.Equal(t, info, decoded, "the evidence was altered in transit")

	ueidExtension, found := findExtension(template.ExtraExtensions, OIDTCGDiceUeid)
	require.True(t, found)
	assert.False(t, ueidExtension.Critical)

	ueid, err := dice.ParseUeid(ueidExtension.Value)
	require.NoError(t, err)
	assert.Equal(t, diceTestUeid, ueid.Value)
}

// TestDICEProfileReEncodesNonCanonicalEvidence is the reason the value is
// decoded and re-encoded rather than copied. Whatever a device sent, the
// issued certificate carries canonical DER.
func TestDICEProfileReEncodesNonCanonicalEvidence(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()
	template := &x509.Certificate{}

	// A DiceTcbInfo carrying a SHA-256 measurement and flags with every bit
	// clear, the flags encoded as a BIT STRING with no data bits. The value is
	// legal and must survive; what is being checked is that the profile writes
	// back the canonical form rather than the bytes it was handed.
	//
	// The fwids element is here because the profile now REFUSES a TcbInfo
	// without one -- an IDevID whose evidence measures nothing asserts a DICE
	// identity while saying nothing about the firmware it was derived from.
	// This fixture is about canonical re-encoding, so it carries the
	// measurement the profile requires and keeps the flags encoding it was
	// written to pin.
	fwid := "a62f" + // [6] IMPLICIT fwids
		"302d" + // one FWID SEQUENCE
		"0609608648016503040201" + // hashAlg: 2.16.840.1.101.3.4.2.1
		"0420" + strings.Repeat("00", 32) // digest
	original, err := hex.DecodeString("3034" + fwid + "870100")
	require.NoError(t, err)

	request := diceTestRequest(t, pkix.Extension{
		Id: OIDTCGDiceTcbInfo, Critical: false, Value: original,
	})
	require.NoError(t, profile.Apply(template, request))

	written, found := findExtension(template.ExtraExtensions, OIDTCGDiceTcbInfo)
	require.True(t, found)
	assert.Equal(t, original, written.Value)
	assert.True(t, written.Critical,
		"the profile re-encodes the extension, so it also restores the criticality the specification asks for")
}

// TestDICEProfilePreservesNotSecure is the honesty check. A device reporting a
// software-only tier gets a certificate that says so; a CA that dropped the
// flag would issue a certificate reading as a stronger attestation than the
// device ever made.
func TestDICEProfilePreservesNotSecure(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()
	info := diceTestTcbInfo()
	info.Flags = &dice.OperationalFlags{NotSecure: true}

	template := &x509.Certificate{}
	require.NoError(t, profile.Apply(template, diceTestRequest(t, diceTcbInfoExtension(t, info))))

	extension, found := findExtension(template.ExtraExtensions, OIDTCGDiceTcbInfo)
	require.True(t, found)

	decoded, err := dice.ParseTcbInfo(extension.Value)
	require.NoError(t, err)
	require.NotNil(t, decoded.Flags)
	assert.True(t, decoded.Flags.NotSecure, "the notSecure claim was dropped from the certificate")
}

func TestDICEProfileRejectsBadInput(t *testing.T) {
	malformed, err := hex.DecodeString("30038a0101") // an unknown DiceTcbInfo field
	require.NoError(t, err)

	tests := []struct {
		name     string
		template *x509.Certificate
		request  *CertificateRequest
		want     error
	}{
		{
			name:     "nil template",
			template: nil,
			request:  diceTestRequest(t, diceTcbInfoExtension(t, diceTestTcbInfo())),
			want:     ErrInvalidProfile,
		},
		{
			name:     "nil request",
			template: &x509.Certificate{},
			request:  nil,
			want:     ErrDICEEvidenceMissing,
		},
		{
			name:     "request with no evidence at all",
			template: &x509.Certificate{},
			request:  diceTestRequest(t),
			want:     ErrDICEEvidenceMissing,
		},
		{
			name:     "request carrying only a ueid",
			template: &x509.Certificate{},
			request:  diceTestRequest(t, diceUeidExtension(t, diceTestUeid)),
			want:     ErrDICEEvidenceMissing,
		},
		{
			name:     "malformed DiceTcbInfo",
			template: &x509.Certificate{},
			request: diceTestRequest(t, pkix.Extension{
				Id: OIDTCGDiceTcbInfo, Value: malformed,
			}),
			want: ErrDICEEvidenceInvalid,
		},
		{
			name:     "malformed ueid",
			template: &x509.Certificate{},
			request: diceTestRequest(t,
				diceTcbInfoExtension(t, diceTestTcbInfo()),
				pkix.Extension{Id: OIDTCGDiceUeid, Value: []byte{0x30, 0x02, 0x04, 0x00}},
			),
			want: ErrDICEEvidenceInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := NewDICEDeviceIdentityProfile()
			err := profile.Apply(test.template, test.request)
			require.Error(t, err)
			assert.ErrorIs(t, err, test.want)
		})
	}
}

// TestDICEProfileValidatesExtraExtensionsInPlace covers the direct-issuance
// path: the caller supplied the evidence among its own extra extensions, which
// the issuer appends after the profile runs. Adding a second copy here would
// encode the same extension twice, which is malformed.
func TestDICEProfileValidatesExtraExtensionsInPlace(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()
	template := &x509.Certificate{}
	request := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "avr-device-0002"},
		ExtraExtensions: []pkix.Extension{
			diceTcbInfoExtension(t, diceTestTcbInfo()),
			diceUeidExtension(t, diceTestUeid),
		},
	}

	require.NoError(t, profile.Apply(template, request))

	_, found := findExtension(template.ExtraExtensions, OIDTCGDiceTcbInfo)
	assert.False(t, found, "the profile duplicated an extension the issuer will append itself")
}

func TestDICEProfileRejectsMalformedExtraExtensions(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()
	request := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "avr-device-0003"},
		ExtraExtensions: []pkix.Extension{
			{Id: OIDTCGDiceTcbInfo, Value: []byte{0x04, 0x01, 0x00}},
		},
	}

	err := profile.Apply(&x509.Certificate{}, request)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDICEEvidenceInvalid)
}

// TestDICEProfileReplacesAnExistingExtension checks that a template already
// carrying a DICE extension ends up with exactly one, and that it is the one
// the request asked for.
func TestDICEProfileReplacesAnExistingExtension(t *testing.T) {
	profile := NewDICEDeviceIdentityProfile()
	template := &x509.Certificate{
		ExtraExtensions: []pkix.Extension{
			{Id: OIDTCGDiceTcbInfo, Critical: false, Value: []byte{0x30, 0x00}},
		},
	}
	info := diceTestTcbInfo()

	require.NoError(t, profile.Apply(template, diceTestRequest(t, diceTcbInfoExtension(t, info))))

	count := 0
	for _, extension := range template.ExtraExtensions {
		if extension.Id.Equal(OIDTCGDiceTcbInfo) {
			count++
		}
	}
	assert.Equal(t, 1, count, "the certificate carries the DiceTcbInfo extension more than once")

	written, found := findExtension(template.ExtraExtensions, OIDTCGDiceTcbInfo)
	require.True(t, found)
	decoded, err := dice.ParseTcbInfo(written.Value)
	require.NoError(t, err)
	assert.Equal(t, info, decoded)
}

func TestCanonicalDICEExtensionRejectsAForeignOID(t *testing.T) {
	extension, err := canonicalDICEExtension(pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: []byte{0x30, 0x00},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDICEEvidenceInvalid)
	assert.Empty(t, extension.Value)
}

// TestDICEProfileRefusesEvidenceWithNoMeasurement is the empty-structure hole.
//
// Every field of DiceTcbInfo is OPTIONAL, so `30 00` is a syntactically valid
// one, and so is a structure carrying only a vendor string. Both parse, both
// re-encode, and before this check both were signed into an IDevID -- a
// certificate asserting a DICE identity while stating nothing about the
// firmware that identity was derived from, which is the half of DICE that
// makes the identity mean anything. Requiring the extension is not the same as
// requiring the measurement, and applyDICEEvidence's own documentation demands
// the measurement.
func TestDICEProfileRefusesEvidenceWithNoMeasurement(t *testing.T) {
	empty, err := hex.DecodeString("3000")
	require.NoError(t, err)

	metadataOnly, err := dice.MarshalTcbInfo(&dice.TcbInfo{
		Vendor:  "Automate The Things",
		Model:   "AVR-DICE",
		Version: "1.0.0",
	})
	require.NoError(t, err)

	tests := []struct {
		name  string
		value []byte
	}{
		{"an empty DiceTcbInfo", empty},
		{"metadata with no fwids", metadataOnly},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Through the CSR extensions, which is where a device's enrollment
			// request carries its evidence.
			profile := NewDICEDeviceIdentityProfile()
			template := &x509.Certificate{}
			request := diceTestRequest(t, pkix.Extension{
				Id: OIDTCGDiceTcbInfo, Critical: true, Value: test.value,
			})

			err := profile.Apply(template, request)
			require.Error(t, err, "an IDevID was issued against evidence that measures nothing")
			assert.ErrorIs(t, err, ErrDICEEvidenceInvalid)
			assert.ErrorIs(t, err, dice.ErrNoMeasurement)

			// And through ExtraExtensions, the route a caller issuing directly
			// takes. The value is validated and left in place there, so it is a
			// second path to the same signature and needs the same refusal.
			template = &x509.Certificate{}
			direct := &CertificateRequest{
				TenantID: testTenant,
				Subject:  Subject{CommonName: "avr-device-0001"},
				ExtraExtensions: []pkix.Extension{{
					Id: OIDTCGDiceTcbInfo, Critical: true, Value: test.value,
				}},
			}
			err = profile.Apply(template, direct)
			require.Error(t, err, "an IDevID was issued against evidence that measures nothing")
			assert.ErrorIs(t, err, dice.ErrNoMeasurement)
		})
	}

	// The same request with one measurement in it is issued, so what is refused
	// is the missing measurement and not the profile.
	profile := NewDICEDeviceIdentityProfile()
	template := &x509.Certificate{}
	require.NoError(t, profile.Apply(template,
		diceTestRequest(t, diceTcbInfoExtension(t, diceTestTcbInfo()))))
}
