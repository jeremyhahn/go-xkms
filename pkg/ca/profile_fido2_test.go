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

package ca_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// =============================================================================
// FIDO2 Attestation Profile Fixtures
//
// These tests assert WebAuthn Level 2 section 8.2.1 conformance directly on
// the encoded certificate, because that is what a relying party checks. The
// device-side validator that motivated the profile (xkey
// keybackend.ValidateAttestationCertificate) lives on another branch and is
// not exercised here.
// =============================================================================

// attestationVendorCountry and attestationVendorOrganization are the issuing
// CA's own identity. They are deliberately not the package defaults, so an
// assertion that they reach the certificate proves the values were copied from
// the CA rather than hardcoded in the profile.
const (
	attestationVendorCountry      = "SE"
	attestationVendorOrganization = "Acme Authenticators AB"
)

// testAAGUID is the authenticator model identifier a device reports. It is
// xkey's own AAGUID because that is the one model the default profile
// certifies: a request naming any other is refused before it reaches the
// section 8.2.1 conformance assertions these fixtures exist to make.
var testAAGUID = ca.XKeyAAGUID[:]

// foreignAAGUID is an authenticator model the default profile does not
// certify, used by the allowlist tests. The distinctive byte pattern makes a
// mis-copied value obvious in a failure.
var foreignAAGUID = []byte{
	0xcd, 0x8c, 0x39, 0x5c, 0x26, 0xed, 0xee, 0xde,
	0x65, 0x3b, 0x00, 0x79, 0x7d, 0x03, 0xca, 0x3c,
}

// oidFIDOGenCEAAGUID is id-fido-gen-ce-aaguid, restated here rather than read
// from the package so the tests pin the OID the specification names.
var oidFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// Distinguished-name attribute OIDs, restated for the same reason.
var (
	oidAttrCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidAttrOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidAttrOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidAttrCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// marshalAAGUIDExtensionValue encodes an AAGUID the way section 8.2.1
// specifies: a DER OCTET STRING, which the extension's own OCTET STRING
// wrapper then carries.
func marshalAAGUIDExtensionValue(t *testing.T, aaguid []byte) []byte {
	t.Helper()
	value, err := asn1.Marshal(aaguid)
	require.NoError(t, err)
	return value
}

// attestationCSR builds the certificate signing request a provisioned
// authenticator produces for its attestation key: the Subject-OU and common
// name the device can assert, plus the id-fido-gen-ce-aaguid extension. It
// mirrors xkey's Authenticator.AttestationCSR.
func attestationCSR(t *testing.T, extensions ...pkix.Extension) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{ca.FIDO2AttestationCertificateOU},
			CommonName:         "xkey Attestation " + hex.EncodeToString(testAAGUID),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions:    extensions,
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// conformantAttestationCSR builds the request a correctly behaving device
// sends: one carrying its AAGUID.
func conformantAttestationCSR(t *testing.T) []byte {
	t.Helper()
	return attestationCSR(t, pkix.Extension{
		Id:    oidFIDOGenCEAAGUID,
		Value: marshalAAGUIDExtensionValue(t, testAAGUID),
	})
}

// attestationVendorCA returns a CA whose own subject names the attestation
// vendor, so the profile has a country and organization to copy.
func attestationVendorCA(t *testing.T) ca.TrustedCA {
	t.Helper()

	config := rootOnlyConfig(t, "Acme Attestation Root CA")
	config.Identity[0].Subject.Country = attestationVendorCountry
	config.Identity[0].Subject.Organization = attestationVendorOrganization

	return newIssuingCA(t, config, nil)
}

// signAttestationCSR signs a request with the FIDO2 attestation profile and
// re-parses the result from DER, so every assertion runs against the encoded
// certificate rather than the template the profile modified.
func signAttestationCSR(t *testing.T, trustedCA ca.TrustedCA, csrPEM []byte) *x509.Certificate {
	t.Helper()

	cert, err := trustedCA.SignCSR(context.Background(), csrPEM, &ca.SignOptions{
		TenantID: e2eTenant,
		Profile:  ca.ProfileNameFIDO2Attestation,
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	reparsed, err := x509.ParseCertificate(cert.Raw)
	require.NoError(t, err)
	return reparsed
}

// certificateExtension returns the certificate's extension for an OID.
func certificateExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, int) {
	var found pkix.Extension
	count := 0
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oid) {
			if count == 0 {
				found = extension
			}
			count++
		}
	}
	return found, count
}

// subjectAttributeTag returns the ASN.1 tag the encoded subject uses for an
// attribute. Section 8.2.1 types Subject-C as a PrintableString and the other
// three attributes as UTF8String, and only the DER says which was emitted.
func subjectAttributeTag(t *testing.T, cert *x509.Certificate, oid asn1.ObjectIdentifier) (int, bool) {
	t.Helper()

	var subject asn1.RawValue
	_, err := asn1.Unmarshal(cert.RawSubject, &subject)
	require.NoError(t, err)

	rest := subject.Bytes
	for len(rest) > 0 {
		var set asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &set)
		require.NoError(t, err)

		inner := set.Bytes
		for len(inner) > 0 {
			var attribute asn1.RawValue
			inner, err = asn1.Unmarshal(inner, &attribute)
			require.NoError(t, err)

			var attributeType asn1.ObjectIdentifier
			body, err := asn1.Unmarshal(attribute.Bytes, &attributeType)
			require.NoError(t, err)

			var value asn1.RawValue
			_, err = asn1.Unmarshal(body, &value)
			require.NoError(t, err)

			if attributeType.Equal(oid) {
				return value.Tag, true
			}
		}
	}

	return 0, false
}

// applyFIDO2Profile runs the profile against a template whose issuer names the
// attestation vendor, which is the state Issuer.Template hands it.
func applyFIDO2Profile(template *x509.Certificate, request *ca.CertificateRequest) error {
	return ca.NewFIDO2AttestationProfile().Apply(template, request)
}

// attestationTemplate returns the template Issuer.Template would hand the
// profile for a device request: the issuer's subject already copied in, the
// requested common name in place.
func attestationTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject: pkix.Name{CommonName: "xkey Attestation"},
		Issuer: pkix.Name{
			Country:      []string{attestationVendorCountry},
			Organization: []string{attestationVendorOrganization},
			CommonName:   "Acme Attestation Root CA",
		},
	}
}

// attestationRequest returns the issuance context for a device request
// carrying the AAGUID extension.
func attestationRequest(t *testing.T) *ca.CertificateRequest {
	t.Helper()
	return requestWithAAGUID(t, testAAGUID)
}

// requestWithAAGUID returns the issuance context for a device request naming
// the given AAGUID, so a test can vary the model without restating the
// surrounding request.
func requestWithAAGUID(t *testing.T, aaguid []byte) *ca.CertificateRequest {
	t.Helper()
	return &ca.CertificateRequest{
		TenantID: e2eTenant,
		Subject:  ca.Subject{CommonName: "xkey Attestation"},
		CSRExtensions: []pkix.Extension{{
			Id:    oidFIDOGenCEAAGUID,
			Value: marshalAAGUIDExtensionValue(t, aaguid),
		}},
	}
}

// =============================================================================
// Registration
// =============================================================================

// TestFIDO2AttestationProfile_IsRegisteredByName proves the profile is
// selectable by the name `provision-attestation --profile` passes.
func TestFIDO2AttestationProfile_IsRegisteredByName(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()

	profile, err := registry.Get(ca.ProfileNameFIDO2Attestation)
	require.NoError(t, err, "the attestation profile must be a built-in")
	assert.Equal(t, ca.ProfileNameFIDO2Attestation, profile.Name())
	assert.Contains(t, registry.List(), ca.ProfileNameFIDO2Attestation)

	// An attestation key signs attestation statements and nothing else. An
	// extended key usage would only give a relying party a reason to reject the
	// certificate.
	assert.Equal(t, x509.KeyUsageDigitalSignature, profile.KeyUsage())
	assert.Empty(t, profile.ExtKeyUsage())
	assert.Positive(t, profile.DefaultValidity())
}

// TestFIDO2AttestationProfile_UnknownNameIsNotFound is the negative case: a
// misspelled profile name must not silently resolve to some other profile.
func TestFIDO2AttestationProfile_UnknownNameIsNotFound(t *testing.T) {
	registry := ca.NewDefaultProfileRegistry()

	profile, err := registry.Get("fido2-attestion")
	require.ErrorIs(t, err, ca.ErrProfileNotFound)
	assert.Nil(t, profile)
}

// =============================================================================
// End-to-End Conformance
// =============================================================================

// TestFIDO2AttestationProfile_IssuesConformantCertificate is the acceptance
// test: a device's attestation request, signed through the real CA by profile
// name, yields a certificate meeting every WebAuthn Level 2 section 8.2.1
// requirement.
func TestFIDO2AttestationProfile_IssuesConformantCertificate(t *testing.T) {
	csrPEM := conformantAttestationCSR(t)
	cert := signAttestationCSR(t, attestationVendorCA(t), csrPEM)

	// "Version MUST be set to 3."
	assert.Equal(t, 3, cert.Version)

	// "Subject-C: ISO 3166 code specifying the country where the Authenticator
	// vendor is incorporated." The device cannot assert this; the CA's own
	// subject supplies it.
	require.Equal(t, []string{attestationVendorCountry}, cert.Subject.Country,
		"Subject-C must be the issuing CA's country")

	// "Subject-O: Legal name of the Authenticator vendor."
	require.Equal(t, []string{attestationVendorOrganization}, cert.Subject.Organization,
		"Subject-O must be the issuing CA's organization")

	// "Subject-OU: Literal string \"Authenticator Attestation\"."
	require.Equal(t, []string{ca.FIDO2AttestationCertificateOU}, cert.Subject.OrganizationalUnit)

	// "Subject-CN: A UTF8String of the vendor's choosing." The request's common
	// name carries the device's AAGUID, so it is kept.
	assert.Equal(t, "xkey Attestation "+hex.EncodeToString(testAAGUID), cert.Subject.CommonName)

	// "The Basic Constraints extension MUST have the CA component set to
	// false."
	assert.False(t, cert.IsCA)
	assert.True(t, cert.BasicConstraintsValid)
	assert.True(t, hasExtension(cert, oidExtensionBasicConstraints),
		"the basic constraints extension must be encoded")

	// The id-fido-gen-ce-aaguid extension "MUST be present, containing the
	// AAGUID as a 16-byte OCTET STRING", and "MUST NOT be marked as critical".
	extension, count := certificateExtension(cert, oidFIDOGenCEAAGUID)
	require.Equal(t, 1, count, "exactly one id-fido-gen-ce-aaguid extension must be encoded")
	assert.False(t, extension.Critical)

	var certAAGUID []byte
	rest, err := asn1.Unmarshal(extension.Value, &certAAGUID)
	require.NoError(t, err)
	assert.Empty(t, rest)
	assert.True(t, bytes.Equal(testAAGUID, certAAGUID),
		"the certificate must vouch for the AAGUID the request asked for")

	assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage)
	assert.Empty(t, cert.ExtKeyUsage)
}

// TestFIDO2AttestationProfile_EncodesSpecifiedStringTypes pins the ASN.1
// string types section 8.2.1 names: Subject-C is a PrintableString and the
// other three attributes are UTF8String. Go's pkix.Name marshalling emits a
// PrintableString for all four unless the profile intervenes, so this is the
// assertion that keeps the intervention in place.
func TestFIDO2AttestationProfile_EncodesSpecifiedStringTypes(t *testing.T) {
	cert := signAttestationCSR(t, attestationVendorCA(t), conformantAttestationCSR(t))

	countryTag, found := subjectAttributeTag(t, cert, oidAttrCountry)
	require.True(t, found, "Subject-C must be encoded")
	assert.Equal(t, asn1.TagPrintableString, countryTag, "Subject-C must be a PrintableString")

	for _, attribute := range []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"Subject-O", oidAttrOrganization},
		{"Subject-OU", oidAttrOrganizationalUnit},
		{"Subject-CN", oidAttrCommonName},
	} {
		tag, found := subjectAttributeTag(t, cert, attribute.oid)
		require.True(t, found, "%s must be encoded", attribute.name)
		assert.Equal(t, asn1.TagUTF8String, tag, "%s must be a UTF8String", attribute.name)
	}
}

// TestFIDO2AttestationProfile_IgnoresOtherRequestedExtensions proves the CA
// copies the AAGUID extension and nothing else. A requester that could name
// its own extensions would be issuing to itself.
func TestFIDO2AttestationProfile_IgnoresOtherRequestedExtensions(t *testing.T) {
	// A requester asking to be a CA, and an unrecognized extension alongside
	// the legitimate AAGUID.
	caBasicConstraints, err := asn1.Marshal(struct {
		IsCA bool `asn1:"optional"`
	}{IsCA: true})
	require.NoError(t, err)

	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}

	csrPEM := attestationCSR(t,
		pkix.Extension{Id: oidFIDOGenCEAAGUID, Value: marshalAAGUIDExtensionValue(t, testAAGUID)},
		pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true, Value: caBasicConstraints},
		pkix.Extension{Id: unknownOID, Value: []byte{0x04, 0x01, 0x2a}},
	)

	cert := signAttestationCSR(t, attestationVendorCA(t), csrPEM)

	assert.False(t, cert.IsCA, "a requested CA basic constraint must not be honoured")
	assert.False(t, hasExtension(cert, unknownOID),
		"an extension the profile does not understand must not be copied")

	_, count := certificateExtension(cert, oidFIDOGenCEAAGUID)
	assert.Equal(t, 1, count)
}

// TestFIDO2AttestationProfile_RefusesRequestWithoutAAGUID is the fail-closed
// case that matters most: a request naming no authenticator model is refused
// rather than issued as a certificate that vouches for nothing.
func TestFIDO2AttestationProfile_RefusesRequestWithoutAAGUID(t *testing.T) {
	cert, err := attestationVendorCA(t).SignCSR(context.Background(), attestationCSR(t), &ca.SignOptions{
		TenantID: e2eTenant,
		Profile:  ca.ProfileNameFIDO2Attestation,
	})

	require.ErrorIs(t, err, ca.ErrFIDO2AttestationAAGUIDMissing)
	require.ErrorIs(t, err, ca.ErrInvalidProfile,
		"a profile refusal must surface as a profile error")
	assert.Nil(t, cert, "no certificate may be issued when the request is refused")
}

// TestFIDO2AttestationProfile_RefusesMalformedAAGUID covers every way the
// extension can be present but unusable. Each is refused: a relying party
// parsing the same bytes would reject the certificate.
func TestFIDO2AttestationProfile_RefusesMalformedAAGUID(t *testing.T) {
	shortAAGUID := marshalAAGUIDExtensionValue(t, testAAGUID[:15])
	longAAGUID := marshalAAGUIDExtensionValue(t, append(append([]byte{}, testAAGUID...), 0x00))
	wellFormed := marshalAAGUIDExtensionValue(t, testAAGUID)

	tests := []struct {
		name      string
		extension pkix.Extension
	}{
		{
			name:      "fifteen bytes",
			extension: pkix.Extension{Id: oidFIDOGenCEAAGUID, Value: shortAAGUID},
		},
		{
			name:      "seventeen bytes",
			extension: pkix.Extension{Id: oidFIDOGenCEAAGUID, Value: longAAGUID},
		},
		{
			name:      "not an octet string",
			extension: pkix.Extension{Id: oidFIDOGenCEAAGUID, Value: []byte{0x02, 0x01, 0x2a}},
		},
		{
			name:      "trailing data after the octet string",
			extension: pkix.Extension{Id: oidFIDOGenCEAAGUID, Value: append(append([]byte{}, wellFormed...), 0x00)},
		},
		{
			name:      "marked critical",
			extension: pkix.Extension{Id: oidFIDOGenCEAAGUID, Critical: true, Value: wellFormed},
		},
		{
			name:      "empty value",
			extension: pkix.Extension{Id: oidFIDOGenCEAAGUID, Value: nil},
		},
	}

	trustedCA := attestationVendorCA(t)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert, err := trustedCA.SignCSR(context.Background(), attestationCSR(t, test.extension), &ca.SignOptions{
				TenantID: e2eTenant,
				Profile:  ca.ProfileNameFIDO2Attestation,
			})

			require.ErrorIs(t, err, ca.ErrFIDO2AttestationAAGUIDInvalid)
			assert.Nil(t, cert)
		})
	}
}

// TestFIDO2AttestationProfile_AcceptsAAGUIDFromCallerExtensions covers the
// direct-issuance path, where the AAGUID arrives among the caller's own extra
// extensions rather than in a device request. The issuer appends those after
// the profile runs, so the certificate must carry exactly one copy.
func TestFIDO2AttestationProfile_AcceptsAAGUIDFromCallerExtensions(t *testing.T) {
	issued, err := attestationVendorCA(t).IssueCertificateWithProfile(context.Background(), &ca.CertificateRequest{
		TenantID: e2eTenant,
		Subject:  ca.Subject{CommonName: "xkey Attestation Direct"},
		ExtraExtensions: []pkix.Extension{{
			Id:    oidFIDOGenCEAAGUID,
			Value: marshalAAGUIDExtensionValue(t, testAAGUID),
		}},
	}, ca.ProfileNameFIDO2Attestation)
	require.NoError(t, err)
	require.NotNil(t, issued)

	cert, err := x509.ParseCertificate(issued.Certificate.Raw)
	require.NoError(t, err)

	extension, count := certificateExtension(cert, oidFIDOGenCEAAGUID)
	require.Equal(t, 1, count, "the extension must not be encoded twice")
	assert.False(t, extension.Critical)

	var certAAGUID []byte
	_, err = asn1.Unmarshal(extension.Value, &certAAGUID)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(testAAGUID, certAAGUID))

	assert.Equal(t, []string{attestationVendorCountry}, cert.Subject.Country)
	assert.Equal(t, []string{ca.FIDO2AttestationCertificateOU}, cert.Subject.OrganizationalUnit)
}

// TestFIDO2AttestationProfile_RefusesMalformedCallerExtension is the negative
// half of the direct-issuance path: a caller-supplied extension the issuer
// would append verbatim is still validated, so a malformed one cannot reach
// the certificate by that route.
func TestFIDO2AttestationProfile_RefusesMalformedCallerExtension(t *testing.T) {
	issued, err := attestationVendorCA(t).IssueCertificateWithProfile(context.Background(), &ca.CertificateRequest{
		TenantID: e2eTenant,
		Subject:  ca.Subject{CommonName: "xkey Attestation Direct"},
		ExtraExtensions: []pkix.Extension{{
			Id:    oidFIDOGenCEAAGUID,
			Value: marshalAAGUIDExtensionValue(t, testAAGUID[:8]),
		}},
	}, ca.ProfileNameFIDO2Attestation)

	require.ErrorIs(t, err, ca.ErrFIDO2AttestationAAGUIDInvalid)
	assert.Nil(t, issued)
}

// =============================================================================
// Authenticator Model Allowlist
// =============================================================================

// TestFIDO2AttestationProfile_DefaultPermitsOnlyTheShippedModel proves the
// no-argument constructor is fail-closed. An operator who never configures the
// profile still gets a model binding: xkey's AAGUID certifies, and a device
// naming any other model is refused rather than certified on its own say-so.
func TestFIDO2AttestationProfile_DefaultPermitsOnlyTheShippedModel(t *testing.T) {
	require.NoError(t, applyFIDO2Profile(attestationTemplate(), attestationRequest(t)),
		"the shipped model's AAGUID must certify under the default profile")

	template := attestationTemplate()
	err := applyFIDO2Profile(template, requestWithAAGUID(t, foreignAAGUID))

	require.ErrorIs(t, err, ca.ErrFIDO2AttestationAAGUIDNotPermitted)
	assert.Empty(t, template.ExtraExtensions,
		"a refused request must leave no AAGUID on the template")
}

// TestFIDO2AttestationProfile_ExplicitAllowlistReplacesTheDefault proves the
// AAGUIDs the operator lists are the whole policy: a listed model certifies,
// and the shipped model does not unless they listed it too. A default quietly
// unioned into every operator's list would be a model the CA vouches for that
// nobody asked it to.
func TestFIDO2AttestationProfile_ExplicitAllowlistReplacesTheDefault(t *testing.T) {
	var listed [16]byte
	copy(listed[:], foreignAAGUID)
	profile := ca.NewFIDO2AttestationProfile(listed)

	require.NoError(t, profile.Apply(attestationTemplate(), requestWithAAGUID(t, foreignAAGUID)),
		"an AAGUID the operator listed must certify")

	err := profile.Apply(attestationTemplate(), requestWithAAGUID(t, ca.XKeyAAGUID[:]))
	require.ErrorIs(t, err, ca.ErrFIDO2AttestationAAGUIDNotPermitted,
		"the shipped model must not be permitted implicitly")
}

// TestFIDO2AttestationProfile_ExplicitAllowlistPermitsEveryListedModel covers
// the multi-model deployment: an operator running more than one authenticator
// lists them all, and every one of them issues while an unlisted one does not.
func TestFIDO2AttestationProfile_ExplicitAllowlistPermitsEveryListedModel(t *testing.T) {
	var listed [16]byte
	copy(listed[:], foreignAAGUID)
	profile := ca.NewFIDO2AttestationProfile(ca.XKeyAAGUID, listed)

	require.NoError(t, profile.Apply(attestationTemplate(), requestWithAAGUID(t, ca.XKeyAAGUID[:])))
	require.NoError(t, profile.Apply(attestationTemplate(), requestWithAAGUID(t, foreignAAGUID)))

	unlisted := bytes.Repeat([]byte{0x11}, 16)
	require.ErrorIs(t, profile.Apply(attestationTemplate(), requestWithAAGUID(t, unlisted)),
		ca.ErrFIDO2AttestationAAGUIDNotPermitted)
}

// TestFIDO2AttestationProfile_RefusalNamesTheAAGUID proves the refusal carries
// what an operator needs to act on it: the AAGUID in the RFC 4122 form device
// documentation and FIDO metadata publish, and the profile to register to
// admit it. A bare "not permitted" would leave them decoding hex to work out
// which device was turned away.
func TestFIDO2AttestationProfile_RefusalNamesTheAAGUID(t *testing.T) {
	err := applyFIDO2Profile(attestationTemplate(), requestWithAAGUID(t, foreignAAGUID))

	require.ErrorIs(t, err, ca.ErrFIDO2AttestationAAGUIDNotPermitted)
	assert.Contains(t, err.Error(), "cd8c395c-26ed-eede-653b-00797d03ca3c",
		"the refusal must name the AAGUID it refused")
	assert.Contains(t, err.Error(), ca.ProfileNameFIDO2Attestation,
		"the refusal must point at how to permit the model")
}

// TestFIDO2AttestationProfile_RefusesUnpermittedCallerExtension closes the
// direct-issuance route through the CA the default registry builds: a caller
// supplying the extension among its own extra extensions, which the issuer
// would append verbatim, is held to the same allowlist as a device request.
// Enforcing only the CSR path would leave the binding bypassable by the caller
// that does not go through a device.
func TestFIDO2AttestationProfile_RefusesUnpermittedCallerExtension(t *testing.T) {
	issued, err := attestationVendorCA(t).IssueCertificateWithProfile(context.Background(), &ca.CertificateRequest{
		TenantID: e2eTenant,
		Subject:  ca.Subject{CommonName: "xkey Attestation Direct"},
		ExtraExtensions: []pkix.Extension{{
			Id:    oidFIDOGenCEAAGUID,
			Value: marshalAAGUIDExtensionValue(t, foreignAAGUID),
		}},
	}, ca.ProfileNameFIDO2Attestation)

	require.ErrorIs(t, err, ca.ErrFIDO2AttestationAAGUIDNotPermitted)
	assert.Nil(t, issued)
}

// =============================================================================
// Profile Preconditions
// =============================================================================

// TestFIDO2AttestationProfile_RefusesIssuerWithoutVendorIdentity proves the
// profile refuses when the CA's own subject cannot supply Subject-C or
// Subject-O, rather than issuing a certificate missing them — which is the
// defect this profile exists to fix.
func TestFIDO2AttestationProfile_RefusesIssuerWithoutVendorIdentity(t *testing.T) {
	tests := []struct {
		name   string
		issuer pkix.Name
	}{
		{
			name:   "no country",
			issuer: pkix.Name{Organization: []string{attestationVendorOrganization}},
		},
		{
			name:   "no organization",
			issuer: pkix.Name{Country: []string{attestationVendorCountry}},
		},
		{
			name:   "empty country string",
			issuer: pkix.Name{Country: []string{""}, Organization: []string{attestationVendorOrganization}},
		},
		{
			name:   "self-signed, no issuer at all",
			issuer: pkix.Name{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template := attestationTemplate()
			template.Issuer = test.issuer

			err := applyFIDO2Profile(template, attestationRequest(t))
			require.ErrorIs(t, err, ca.ErrFIDO2AttestationIssuerIncomplete)
		})
	}
}

// TestFIDO2AttestationProfile_RefusesRequestWithoutCommonName proves the
// Subject-CN requirement is enforced. The CA has nothing to put there, so it
// refuses rather than issuing a nameless attestation certificate.
func TestFIDO2AttestationProfile_RefusesRequestWithoutCommonName(t *testing.T) {
	template := attestationTemplate()
	template.Subject.CommonName = ""

	err := applyFIDO2Profile(template, attestationRequest(t))
	require.ErrorIs(t, err, ca.ErrFIDO2AttestationSubjectCNRequired)
}

// TestFIDO2AttestationProfile_ApplyRejectsNilInputs covers the two degenerate
// calls: no template to stamp, and no issuance context to read the AAGUID
// from.
func TestFIDO2AttestationProfile_ApplyRejectsNilInputs(t *testing.T) {
	require.ErrorIs(t, applyFIDO2Profile(nil, attestationRequest(t)), ca.ErrInvalidProfile)
	require.ErrorIs(t, applyFIDO2Profile(attestationTemplate(), nil), ca.ErrFIDO2AttestationAAGUIDMissing)
}

// TestFIDO2AttestationProfile_OverridesRequestedCAStatus proves the profile is
// the last word on basic constraints: an issuance context asking for a CA
// certificate still yields CA:false.
func TestFIDO2AttestationProfile_OverridesRequestedCAStatus(t *testing.T) {
	template := attestationTemplate()
	template.IsCA = true

	request := attestationRequest(t)
	request.IsCA = true
	request.MaxPathLen = 3

	require.NoError(t, applyFIDO2Profile(template, request))
	assert.False(t, template.IsCA, "section 8.2.1 requires the CA component to be false")
	assert.True(t, template.BasicConstraintsValid)
}

// TestFIDO2AttestationProfile_ReplacesExistingAAGUIDExtension proves the
// profile is idempotent over the template it is handed: a template that
// already carries an AAGUID extension ends up with one, not two.
func TestFIDO2AttestationProfile_ReplacesExistingAAGUIDExtension(t *testing.T) {
	template := attestationTemplate()
	template.ExtraExtensions = []pkix.Extension{{
		Id:    oidFIDOGenCEAAGUID,
		Value: marshalAAGUIDExtensionValue(t, make([]byte, 16)),
	}}

	require.NoError(t, applyFIDO2Profile(template, attestationRequest(t)))

	matches := 0
	for _, extension := range template.ExtraExtensions {
		if extension.Id.Equal(oidFIDOGenCEAAGUID) {
			matches++

			var aaguid []byte
			_, err := asn1.Unmarshal(extension.Value, &aaguid)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(testAAGUID, aaguid),
				"the requested AAGUID must replace the placeholder")
		}
	}
	assert.Equal(t, 1, matches)
}

// =============================================================================
// The Defect This Profile Fixes
// =============================================================================

// TestSignCSR_DefaultProfileIsNotAttestationConformant records why the profile
// is needed: signing the very same attestation request without it produces a
// certificate with no Subject-C, no Subject-O and no AAGUID extension, which a
// relying party rejects. It is the measurement from go-xkms issue #232, kept
// as a test so a future change that makes the default path conformant is
// noticed rather than assumed.
func TestSignCSR_DefaultProfileIsNotAttestationConformant(t *testing.T) {
	cert, err := attestationVendorCA(t).SignCSR(context.Background(), conformantAttestationCSR(t), &ca.SignOptions{TenantID: e2eTenant})
	require.NoError(t, err)

	assert.Empty(t, cert.Subject.Country,
		"the default path carries only what the CSR asserted, and a device cannot assert its vendor's country")
	assert.Empty(t, cert.Subject.Organization)
	assert.False(t, hasExtension(cert, oidFIDOGenCEAAGUID),
		"the default path copies no CSR extension, so the certificate vouches for no authenticator model")
}

// =============================================================================
// Requested-Extension Plumbing
// =============================================================================

// recordingProfile captures the issuance context a profile is handed, so the
// tests can assert on what the CA passes rather than on what a profile does
// with it.
type recordingProfile struct {
	name    string
	request *ca.CertificateRequest
}

func (p *recordingProfile) Name() string                    { return p.name }
func (p *recordingProfile) KeyUsage() x509.KeyUsage         { return x509.KeyUsageDigitalSignature }
func (p *recordingProfile) ExtKeyUsage() []x509.ExtKeyUsage { return nil }
func (p *recordingProfile) DefaultValidity() int            { return 30 }

func (p *recordingProfile) Apply(template *x509.Certificate, request *ca.CertificateRequest) error {
	if template == nil {
		return ca.ErrInvalidProfile
	}
	p.request = request
	template.BasicConstraintsValid = true
	return nil
}

// TestSignCSR_RequestedExtensionsReachTheProfile proves the plumbing the FIDO2
// profile depends on: the extensions a CSR asked for are handed to the profile
// without being applied to the certificate.
func TestSignCSR_RequestedExtensionsReachTheProfile(t *testing.T) {
	const profileName = "recording"

	unknownOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 8}
	recorder := &recordingProfile{name: profileName}

	registry := ca.NewDefaultProfileRegistry()
	require.NoError(t, registry.Register(profileName, recorder))

	config := rootOnlyConfig(t, "Recording Root CA")
	trustedCA := newIssuingCA(t, config, registry)

	csrPEM := attestationCSR(t, pkix.Extension{Id: unknownOID, Value: []byte{0x04, 0x01, 0x2a}})

	cert, err := trustedCA.SignCSR(context.Background(), csrPEM, &ca.SignOptions{TenantID: e2eTenant, Profile: profileName})
	require.NoError(t, err)

	require.NotNil(t, recorder.request, "the profile must receive an issuance context")
	_, found := certificateExtension(&x509.Certificate{Extensions: recorder.request.CSRExtensions}, unknownOID)
	assert.NotZero(t, found, "the requested extension must reach the profile")

	assert.False(t, hasExtension(cert, unknownOID),
		"a requested extension no profile copied must not reach the certificate")
}

// TestSignCSR_RequestedExtensionsDoNotMutateCallerRequest is the negative
// half: recording what the CSR asked for must not write into the
// CertificateRequest value the caller still holds.
func TestSignCSR_RequestedExtensionsDoNotMutateCallerRequest(t *testing.T) {
	const profileName = "recording-issue"

	recorder := &recordingProfile{name: profileName}
	registry := ca.NewDefaultProfileRegistry()
	require.NoError(t, registry.Register(profileName, recorder))

	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Recording Issue Root CA"), registry)

	// The subject alternative name makes the generated request carry an
	// extension. Without one there would be nothing to write back into the
	// caller's value, and the assertion below would hold either way.
	request := &ca.CertificateRequest{
		TenantID: e2eTenant,
		Subject:  ca.Subject{CommonName: "recorded"},
		SANS:     &ca.SubjectAlternativeNames{DNS: []string{"recorded.example.com"}},
	}
	_, err := trustedCA.IssueCertificateWithProfile(context.Background(), request, profileName)
	require.NoError(t, err)

	require.NotNil(t, recorder.request)
	assert.NotEmpty(t, recorder.request.CSRExtensions,
		"the profile must see the generated request's extensions")
	assert.Nil(t, request.CSRExtensions,
		"the caller's request must be left as it was passed")
	assert.Equal(t, "recorded", recorder.request.Subject.CommonName,
		"the profile must still see the caller's issuance context")
}
