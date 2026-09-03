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

// Package ca provides the FIDO2 attestation certificate profile: the profile
// that turns a FIDO2 authenticator's attestation certificate signing request
// into a certificate a WebAuthn relying party will accept.
package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// =============================================================================
// FIDO2 Attestation Certificate Profile
//
// WebAuthn Level 2 section 8.2.1 ("Packed Attestation Statement Certificate
// Requirements") states what an attestation certificate must carry. A relying
// party runs those checks on every registration, so a certificate that misses
// any of them silently disables attestation for the life of the device. The
// profile therefore refuses to issue rather than issue something short.
// =============================================================================

// ProfileNameFIDO2Attestation is the registry name of the FIDO2 attestation
// profile. It is the name an operator gives to `xkey fido2
// provision-attestation --profile`, so renaming it breaks provisioning
// against an already-deployed CA.
const ProfileNameFIDO2Attestation = "fido2-attestation"

// FIDO2AttestationCertificateOU is the literal Subject Organizational Unit
// WebAuthn Level 2 section 8.2.1 requires on an attestation certificate. It is
// how a relying party recognizes the certificate as an attestation identity
// rather than an ordinary end-entity certificate.
const FIDO2AttestationCertificateOU = "Authenticator Attestation"

// OIDFIDOGenCEAAGUID is id-fido-gen-ce-aaguid, the extension that binds an
// attestation certificate to one authenticator model. WebAuthn Level 2 section
// 8.2.1 requires it whenever the attestation root certifies more than one
// model, and section 8.2 step 3 has the relying party compare its value with
// the AAGUID in the authenticator data.
var OIDFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// fido2AAGUIDSize is the length of an AAGUID in bytes.
const fido2AAGUIDSize = 16

// fido2AttestationValidityDays is the default validity of an attestation
// certificate: ten years. A device's attestation identity is provisioned once
// by a Security Officer and is expected to outlive every credential the device
// holds, so a short-lived default would strand working authenticators. An
// operator that rotates more aggressively overrides it with
// SignOptions.ValidityDays.
const fido2AttestationValidityDays = 3650

// Distinguished-name attribute OIDs used to encode the subject exactly as
// section 8.2.1 specifies. Go's pkix.Name marshals every string attribute as a
// PrintableString when it can, which is right for Subject-C but not for the
// three attributes the specification calls out as UTF8String, so those are
// emitted through ExtraNames with an explicit tag.
var (
	oidAttributeOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidAttributeOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidAttributeCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// fido2AttestationProfile issues FIDO2 attestation certificates conforming to
// WebAuthn Level 2 section 8.2.1.
type fido2AttestationProfile struct {
	baseProfile
}

// NewFIDO2AttestationProfile creates the profile for FIDO2 authenticator
// attestation certificates.
//
// Key usage is DigitalSignature: an attestation key does nothing but sign
// attestation statements. No extended key usage is set, because an attestation
// certificate is not a TLS or code-signing credential and section 8.2.1 asks
// for none — an EKU here would only invite a relying party to reject it.
//
// Certificates issued with this profile carry:
//
//   - Subject-C and Subject-O copied from the issuing CA's own subject. The
//     specification wants the attestation vendor's country and legal name, and
//     the device cannot assert either credibly; the operator running this CA is
//     the vendor of record for the authenticators it provisions.
//   - Subject-OU set to the literal "Authenticator Attestation".
//   - Subject-CN taken from the request.
//   - The id-fido-gen-ce-aaguid extension carrying the AAGUID the request asked
//     for, non-critical.
//   - Basic constraints asserting CA:false.
func NewFIDO2AttestationProfile() ProfileProvider {
	return &fido2AttestationProfile{
		baseProfile: baseProfile{
			name:                  ProfileNameFIDO2Attestation,
			keyUsage:              x509.KeyUsageDigitalSignature,
			extKeyUsage:           nil,
			defaultValidity:       fido2AttestationValidityDays,
			basicConstraintsValid: true,
		},
	}
}

// Apply stamps the WebAuthn Level 2 section 8.2.1 requirements onto the
// certificate template.
//
// Every requirement the profile cannot satisfy is an error, never a silently
// incomplete certificate: an attestation certificate missing any of these
// fields is rejected by the relying party that receives it, so issuing one
// would only move the failure to a place nobody can diagnose.
func (p *fido2AttestationProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	if err := p.baseProfile.Apply(template, request); err != nil {
		return err
	}

	// Section 8.2.1: "The Basic Constraints extension MUST have the CA
	// component set to false." A CA certificate presented as an attestation
	// leaf would let its holder mint further attestation identities.
	template.IsCA = false
	template.BasicConstraintsValid = true

	if err := applyFIDO2AttestationSubject(template); err != nil {
		return err
	}

	return applyFIDO2AAGUIDExtension(template, request)
}

// applyFIDO2AttestationSubject rewrites the template's subject into the exact
// distinguished name section 8.2.1 requires.
//
// The subject is rebuilt rather than merged: the requester supplies only the
// common name, and every other attribute a certificate signing request might
// have asked for is dropped so that the issued name is a function of the CA's
// identity and nothing the device controls.
//
// The country and organization come from the issuing CA's subject, which the
// issuer has already copied onto the template. A CA whose own subject omits
// either cannot describe an attestation vendor, so issuance is refused instead
// of producing a certificate that fails at the relying party.
func applyFIDO2AttestationSubject(template *x509.Certificate) error {
	country := firstOrEmpty(template.Issuer.Country)
	if country == "" {
		return &errs.Detail{
			Err:    ErrFIDO2AttestationIssuerIncomplete,
			Detail: "issuing ca subject has no country (C) attribute",
		}
	}

	organization := firstOrEmpty(template.Issuer.Organization)
	if organization == "" {
		return &errs.Detail{
			Err:    ErrFIDO2AttestationIssuerIncomplete,
			Detail: "issuing ca subject has no organization (O) attribute",
		}
	}

	commonName := template.Subject.CommonName
	if commonName == "" {
		return ErrFIDO2AttestationSubjectCNRequired
	}

	// Section 8.2.1 types Subject-C as a PrintableString and the remaining
	// three attributes as UTF8String. Country therefore stays on pkix.Name,
	// whose marshalling produces a PrintableString for an ISO 3166 code, while
	// the others are emitted through ExtraNames with an explicit UTF8String
	// tag. ExtraNames are appended in order after the named fields, so the
	// encoded name reads C, O, OU, CN.
	template.Subject = pkix.Name{
		Country: []string{country},
		ExtraNames: []pkix.AttributeTypeAndValue{
			utf8NameAttribute(oidAttributeOrganization, organization),
			utf8NameAttribute(oidAttributeOrganizationalUnit, FIDO2AttestationCertificateOU),
			utf8NameAttribute(oidAttributeCommonName, commonName),
		},
	}

	return nil
}

// utf8NameAttribute builds a distinguished-name attribute whose value is
// encoded as an ASN.1 UTF8String regardless of whether the text would fit a
// narrower string type.
func utf8NameAttribute(oid asn1.ObjectIdentifier, value string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type: oid,
		Value: asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagUTF8String,
			Bytes: []byte(value),
		},
	}
}

// applyFIDO2AAGUIDExtension copies the AAGUID the request asked for onto the
// certificate.
//
// Trust assumption, and its limit: the AAGUID is copied verbatim from the
// request. The CA does not check it against a set of authenticator models the
// operator has vouched for, because no such registry exists in this project.
// What stands behind the value is therefore the provisioning ceremony alone —
// the requester had to hold the device and its Security Officer PIN to produce
// the request, and the CA certifying it is the operator's own. A device that
// clears both bars can name any AAGUID it likes and this CA will certify it,
// which is a weaker binding than the extension implies. Closing that gap needs
// an operator-curated model registry consulted here; until one exists, do not
// read a certificate issued by this profile as evidence of the authenticator's
// model beyond what the ceremony already established.
func applyFIDO2AAGUIDExtension(template *x509.Certificate, request *CertificateRequest) error {
	if request == nil {
		return ErrFIDO2AttestationAAGUIDMissing
	}

	// The requested extensions are the primary source: an attestation request
	// produced on the device carries the AAGUID the device reports.
	extension, found := findExtension(request.CSRExtensions, OIDFIDOGenCEAAGUID)
	if found {
		aaguid, err := parseFIDO2AAGUIDExtension(extension)
		if err != nil {
			return err
		}
		return setFIDO2AAGUIDExtension(template, aaguid)
	}

	// A caller issuing directly rather than from a device request supplies the
	// extension among its own extra extensions. The issuer appends those to the
	// certificate after this profile runs, so the value is validated here and
	// left where it is; adding a second copy would encode the same extension
	// twice, which is malformed.
	if extension, found = findExtension(request.ExtraExtensions, OIDFIDOGenCEAAGUID); found {
		_, err := parseFIDO2AAGUIDExtension(extension)
		return err
	}

	return ErrFIDO2AttestationAAGUIDMissing
}

// parseFIDO2AAGUIDExtension validates an id-fido-gen-ce-aaguid extension and
// returns the AAGUID it carries.
//
// Section 8.2.1 encodes the AAGUID as a DER OCTET STRING which the extension's
// own OCTET STRING wrapper then carries, so the extension value unmarshals to
// exactly sixteen bytes and nothing more.
func parseFIDO2AAGUIDExtension(extension pkix.Extension) ([]byte, error) {
	// Section 8.2.1: "The extension MUST NOT be marked as critical." A relying
	// party that does not recognize a critical extension must reject the whole
	// certificate.
	if extension.Critical {
		return nil, &errs.Detail{
			Err:    ErrFIDO2AttestationAAGUIDInvalid,
			Detail: "extension is marked critical",
		}
	}

	var aaguid []byte
	rest, err := asn1.Unmarshal(extension.Value, &aaguid)
	if err != nil {
		return nil, &errs.Joined{
			Lead:   ErrFIDO2AttestationAAGUIDInvalid,
			Detail: "extension value is not a der octet string",
			Cause:  err,
		}
	}
	if len(rest) != 0 {
		return nil, &errs.Detail{
			Err:    ErrFIDO2AttestationAAGUIDInvalid,
			Detail: "trailing data after the octet string",
		}
	}
	if len(aaguid) != fido2AAGUIDSize {
		return nil, ErrFIDO2AttestationAAGUIDInvalid
	}

	return aaguid, nil
}

// setFIDO2AAGUIDExtension puts the canonically re-encoded AAGUID extension on
// the template, replacing any entry the template already carries for that OID.
//
// The value is re-encoded rather than copied byte for byte so that the issued
// certificate carries canonical DER whatever the requester sent.
func setFIDO2AAGUIDExtension(template *x509.Certificate, aaguid []byte) error {
	value, err := asn1.Marshal(aaguid)
	if err != nil {
		return &errs.Joined{
			Lead:   ErrFIDO2AttestationAAGUIDInvalid,
			Detail: "aaguid could not be encoded",
			Cause:  err,
		}
	}

	extension := pkix.Extension{
		Id:       OIDFIDOGenCEAAGUID,
		Critical: false,
		Value:    value,
	}

	for i := range template.ExtraExtensions {
		if template.ExtraExtensions[i].Id.Equal(OIDFIDOGenCEAAGUID) {
			template.ExtraExtensions[i] = extension
			return nil
		}
	}

	template.ExtraExtensions = append(template.ExtraExtensions, extension)
	return nil
}

// findExtension returns the first extension carrying the given OID.
func findExtension(extensions []pkix.Extension, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, extension := range extensions {
		if extension.Id.Equal(oid) {
			return extension, true
		}
	}
	return pkix.Extension{}, false
}
