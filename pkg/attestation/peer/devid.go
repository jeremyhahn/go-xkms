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

package peer

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"time"
)

// The TCG object identifiers a DevID credential is recognised by. They are
// declared here rather than imported from pkg/ca so that a consumer of this
// primitive does not link the certificate authority; pkg/ca is the issuer of
// the same values and TestDevIDOIDsMatchTheIssuer pins the two together so
// they cannot drift.
var (
	// oidTCGVerifiedTPMFixed is tcg-cap-verifiedTPMFixed (2.23.133.11.1.2):
	// the issuing CA verified the certified key is TPM-resident and fixed to
	// its TPM. TCG "TPM 2.0 Keys for Device Identity and Attestation" v1 r12
	// §8.2 stamps it on a device IDENTITY key, which is deliberately
	// Unrestricted so it can sign arbitrary data such as a TLS
	// CertificateVerify.
	oidTCGVerifiedTPMFixed = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 2}

	// oidTCGVerifiedTPMFixedX509 is the same assertion in the x509.OID form Go
	// populates Certificate.Policies with.
	oidTCGVerifiedTPMFixedX509 = mustOID(2, 23, 133, 11, 1, 2)

	// oidTCGHwTypeTPM2 (2.23.133.1.2) is the TCG-registered hwType of a TPM
	// 2.0, carried by the RFC 4108 hardwareModuleName of a DevID certificate
	// (§8.1).
	oidTCGHwTypeTPM2 = asn1.ObjectIdentifier{2, 23, 133, 1, 2}

	// oidTCGOnEKPermIdSha256 is tcg-on-ekPermIdSha256 (2.23.133.12.1), the
	// assigner of the RFC 4043 permanentIdentifier a DevID certificate carries
	// (§8.1: "IDevID/IAK certificates SHALL include both assigner and
	// identifierValue fields").
	oidTCGOnEKPermIdSha256 = asn1.ObjectIdentifier{2, 23, 133, 12, 1}

	// oidHardwareModuleName is RFC 4108 id-on-hardwareModuleName.
	oidHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}

	// oidPermanentIdentifier is RFC 4043 id-on-permanentIdentifier.
	oidPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}

	// oidSubjectAltNameExt is RFC 5280 id-ce-subjectAltName, where both
	// otherNames live.
	oidSubjectAltNameExt = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// DevIDPolicy is what a DevID certificate is checked against. Like Policy it
// is provisioned by the relying party and never learned from the peer.
type DevIDPolicy struct {
	// Anchors are the roots the credential must chain to. There is no
	// default and no waiver: a certificate that chains to nothing proves
	// nothing, so a nil pool is a *DevIDPolicyError rather than a pass.
	Anchors *x509.CertPool

	// Intermediates are additional issuing certificates that may complete the
	// chain.
	Intermediates *x509.CertPool

	// CurrentTime is the instant the certificate's validity and its chain are
	// judged at. The zero value means time.Now().UTC(), which is what
	// production wants; tests pin it.
	CurrentTime time.Time
}

// devIDClass is one of the two TCG credential classes. §8.2 marks them
// differently "to prevent the possibility of spoofing": an identity key
// asserts verifiedTPMFixed and an attestation key verifiedTPMRestricted, and
// the two assertions MUST NOT be combined. Each class therefore both requires
// its own assertion and refuses the other's.
type devIDClass struct {
	// name is how the credential is called in an error.
	name string
	// assert is the TCG assertion the credential must carry.
	assert asn1.ObjectIdentifier
	// assertX509 is assert in the form Go populates Policies with.
	assertX509 x509.OID
	// assertName is the specification's name for assert.
	assertName string
	// forbid is the other class's assertion, which must be absent.
	forbid asn1.ObjectIdentifier
	// forbidX509 is forbid in the form Go populates Policies with.
	forbidX509 x509.OID
	// forbidName is the specification's name for forbid.
	forbidName string
}

var (
	// classIdentity is the IDevID/LDevID class: fixed, never restricted.
	classIdentity = devIDClass{
		name:       "IDevID",
		assert:     oidTCGVerifiedTPMFixed,
		assertX509: oidTCGVerifiedTPMFixedX509,
		assertName: "tcg-cap-verifiedTPMFixed (2.23.133.11.1.2)",
		forbid:     oidTCGVerifiedTPMRestricted,
		forbidX509: oidTCGVerifiedTPMRestrictedX509,
		forbidName: "tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3)",
	}

	// classAttestation is the IAK/LAK class: restricted, never fixed.
	classAttestation = devIDClass{
		name:       "IAK",
		assert:     oidTCGVerifiedTPMRestricted,
		assertX509: oidTCGVerifiedTPMRestrictedX509,
		assertName: "tcg-cap-verifiedTPMRestricted (2.23.133.11.1.3)",
		forbid:     oidTCGVerifiedTPMFixed,
		forbidX509: oidTCGVerifiedTPMFixedX509,
		forbidName: "tcg-cap-verifiedTPMFixed (2.23.133.11.1.2)",
	}
)

// VerifyIDevID reports whether a certificate is a usable TCG device identity
// credential (IDevID, or an LDevID of the same shape) under the policy.
//
// Every check must hold; the first that does not is returned as a
// *DevIDError, so a gate that denies on any error denies on all of them:
//
//  1. the certificate is within its validity window at the policy's clock;
//  2. it chains to Policy.Anchors through Policy.Intermediates;
//  3. it carries the digitalSignature key usage TCG DevID v1 r12 §8.1
//     Table 22 requires, and is not a CA or certificate/CRL signer;
//  4. it asserts tcg-cap-verifiedTPMFixed and does NOT assert
//     tcg-cap-verifiedTPMRestricted, which would make it an attestation key
//     masquerading as an identity (§8.2);
//  5. its subjectAltName carries the two §8.1 otherNames: an RFC 4108
//     hardwareModuleName whose hwType is the TPM 2.0 OID, and an RFC 4043
//     permanentIdentifier assigned by tcg-on-ekPermIdSha256.
//
// It returns *ContextError for a done context and *DevIDPolicyError for a
// policy with no anchors. Nothing about the certificate is reported as
// anything but an error: unlike Verify, which renders a verdict over evidence
// that may be partially absent, a certificate either is this credential or is
// not.
func VerifyIDevID(ctx context.Context, cert *x509.Certificate, policy DevIDPolicy) error {
	return verifyDevID(ctx, cert, policy, classIdentity)
}

// VerifyIAK reports whether a certificate is a usable TCG initial attestation
// key credential (IAK, or an LAK of the same shape) under the policy. It runs
// the same checks as VerifyIDevID with the class assertions exchanged: an IAK
// MUST assert tcg-cap-verifiedTPMRestricted and MUST NOT assert
// tcg-cap-verifiedTPMFixed.
//
// This is the credential whose certificate Verify consumes as
// Evidence.AKCertificatePEM. Verify checks the Restricted assertion itself
// because a quote is worthless without it; VerifyIAK additionally holds the
// certificate to the full §8.1 DevID shape, which is what an enrollment path
// should demand before recording it.
func VerifyIAK(ctx context.Context, cert *x509.Certificate, policy DevIDPolicy) error {
	return verifyDevID(ctx, cert, policy, classAttestation)
}

// IsIDevID reports whether a certificate has the shape of a TCG device
// identity credential: the §8.2 class assertion and the two §8.1 otherNames.
//
// It answers what a certificate claims to be, not whether it may be trusted:
// no chain is built and no clock is consulted. It is for routing a credential
// to the right handler. Authorization is VerifyIDevID.
func IsIDevID(cert *x509.Certificate) bool {
	return devIDShape(cert, classIdentity) == nil
}

// IsIAK reports whether a certificate has the shape of a TCG initial
// attestation key credential. Like IsIDevID it verifies no chain and must not
// be used as an authorization decision; VerifyIAK is.
func IsIAK(cert *x509.Certificate) bool {
	return devIDShape(cert, classAttestation) == nil
}

// verifyDevID runs the full credential check for one class.
func verifyDevID(ctx context.Context, cert *x509.Certificate, policy DevIDPolicy, class devIDClass) error {
	if err := ctx.Err(); err != nil {
		return &ContextError{Cause: err}
	}
	if cert == nil {
		return &DevIDError{Credential: class.name, Reason: "no certificate"}
	}
	if policy.Anchors == nil {
		return &DevIDPolicyError{
			Field:  "Anchors",
			Reason: "no trust anchors configured; a device credential that chains to nothing proves nothing",
		}
	}

	now := policy.CurrentTime
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// The validity window is checked before the chain so that an expired
	// credential says so, rather than reporting the chain failure expiry
	// causes.
	if now.Before(cert.NotBefore) {
		return &DevIDError{
			Credential: class.name,
			Reason:     "certificate is not valid until " + cert.NotBefore.UTC().Format(time.RFC3339),
		}
	}
	if now.After(cert.NotAfter) {
		return &DevIDError{
			Credential: class.name,
			Reason:     "certificate expired at " + cert.NotAfter.UTC().Format(time.RFC3339),
		}
	}

	// A DevID credential carries the TLS client and server usages (§8.1), but
	// what the key is FOR is established by the TCG assertions below, not by
	// extended key usage, so the chain is built for any usage. Constraining it
	// here would reject a conformant credential issued for the other TLS role.
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         policy.Anchors,
		Intermediates: policy.Intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return &DevIDError{
			Credential: class.name,
			Reason:     "certificate does not chain to a trusted anchor",
			Cause:      err,
		}
	}

	if err := verifyDevIDKeyUsage(cert, class); err != nil {
		return err
	}
	return devIDShape(cert, class)
}

// verifyDevIDKeyUsage holds the credential to the key usage TCG DevID v1 r12
// §8.1 Table 22 gives it: digitalSignature, which both classes need to sign a
// CertificateVerify or a quote. A credential that can also sign certificates
// or revocation lists is a CA, not a device.
func verifyDevIDKeyUsage(cert *x509.Certificate, class devIDClass) error {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &DevIDError{
			Credential: class.name,
			Reason:     "certificate does not carry the digitalSignature key usage TCG DevID v1 r12 §8.1 Table 22 requires",
		}
	}
	if cert.IsCA {
		return &DevIDError{
			Credential: class.name,
			Reason:     "certificate asserts the CA basic constraint; a device credential is an end entity",
		}
	}
	if cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return &DevIDError{
			Credential: class.name,
			Reason:     "certificate carries a certificate- or CRL-signing key usage; a device credential signs neither",
		}
	}
	return nil
}

// devIDShape checks what a certificate claims about itself: the §8.2 class
// assertion, the absence of the other class's assertion, and the two §8.1
// subjectAltName otherNames. It builds no chain, so it is exactly what the
// Is* predicates answer and the last stage of what the Verify* functions
// demand.
func devIDShape(cert *x509.Certificate, class devIDClass) error {
	if cert == nil {
		return &DevIDError{Credential: class.name, Reason: "no certificate"}
	}
	if !carriesTCGAssertion(cert, class.assert, class.assertX509) {
		return &DevIDError{
			Credential: class.name,
			Reason:     "certificate does not assert " + class.assertName + ", required by TCG DevID v1 r12 §8.2",
		}
	}
	if carriesTCGAssertion(cert, class.forbid, class.forbidX509) {
		return &DevIDError{
			Credential: class.name,
			Reason: "certificate asserts " + class.forbidName + ", which marks the other credential class; " +
				"TCG DevID v1 r12 §8.2 forbids combining the two",
		}
	}

	hardware, permanent, err := devIDOtherNames(cert, class)
	if err != nil {
		return err
	}
	if !hardware.HWType.Equal(oidTCGHwTypeTPM2) {
		return &DevIDError{
			Credential: class.name,
			Reason:     "hardware module name declares hwType " + hardware.HWType.String() + ", not the TPM 2.0 OID 2.23.133.1.2",
		}
	}
	if len(hardware.HWSerial) == 0 {
		return &DevIDError{Credential: class.name, Reason: "hardware module name carries no hwSerialNum"}
	}
	if permanent.IdentifierValue == "" {
		return &DevIDError{Credential: class.name, Reason: "permanent identifier carries no identifierValue"}
	}
	if len(permanent.Assigner) == 0 {
		return &DevIDError{
			Credential: class.name,
			Reason: "permanent identifier carries no assigner; TCG DevID v1 r12 §8.1 requires both assigner " +
				"and identifierValue on an IDevID/IAK certificate",
		}
	}
	if !permanent.Assigner.Equal(oidTCGOnEKPermIdSha256) {
		return &DevIDError{
			Credential: class.name,
			Reason: "permanent identifier is assigned by " + permanent.Assigner.String() +
				", not tcg-on-ekPermIdSha256 (2.23.133.12.1)",
		}
	}
	return nil
}

// carriesTCGAssertion reports whether a certificate asserts a TCG capability
// OID, in either of the two encodings TCG DevID v1 r12 §8 defines for it: a
// certificate policy (§8.2, "No data") or an extended key usage (§8.1, "the
// one TCG OID most appropriate for the type of key used"). pkg/ca stamps both.
//
// Go splits each across two fields — Policies and the legacy
// PolicyIdentifiers, ExtKeyUsage and UnknownExtKeyUsage — and a TCG OID is
// never one of Go's known extended key usages, so three fields are consulted.
func carriesTCGAssertion(cert *x509.Certificate, oid asn1.ObjectIdentifier, policy x509.OID) bool {
	for _, p := range cert.Policies {
		if p.Equal(policy) {
			return true
		}
	}
	for _, p := range cert.PolicyIdentifiers {
		if p.Equal(oid) {
			return true
		}
	}
	for _, eku := range cert.UnknownExtKeyUsage {
		if eku.Equal(oid) {
			return true
		}
	}
	return false
}

// tcgHardwareModuleName is the RFC 4108 HardwareModuleName carried as a
// subjectAltName otherName:
//
//	HardwareModuleName ::= SEQUENCE { hwType OBJECT IDENTIFIER, hwSerialNum OCTET STRING }
type tcgHardwareModuleName struct {
	HWType   asn1.ObjectIdentifier
	HWSerial []byte
}

// tcgPermanentIdentifier is the RFC 4043 PermanentIdentifier carried as a
// subjectAltName otherName:
//
//	PermanentIdentifier ::= SEQUENCE { identifierValue UTF8String OPTIONAL, assigner OBJECT IDENTIFIER OPTIONAL }
//
// Both fields are OPTIONAL in RFC 4043 and both are a SHALL for a DevID
// credential in §8.1, so absence decodes cleanly here and is refused by the
// caller with a reason naming which field is missing.
type tcgPermanentIdentifier struct {
	IdentifierValue string                `asn1:"optional,utf8"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

// devIDOtherNames extracts the two TCG DevID §8.1 otherNames from a
// certificate's subjectAltName. crypto/x509 parses the standard GeneralName
// choices and silently skips otherName, so the extension is decoded here.
//
// A missing or malformed name is an error, never a skipped check: these names
// are what bind the credential to a TPM.
func devIDOtherNames(cert *x509.Certificate, class devIDClass) (*tcgHardwareModuleName, *tcgPermanentIdentifier, error) {
	var encoded []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltNameExt) {
			encoded = ext.Value
			break
		}
	}
	if len(encoded) == 0 {
		return nil, nil, &DevIDError{
			Credential: class.name,
			Reason:     "certificate has no subjectAltName; TCG DevID v1 r12 §8.1 requires a hardware module name and a permanent identifier",
		}
	}

	var sequence asn1.RawValue
	if _, err := asn1.Unmarshal(encoded, &sequence); err != nil {
		return nil, nil, &DevIDError{Credential: class.name, Reason: "subjectAltName does not decode", Cause: err}
	}

	var hardware *tcgHardwareModuleName
	var permanent *tcgPermanentIdentifier
	rest := sequence.Bytes
	for len(rest) > 0 {
		var name asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &name)
		if err != nil {
			return nil, nil, &DevIDError{Credential: class.name, Reason: "subjectAltName holds a general name that does not decode", Cause: err}
		}
		rest = remaining

		// otherName is GeneralName CHOICE [0], an IMPLICIT constructed tag
		// over the OtherName SEQUENCE. Every other choice is a name this
		// credential may also carry and is not one of these two.
		if name.Class != asn1.ClassContextSpecific || name.Tag != 0 || !name.IsCompound {
			continue
		}
		typeID, value, err := splitOtherName(name.Bytes)
		if err != nil {
			return nil, nil, &DevIDError{Credential: class.name, Reason: "subjectAltName holds an otherName that does not decode", Cause: err}
		}

		switch {
		case typeID.Equal(oidHardwareModuleName):
			decoded := &tcgHardwareModuleName{}
			if _, err := asn1.Unmarshal(value, decoded); err != nil {
				return nil, nil, &DevIDError{Credential: class.name, Reason: "hardware module name does not decode", Cause: err}
			}
			hardware = decoded
		case typeID.Equal(oidPermanentIdentifier):
			decoded := &tcgPermanentIdentifier{}
			if _, err := asn1.Unmarshal(value, decoded); err != nil {
				return nil, nil, &DevIDError{Credential: class.name, Reason: "permanent identifier does not decode", Cause: err}
			}
			permanent = decoded
		}
	}

	if hardware == nil {
		return nil, nil, &DevIDError{
			Credential: class.name,
			Reason:     "subjectAltName carries no RFC 4108 hardware module name, which TCG DevID v1 r12 §8.1 requires",
		}
	}
	if permanent == nil {
		return nil, nil, &DevIDError{
			Credential: class.name,
			Reason:     "subjectAltName carries no RFC 4043 permanent identifier, which TCG DevID v1 r12 §8.1 requires",
		}
	}
	return hardware, permanent, nil
}

// splitOtherName decodes the body of a GeneralName otherName into its type
// identifier and the DER of its value:
//
//	OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }
func splitOtherName(der []byte) (asn1.ObjectIdentifier, []byte, error) {
	var typeID asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &typeID)
	if err != nil {
		return nil, nil, err
	}
	var wrapper asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &wrapper); err != nil {
		return nil, nil, err
	}
	if wrapper.Class != asn1.ClassContextSpecific || wrapper.Tag != 0 || !wrapper.IsCompound {
		return nil, nil, asn1.StructuralError{Msg: "otherName value is not [0] EXPLICIT"}
	}
	return typeID, wrapper.Bytes, nil
}
