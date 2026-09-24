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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// =============================================================================
// DICE Initial Device Identity Profile
//
// TCG DICE Certificate Profiles v1.0 r0.01 section 5.1.6.1 Table 1 states what
// an IEEE 802.1AR IDevID certificate issued to a DICE device must carry. The
// certificate this profile produces asserts DICE-based device identity with a
// hardware root of trust: an identity derived from a Unique Device Secret and
// a measurement of the firmware the device is running.
// =============================================================================

// ProfileNameDICEDeviceIdentity is the registry name of the DICE IDevID
// profile. It is the name an operator gives to a certificate request, so
// renaming it breaks enrollment against an already-deployed CA.
const ProfileNameDICEDeviceIdentity = "dice-idevid"

// diceIdentityValidityDays is the validity a DICE IDevID is issued for: ten
// years. An initial device identity is provisioned once during manufacturing
// and is expected to outlive every operational credential the device derives
// from it, so a short default would strand working hardware in the field. An
// operator that rotates more aggressively overrides it with
// SignOptions.ValidityDays.
const diceIdentityValidityDays = 3650

// diceIdentityExtKeyUsage is the DICE policy OID an IDevID certificate carries.
//
// DICE Certificate Profiles section 5.1.6.1 Table 1: the certificate "MUST
// contain tcg-dice-kp-identityInit, MAY contain tcg-dice-kp-eca,
// tcg-dice-kp-attestInit". Only the mandatory one is stamped. The two optional
// OIDs say the subject key may run an embedded CA or sign attestation
// evidence, and this CA has no basis to assert either on the device's behalf --
// an IDevID request proves the device holds the key, not what the key is
// allowed to do next.
//
// They travel in UnknownExtKeyUsage because crypto/x509 has no
// x509.ExtKeyUsage constant for any tcg-dice-kp OID; the encoder puts them in
// the same extension as the named usages.
func diceIdentityExtKeyUsage() []asn1.ObjectIdentifier {
	return []asn1.ObjectIdentifier{OIDTCGDiceKpIdentityInit}
}

// diceIdentityExtensions are the DICE evidence extensions this profile carries
// from the request onto the certificate, in the order they are written.
var diceIdentityExtensions = []asn1.ObjectIdentifier{
	OIDTCGDiceTcbInfo,
	OIDTCGDiceUeid,
}

// diceDeviceIdentityProfile issues IDevID certificates to DICE devices.
type diceDeviceIdentityProfile struct {
	baseProfile
}

// NewDICEDeviceIdentityProfile creates the profile for DICE initial device
// identity certificates.
//
// Key usage is DigitalSignature alone. Table 1: "If Subject is an ECA then
// this field MUST contain keyCertSign ... Otherwise MUST NOT contain
// keyCertSign." This profile issues to an end-entity device identity, never to
// an embedded CA, so keyCertSign is absent and Basic Constraints is omitted
// entirely -- Table 1 says a non-ECA certificate "SHOULD NOT contain
// BasicConstraints".
//
// Certificates issued with this profile carry:
//
//   - tcg-dice-kp-identityInit as an extended key usage.
//   - TLS client and server authentication, the "appropriate values for the
//     usage model" Table 1 leaves to the issuer. A device identity exists to
//     authenticate the device's connections.
//   - The device's tcg-dice-TcbInfo evidence, canonically re-encoded.
//   - The device's tcg-dice-Ueid, canonically re-encoded, when the request
//     carries one.
//
// The evidence is copied rather than summarised, and its operational flags are
// copied with it. A device that reported notSecure -- a software-only tier --
// gets a certificate that says so, because the whole value of carrying
// DiceTcbInfo forward is that a relying party can read what the device
// actually claimed. A CA that dropped the flag would be issuing a certificate
// that reads as a stronger attestation than the device ever made.
func NewDICEDeviceIdentityProfile() ProfileProvider {
	return &diceDeviceIdentityProfile{
		baseProfile: baseProfile{
			name:               ProfileNameDICEDeviceIdentity,
			keyUsage:           x509.KeyUsageDigitalSignature,
			extKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			unknownExtKeyUsage: diceIdentityExtKeyUsage(),
			defaultValidity:    diceIdentityValidityDays,
			// Table 1: a certificate whose subject is not an embedded CA
			// "SHOULD NOT contain BasicConstraints".
			basicConstraintsValid: false,
		},
	}
}

// Apply stamps the DICE IDevID requirements onto the certificate template.
func (p *diceDeviceIdentityProfile) Apply(template *x509.Certificate, request *CertificateRequest) error {
	if template == nil {
		return ErrInvalidProfile
	}

	if err := p.baseProfile.Apply(template, request); err != nil {
		return err
	}

	template.IsCA = false

	return applyDICEEvidence(template, request)
}

// applyDICEEvidence copies the device's DICE evidence from the request onto the
// certificate.
//
// The DiceTcbInfo is mandatory, and so is a measurement inside it: without one
// the certificate would assert a device identity while carrying no statement of
// what the device measured, which is the half of DICE that makes the identity
// mean anything. Both are enforced -- the extension here, the fwids in
// canonicalDICEExtension -- because an empty structure satisfies the first
// check and not the second. The UEID is optional, because the DICE certificate
// profile does not require one and a device may be named by its subject
// instead.
func applyDICEEvidence(template *x509.Certificate, request *CertificateRequest) error {
	if request == nil {
		return ErrDICEEvidenceMissing
	}

	for _, oid := range diceIdentityExtensions {
		// The requested extensions are the primary source: an enrollment
		// request produced on the device carries the evidence the device
		// generated.
		extension, found := findExtension(request.CSRExtensions, oid)
		if found {
			canonical, err := canonicalDICEExtension(extension)
			if err != nil {
				return err
			}
			setExtension(template, canonical)
			continue
		}

		// A caller issuing directly rather than from a device request supplies
		// the evidence among its own extra extensions. The issuer appends
		// those to the certificate after this profile runs, so the value is
		// validated here and left where it is; adding a second copy would
		// encode the same extension twice, which is malformed.
		if extension, found = findExtension(request.ExtraExtensions, oid); found {
			if _, err := canonicalDICEExtension(extension); err != nil {
				return err
			}
			continue
		}

		if oid.Equal(OIDTCGDiceTcbInfo) {
			return ErrDICEEvidenceMissing
		}
	}

	return nil
}

// canonicalDICEExtension decodes a DICE evidence extension and re-encodes it.
//
// The value is re-encoded rather than copied byte for byte so the issued
// certificate carries canonical DER whatever the requester sent, and so that
// evidence this CA cannot parse is never signed: a certificate carrying a
// DiceTcbInfo the issuer could not read would invite a relying party to trust
// claims nobody checked.
func canonicalDICEExtension(extension pkix.Extension) (pkix.Extension, error) {
	switch {
	case extension.Id.Equal(OIDTCGDiceTcbInfo):
		info, err := dice.ParseTcbInfo(extension.Value)
		if err != nil {
			return pkix.Extension{}, &errs.Joined{
				Lead:   ErrDICEEvidenceInvalid,
				Detail: "the tcg-dice-TcbInfo extension could not be decoded",
				Cause:  err,
			}
		}
		// A DiceTcbInfo with no fwids is what applyDICEEvidence demands not be
		// issued against: the certificate would assert a DICE identity while
		// saying nothing about the firmware that identity was derived from,
		// which is the half of DICE that makes the identity mean anything.
		//
		// Requiring the EXTENSION and requiring the MEASUREMENT are separate
		// checks because a structure can be present and empty. Every field of
		// DiceTcbInfo is optional, so `30 00` -- a SEQUENCE with nothing in it
		// -- parses and re-encodes without complaint, and so does one carrying
		// only a vendor string. Both would have been signed as an IDevID.
		if len(info.FWIDs) == 0 {
			return pkix.Extension{}, &errs.Joined{
				Lead:   ErrDICEEvidenceInvalid,
				Detail: "the tcg-dice-TcbInfo extension carries no firmware measurement",
				Cause:  dice.ErrNoMeasurement,
			}
		}
		return dice.CreateTcbInfoExtension(info)

	case extension.Id.Equal(OIDTCGDiceUeid):
		ueid, err := dice.ParseUeid(extension.Value)
		if err != nil {
			return pkix.Extension{}, &errs.Joined{
				Lead:   ErrDICEEvidenceInvalid,
				Detail: "the tcg-dice-Ueid extension could not be decoded",
				Cause:  err,
			}
		}
		return dice.CreateUeidExtension(ueid.Value)

	default:
		return pkix.Extension{}, &errs.Detail{
			Err:    ErrDICEEvidenceInvalid,
			Detail: "extension " + extension.Id.String() + " is not DICE evidence this profile carries",
		}
	}
}

// setExtension puts an extension on the template, replacing any entry the
// template already carries for that OID.
func setExtension(template *x509.Certificate, extension pkix.Extension) {
	for i := range template.ExtraExtensions {
		if template.ExtraExtensions[i].Id.Equal(extension.Id) {
			template.ExtraExtensions[i] = extension
			return
		}
	}
	template.ExtraExtensions = append(template.ExtraExtensions, extension)
}
