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

package deviceattest01

import (
	"crypto/x509"
	"encoding/hex"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Device identity (go-xkms#828)
//
// VerifyAttestation and BindCSRKey together establish that the certificate
// request's key lives inside a genuine, chain-anchored attestation device.
// Neither says anything about WHICH device: the evidence is not secret, so
// anyone who has seen one genuine device's answer could present it beside an
// order for an identifier that device was never assigned. DeviceIdentity is
// the missing half -- the identity the evidence itself carries, read the same
// way this repository already reads it everywhere else an identity has to
// come from a certificate rather than from what a client merely asserts.
//
// The value read is the RFC 4043 permanentIdentifier otherName (OID
// 1.3.6.1.5.5.7.8.3) in the leaf's subjectAltName, exactly as
// pkg/acme/server/handlers.matchesPermanentIdentifierOrder reads it from a
// CSR: this codebase has one convention for what a permanent identifier looks
// like on a certificate, and this is it, not a second one. That convention is
// also why a hardwareModuleName-only otherName is refused here rather than
// accepted as a fallback: matchesPermanentIdentifierOrder refuses any
// otherName besides permanentIdentifier on a CSR, and a leaf whose identity
// this gate accepted by a rule the CSR side does not honor would make the two
// gates disagree about what "the order's identifier" means.
//
//   - "tpm": x5c[0], the AIK certificate. go-xkms's own enroll-01 issuance
//     (pkg/ca/tcg.go, TCG DevID v1 r12 section 8.1) puts the same
//     permanentIdentifier otherName the IDevID carries onto the IAK
//     certificate it issues alongside it -- "on both credentials" is the
//     spec's phrase -- so an AIK certified by this stack's own CA carries
//     it. WebAuthn Level 2 section 8.3.1 itself mandates only the TCG EK
//     Credential Profile section 3.2.9 manufacturer/model/version
//     directoryName, which is not unique per device, so it is not read as an
//     identity here.
//   - "dice": the alias leaf's UEID (TCG DICE Attestation Architecture), the
//     device identifier docs/dice-device-identity names as such, read by
//     dice.DeviceUeid from the tcg-dice-Ueid extension or from the ueid claim
//     (CWT key 256) of the tcg-dice-UCCS-evidence extension. The second is
//     where the arduino-generic firmware states it, because its alias
//     certificate has room for one extension; a gate that read only the first
//     would refuse every real device. The type byte is part of the UEID and is
//     kept. Rendered lowercase hex: the certificate carries it as bytes and
//     an ACME identifier value is a string, and no canonical string form is
//     defined for a Ueid elsewhere in this codebase.
var (
	// ErrDeviceIdentityUnavailable is returned when the attestation evidence
	// carries no device identity this gate can read: no permanentIdentifier
	// otherName on a "tpm" leaf, no UEID on a "dice"
	// leaf, or a format this gate has no rule for. It is not a refusal of
	// the device's identity, it is the gate saying the check could not run
	// -- which must never be treated as the check passing.
	ErrDeviceIdentityUnavailable = errors.New("device-attest-01: the attestation evidence carries no device identity")
)

// DeviceIdentity reads the device identity the verified evidence carries. See
// the package-level discussion above for what is read and why.
//
// It does not compare the identity against anything: the order it must
// authorize is an ACME concept this package does not know about, so that
// comparison is the caller's (pkg/acme/server/handlers).
func (v *VerifiedAttestation) DeviceIdentity() (string, error) {
	leaf, err := v.verifiedLeaf()
	if err != nil {
		return "", err
	}
	return DeviceIdentityFromCertificate(v.Format, leaf)
}

// DeviceIdentityFromCertificate reads the device identity a leaf certificate
// of the given attestation format carries: the RFC 4043 permanentIdentifier of
// a "tpm" AIK certificate, the lowercase-hex UEID of a "dice" alias
// certificate (see dice.DeviceUeid for where it is read from). It is the one rule both sides share -- the server reads it from
// the evidence (DeviceIdentity) and a client reads it from its own
// certificate to name the order's identifier -- so the two cannot disagree
// about what the device's identity is.
func DeviceIdentityFromCertificate(format AttestationFormat, leaf *x509.Certificate) (string, error) {
	if leaf == nil {
		return "", &errs.Detail{Err: ErrDeviceIdentityUnavailable, Detail: "there is no attestation certificate to read the identity from"}
	}
	switch format {
	case FormatTPM:
		return permanentIdentifierFromCertificate(leaf)
	case FormatDICE:
		return diceDeviceIdentity(leaf)
	default:
		return "", &errs.Detail{Err: ErrDeviceIdentityUnavailable, Detail: string(format) + " has no defined device identity source"}
	}
}

// permanentIdentifierFromCertificate reads the RFC 4043 permanentIdentifier
// otherName from a certificate's subjectAltName, the same way
// pkg/acme/server/handlers.matchesPermanentIdentifierOrder reads it from a
// CSR: exactly one otherName of this type, with a non-empty identifierValue.
// A second permanentIdentifier would make the identity depend on SAN order, so
// it is refused. Other otherName types are not: a DevID certificate carries a
// hardwareModuleName beside its permanentIdentifier (TCG DevID v1 r12 section
// 8.1), and refusing it would refuse genuine devices. (The CSR side refuses
// them because a request has no business asserting anything the order did not
// authorize; a certificate is the CA's own statement.)
func permanentIdentifierFromCertificate(cert *x509.Certificate) (string, error) {
	otherNames, err := ca.ParseOtherNames(cert.Extensions)
	if err != nil {
		return "", &errs.Joined{
			Lead:   ErrDeviceIdentityUnavailable,
			Detail: "the attestation certificate's subjectAltName could not be decoded",
			Cause:  err,
		}
	}
	var identity string
	found := false
	for _, other := range otherNames {
		if !other.TypeID.Equal(ca.OIDPermanentIdentifier) {
			continue
		}
		if found {
			return "", &errs.Detail{Err: ErrDeviceIdentityUnavailable, Detail: "the attestation certificate's subjectAltName carries more than one permanentIdentifier otherName"}
		}
		parsed, err := ca.ParsePermanentIdentifierExtension(other.Value)
		if err != nil {
			return "", &errs.Joined{
				Lead:   ErrDeviceIdentityUnavailable,
				Detail: "the attestation certificate's permanentIdentifier otherName could not be decoded",
				Cause:  err,
			}
		}
		if parsed.IdentifierValue == "" {
			return "", &errs.Detail{Err: ErrDeviceIdentityUnavailable, Detail: "the attestation certificate's permanentIdentifier carries no identifierValue"}
		}
		identity = parsed.IdentifierValue
		found = true
	}
	if !found {
		return "", &errs.Detail{Err: ErrDeviceIdentityUnavailable, Detail: "the attestation certificate's subjectAltName carries no RFC 4043 permanentIdentifier otherName"}
	}
	return identity, nil
}

// diceDeviceIdentity reads the UEID from a DICE leaf certificate, rendered as
// lowercase hex.
func diceDeviceIdentity(cert *x509.Certificate) (string, error) {
	ueid, err := dice.DeviceUeid(cert)
	if err != nil {
		return "", &errs.Joined{
			Lead:   ErrDeviceIdentityUnavailable,
			Detail: "the dice leaf certificate states no readable ueid, as a tcg-dice-Ueid extension or as a ueid claim",
			Cause:  err,
		}
	}
	return hex.EncodeToString(ueid), nil
}
