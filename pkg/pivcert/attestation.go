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

package pivcert

// PIV slot-attestation parsing.
//
// A PIV attestation certificate carries vendor extensions describing the
// device the key lives on and the policy that governs its use. xkms produced
// this material (AttestPIVSlot) without being able to read it back, so a
// consumer could establish only that a chain anchored — never that touch was
// required, or which device it came from.
//
// SCOPE OF VALIDATION. The layout implemented here is Yubico's documented one
// (developers.yubico.com, PIV attestation). It has NOT been validated against
// a physical device: no YubiKey was available, so there is no captured
// certificate to test against, and every fixture in this package's tests is
// built by this package's own encoder. That is a closed loop, and it cannot
// prove the framing is right.
//
// The design answers that rather than hiding it. Each field is decoded
// STRICTLY — exact lengths, exact ASN.1 types — and anything that does not
// match is reported as unparseable rather than being coerced into a plausible
// value. A device whose framing differs from this reading therefore surfaces
// as "I could not read this extension", which a caller can act on, instead of
// a confidently wrong touch policy, which it cannot.

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// Yubico PIV attestation extension OIDs, under the 1.3.6.1.4.1.41482.3 arc.
var (
	// OIDFirmwareVersion carries the device firmware version.
	OIDFirmwareVersion = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}

	// OIDSerialNumber carries the device serial number.
	OIDSerialNumber = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}

	// OIDPINTouchPolicy carries the PIN policy and the touch policy.
	OIDPINTouchPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}

	// OIDFormFactor carries the device form factor.
	OIDFormFactor = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}
)

// PINPolicy is how often the PIN must be presented to use the key.
type PINPolicy uint8

// PIN policy values.
const (
	PINPolicyNever  PINPolicy = 0x01
	PINPolicyOnce   PINPolicy = 0x02
	PINPolicyAlways PINPolicy = 0x03
)

// String returns the policy name, or a hex form for a value this build does
// not recognise. An unrecognised value is rendered rather than hidden: a newer
// firmware may define one, and a caller comparing against a known policy will
// not match it either way.
func (p PINPolicy) String() string {
	switch p {
	case PINPolicyNever:
		return "never"
	case PINPolicyOnce:
		return "once"
	case PINPolicyAlways:
		return "always"
	default:
		return fmt.Sprintf("unrecognized(0x%02x)", uint8(p))
	}
}

// Known reports whether this build recognises the policy value.
func (p PINPolicy) Known() bool {
	return p == PINPolicyNever || p == PINPolicyOnce || p == PINPolicyAlways
}

// TouchPolicy is whether the device requires a physical touch to use the key.
type TouchPolicy uint8

// Touch policy values.
const (
	TouchPolicyNever  TouchPolicy = 0x01
	TouchPolicyAlways TouchPolicy = 0x02
	TouchPolicyCached TouchPolicy = 0x03
)

// String returns the policy name, or a hex form for an unrecognised value.
func (t TouchPolicy) String() string {
	switch t {
	case TouchPolicyNever:
		return "never"
	case TouchPolicyAlways:
		return "always"
	case TouchPolicyCached:
		return "cached"
	default:
		return fmt.Sprintf("unrecognized(0x%02x)", uint8(t))
	}
}

// Known reports whether this build recognises the policy value.
func (t TouchPolicy) Known() bool {
	return t == TouchPolicyNever || t == TouchPolicyAlways || t == TouchPolicyCached
}

// FormFactor is the physical shape of the device, with the high bit marking a
// FIPS model. Use FormFactor.Base to compare against the constants and
// FormFactor.FIPS to read the flag.
type FormFactor uint8

// Form factor values, without the FIPS bit.
const (
	FormFactorUSBAKeychain FormFactor = 0x01
	FormFactorUSBANano     FormFactor = 0x02
	FormFactorUSBCKeychain FormFactor = 0x03
	FormFactorUSBCNano     FormFactor = 0x04
	FormFactorLightning    FormFactor = 0x05
)

// formFactorFIPSBit marks a FIPS model.
const formFactorFIPSBit = 0x80

// Base returns the form factor with the FIPS bit cleared.
func (f FormFactor) Base() FormFactor { return f &^ formFactorFIPSBit }

// FIPS reports whether the device is a FIPS model.
func (f FormFactor) FIPS() bool { return f&formFactorFIPSBit != 0 }

// String returns the form factor name, noting FIPS where set.
func (f FormFactor) String() string {
	var name string
	switch f.Base() {
	case FormFactorUSBAKeychain:
		name = "usb-a-keychain"
	case FormFactorUSBANano:
		name = "usb-a-nano"
	case FormFactorUSBCKeychain:
		name = "usb-c-keychain"
	case FormFactorUSBCNano:
		name = "usb-c-nano"
	case FormFactorLightning:
		name = "lightning"
	default:
		name = fmt.Sprintf("unrecognized(0x%02x)", uint8(f.Base()))
	}
	if f.FIPS() {
		return name + "+fips"
	}
	return name
}

// FirmwareVersion is the device firmware version.
type FirmwareVersion struct {
	Major uint8
	Minor uint8
	Patch uint8
}

// String renders the version as major.minor.patch.
func (v FirmwareVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// AtLeast reports whether v is at or above the given version, for a caller
// enforcing a firmware floor.
func (v FirmwareVersion) AtLeast(major, minor, patch uint8) bool {
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Patch >= patch
}

// Attestation is what a PIV slot-attestation certificate says about the device
// and the key's policy.
//
// Every field is a pointer, and nil means the extension was NOT USABLE — which
// is two different situations that a caller enforcing a policy has to tell
// apart:
//
//   - the extension was absent, e.g. firmware that predates it;
//   - the extension was present and could not be decoded.
//
// Unparseable lists the OIDs in the second group. A nil field whose OID is not
// in Unparseable was absent. Collapsing the two would let "this device does
// not report touch policy" and "this device reports something I cannot read"
// produce the same verdict, and they warrant opposite responses: the first may
// be acceptable, the second means the evidence is not being understood.
type Attestation struct {
	// FirmwareVersion is the device firmware, nil when not usable.
	FirmwareVersion *FirmwareVersion

	// SerialNumber is the device serial, nil when not usable.
	SerialNumber *uint64

	// PINPolicy is how often the PIN is required, nil when not usable.
	PINPolicy *PINPolicy

	// TouchPolicy is whether a touch is required, nil when not usable.
	TouchPolicy *TouchPolicy

	// FormFactor is the device shape and FIPS flag, nil when not usable.
	FormFactor *FormFactor

	// Unparseable holds the attestation OIDs that were present on the
	// certificate but whose contents did not decode. It is the difference
	// between "absent" and "unreadable".
	Unparseable []asn1.ObjectIdentifier
}

// IsUnparseable reports whether the given attestation OID was present but did
// not decode.
func (a *Attestation) IsUnparseable(oid asn1.ObjectIdentifier) bool {
	if a == nil {
		return false
	}
	for _, got := range a.Unparseable {
		if got.Equal(oid) {
			return true
		}
	}
	return false
}

// HasAttestationExtensions reports whether the certificate carried any
// recognised attestation extension at all, decodable or not.
//
// It answers "is this an attestation certificate", which is a different
// question from "did every field decode". A caller with no vendor root
// configured can use this as the presence check it already performs, without
// depending on the values.
func (a *Attestation) HasAttestationExtensions() bool {
	if a == nil {
		return false
	}
	return a.FirmwareVersion != nil || a.SerialNumber != nil ||
		a.PINPolicy != nil || a.TouchPolicy != nil ||
		a.FormFactor != nil || len(a.Unparseable) > 0
}

// ParseAttestation reads the Yubico attestation extensions from a PIV slot
// attestation certificate.
//
// It performs NO trust evaluation: a certificate that decodes returns its
// values whether or not it chains to anything. Use VerifyAttestation to
// establish trust, or pair this with a chain check of your own. Parsing and
// trusting are separated so a caller can inspect evidence it has not decided
// to trust yet.
//
// A certificate carrying none of the extensions is not an error: it returns an
// Attestation whose HasAttestationExtensions reports false.
func ParseAttestation(cert *x509.Certificate) (*Attestation, error) {
	if cert == nil {
		return nil, &VerifyError{Reason: "certificate is nil"}
	}

	att := &Attestation{}
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(OIDFirmwareVersion):
			att.setFirmware(ext.Value)
		case ext.Id.Equal(OIDSerialNumber):
			att.setSerial(ext.Value)
		case ext.Id.Equal(OIDPINTouchPolicy):
			att.setPolicies(ext.Value)
		case ext.Id.Equal(OIDFormFactor):
			att.setFormFactor(ext.Value)
		}
	}
	return att, nil
}

// setFirmware decodes the three raw version bytes.
//
// The value is the bytes themselves, not an inner ASN.1 object: pkix.Extension
// already carries the contents of extnValue's OCTET STRING. A value of any
// other length is not reinterpreted — a 5-byte value that happens to look like
// an OCTET STRING wrapping three bytes is reported unparseable rather than
// unwrapped, because guessing at the framing is how a parser reports a
// confident wrong answer.
func (a *Attestation) setFirmware(value []byte) {
	if len(value) != 3 {
		a.markUnparseable(OIDFirmwareVersion)
		return
	}
	a.FirmwareVersion = &FirmwareVersion{Major: value[0], Minor: value[1], Patch: value[2]}
}

// setSerial decodes the serial, which is a DER INTEGER rather than raw bytes.
func (a *Attestation) setSerial(value []byte) {
	var serial *big.Int
	rest, err := asn1.Unmarshal(value, &serial)
	if err != nil || len(rest) != 0 || serial == nil || serial.Sign() < 0 || !serial.IsUint64() {
		a.markUnparseable(OIDSerialNumber)
		return
	}
	n := serial.Uint64()
	a.SerialNumber = &n
}

// setPolicies decodes the two policy bytes, PIN first and touch second.
//
// An unrecognised policy VALUE is still returned: the extension decoded, and a
// caller comparing against a known policy will not match it. That is different
// from a value that does not decode, which is what unparseable is for.
func (a *Attestation) setPolicies(value []byte) {
	if len(value) != 2 {
		a.markUnparseable(OIDPINTouchPolicy)
		return
	}
	pin := PINPolicy(value[0])
	touch := TouchPolicy(value[1])
	a.PINPolicy = &pin
	a.TouchPolicy = &touch
}

// setFormFactor decodes the single form-factor byte.
func (a *Attestation) setFormFactor(value []byte) {
	if len(value) != 1 {
		a.markUnparseable(OIDFormFactor)
		return
	}
	ff := FormFactor(value[0])
	a.FormFactor = &ff
}

// markUnparseable records an OID that was present but did not decode.
func (a *Attestation) markUnparseable(oid asn1.ObjectIdentifier) {
	a.Unparseable = append(a.Unparseable, oid)
}

// AttestationVerifyOptions configures VerifyAttestation.
type AttestationVerifyOptions struct {
	// TrustedRoots anchors the attestation chain. It is supplied by the
	// caller and this package ships none: which vendor root a deployment
	// trusts is a deployment's decision, not a library's. A nil pool is an
	// error rather than a pass — an unanchored attestation is evidence of
	// nothing.
	TrustedRoots *x509.CertPool

	// Intermediates are additional certificates for path building. The
	// attestation certificate presented by the device is normally the one
	// intermediate needed.
	Intermediates *x509.CertPool

	// CurrentTime is the instant the chain is validated against. The zero
	// value defers to crypto/x509, which uses the current time, so leaving it
	// unset keeps expiry enforcement on the real clock.
	CurrentTime time.Time
}

// VerifyAttestation checks that a PIV slot attestation chains to a trusted
// root and returns what the leaf says about the device.
//
// chain is leaf-first: the slot attestation certificate, then the device
// attestation certificate (slot f9), and any further intermediates. Roots come
// from opts.
//
// A parse that yields no usable field is NOT an error here — the chain may be
// perfectly good while the device reports nothing this build can read, and the
// returned Attestation says which. Callers enforcing a policy must check the
// field they care about rather than treating a nil error as a satisfied
// policy.
func VerifyAttestation(chain []*x509.Certificate, opts *AttestationVerifyOptions) (*Attestation, error) {
	if len(chain) == 0 {
		return nil, &VerifyError{Reason: "attestation chain is empty"}
	}
	if opts == nil || opts.TrustedRoots == nil {
		return nil, &VerifyError{Reason: "no trusted roots supplied for attestation verification"}
	}

	leaf := chain[0]
	if leaf == nil {
		return nil, &VerifyError{Reason: "attestation leaf is nil"}
	}

	intermediates := opts.Intermediates
	if intermediates == nil {
		intermediates = x509.NewCertPool()
	} else {
		intermediates = intermediates.Clone()
	}
	for _, cert := range chain[1:] {
		if cert != nil {
			intermediates.AddCert(cert)
		}
	}

	// Attestation certificates are not client certificates, so the ClientAuth
	// requirement VerifyChain applies is wrong for them. KeyUsages is left
	// empty, which crypto/x509 reads as ExtKeyUsageAny.
	verifyOpts := x509.VerifyOptions{
		Roots:         opts.TrustedRoots,
		Intermediates: intermediates,
		CurrentTime:   opts.CurrentTime,
	}
	if _, err := leaf.Verify(verifyOpts); err != nil {
		return nil, &VerifyChainError{Cause: err}
	}

	return ParseAttestation(leaf)
}
