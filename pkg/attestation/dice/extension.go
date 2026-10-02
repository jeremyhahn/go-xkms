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

// Package dice parses, encodes and verifies the TCG DICE certificate
// extensions that carry DICE-based device identity with a hardware root of
// trust.
//
// A DICE device derives its identity from a Unique Device Secret and a
// measurement of the firmware it is about to run, and presents that identity as
// an X.509 chain. Three extensions carry the evidence:
//
//   - tcg-dice-TcbInfo (2.23.133.5.4.1) -- the DiceTcbInfo structure, which
//     says what the issuing DICE layer measured about the layer the
//     certificate's subject key belongs to.
//   - tcg-dice-Ueid (2.23.133.5.4.4) -- the TcgUeid structure, which carries
//     the device's unique identifier.
//   - tcg-dice-UCCS-evidence (2.23.133.5.4.6) -- the UccsEvidence structure,
//     whose octet string is an Unprotected CWT Claims Set carrying the EAT
//     claims the device asserts, including the verifier's nonce.
//
// Freshness in this package is always a nonce the verifier issued, read from
// the eat_nonce claim of the UCCS extension. A DICE device has no clock, so
// nothing here reads a device-supplied time or compares one against the
// host's.
//
// See: TCG DICE Attestation Architecture, Version 1.00 Revision 0.23, sections
// 6.1.1 through 6.1.4, and TCG DICE Certificate Profiles, Version 1.0
// Revision 0.01, section 5.1.5.
package dice

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strconv"
	"unicode/utf8"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The DICE OID arc.
//
//	tcg      OBJECT IDENTIFIER ::= {2 23 133}
//	tcg-dice OBJECT IDENTIFIER ::= {tcg platformClass(5) 4}
//
// These are the canonical definitions for the portfolio. pkg/ca and
// pkg/certstore restate them as literals to match the flat OID registries
// already in those packages; TestDiceOIDsMatchAttestationPackage in pkg/ca
// pins the two sets together so they cannot drift apart.
var (
	// OIDArc is tcg-dice (2.23.133.5.4), the arc every identifier below
	// descends from.
	OIDArc = asn1.ObjectIdentifier{2, 23, 133, 5, 4}

	// OIDTcbInfo is tcg-dice-TcbInfo (2.23.133.5.4.1).
	OIDTcbInfo = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

	// OIDEndorsementManifest is tcg-dice-endorsement-manifest (2.23.133.5.4.2).
	OIDEndorsementManifest = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 2}

	// OIDEndorsementManifestURI is tcg-dice-endorsement-manifest-uri
	// (2.23.133.5.4.3).
	OIDEndorsementManifestURI = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 3}

	// OIDUeid is tcg-dice-Ueid (2.23.133.5.4.4).
	OIDUeid = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 4}

	// OIDMultiTcbInfo is tcg-dice-MultiTcbInfo (2.23.133.5.4.5), a SEQUENCE of
	// DiceTcbInfo structures.
	OIDMultiTcbInfo = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 5}

	// OIDUccsEvidence is tcg-dice-UCCS-evidence (2.23.133.5.4.6).
	OIDUccsEvidence = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 6}

	// OIDManifestEvidence is tcg-dice-manifest-evidence (2.23.133.5.4.7).
	OIDManifestEvidence = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 7}
)

// The DICE key purpose arc, tcg-dice-kp (2.23.133.5.4.100).
//
// DICE Certificate Profiles section 5.1.5 defines these as policy OIDs
// authorising what a certified key may be used for. crypto/x509 has no
// ExtKeyUsage constant for any of them, so a profile that stamps them carries
// them in x509.Certificate.UnknownExtKeyUsage.
var (
	// OIDKpArc is tcg-dice-kp (2.23.133.5.4.100).
	OIDKpArc = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100}

	// OIDKpIdentityInit is tcg-dice-kp-identityInit (2.23.133.5.4.100.6): the
	// key authenticates an initial device identity and was bound to the device
	// during manufacturing.
	OIDKpIdentityInit = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 6}

	// OIDKpIdentityLoc is tcg-dice-kp-identityLoc (2.23.133.5.4.100.7): the key
	// authenticates a local device identity issued after manufacturing.
	OIDKpIdentityLoc = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 7}

	// OIDKpAttestInit is tcg-dice-kp-attestInit (2.23.133.5.4.100.8): the key
	// signs evidence describing the device and was bound during manufacturing.
	OIDKpAttestInit = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 8}

	// OIDKpAttestLoc is tcg-dice-kp-attestLoc (2.23.133.5.4.100.9): the key
	// signs evidence describing the device and was bound locally.
	OIDKpAttestLoc = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 9}

	// OIDKpAssertInit is tcg-dice-kp-assertInit (2.23.133.5.4.100.10): the key
	// asserts reference measurements and was bound during manufacturing.
	OIDKpAssertInit = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 10}

	// OIDKpAssertLoc is tcg-dice-kp-assertLoc (2.23.133.5.4.100.11): the key
	// asserts reference measurements and was bound locally.
	OIDKpAssertLoc = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 11}

	// OIDKpECA is tcg-dice-kp-eca (2.23.133.5.4.100.12): the key belongs to an
	// embedded CA and may certify further keys resident on the same device.
	OIDKpECA = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 100, 12}
)

// Context-specific tag numbers of the DiceTcbInfo fields, in the order the
// SEQUENCE declares them.
const (
	tagVendor     = 0
	tagModel      = 1
	tagVersion    = 2
	tagSVN        = 3
	tagLayer      = 4
	tagIndex      = 5
	tagFWIDs      = 6
	tagFlags      = 7
	tagVendorInfo = 8
	tagType       = 9
)

// Bit positions of the operational states inside the flags BIT STRING.
const (
	bitNotConfigured = 0
	bitNotSecure     = 1
	bitRecovery      = 2
	bitDebug         = 3

	// operationalFlagCount is how many bits the BIT STRING may carry. A
	// longer one declares a state this verifier cannot read.
	operationalFlagCount = 4
)

// TcbInfo is the decoded tcg-dice-TcbInfo extension value: what the issuing
// DICE layer measured about the target TCB the subject key belongs to.
//
//	DiceTcbInfo ::= SEQUENCE {
//	    vendor     [0] IMPLICIT UTF8String       OPTIONAL,
//	    model      [1] IMPLICIT UTF8String       OPTIONAL,
//	    version    [2] IMPLICIT UTF8String       OPTIONAL,
//	    svn        [3] IMPLICIT INTEGER          OPTIONAL,
//	    layer      [4] IMPLICIT INTEGER          OPTIONAL,
//	    index      [5] IMPLICIT INTEGER          OPTIONAL,
//	    fwids      [6] IMPLICIT FWIDLIST         OPTIONAL,
//	    flags      [7] IMPLICIT OperationalFlags OPTIONAL,
//	    vendorInfo [8] IMPLICIT OCTET STRING     OPTIONAL,
//	    type       [9] IMPLICIT OCTET STRING     OPTIONAL
//	}
//
// The three integers and the flags are pointers because every one of them has
// a meaningful zero. Layer 0 is the DICE core, index 0 is the first measured
// asset in a layer, and svn 0 is a first release; a flags field present with
// every bit clear is a positive statement that none of the four operational
// states is active, which is not the same as a device that said nothing. A
// plain int cannot tell "zero" from "absent", and encoding/asn1 makes the
// confusion concrete: it drops an `optional` field whose value is the zero
// value, so a struct-tag encoding of this structure silently omits layer 0.
type TcbInfo struct {
	// Vendor is the entity that created the target TCB. Empty means absent.
	Vendor string

	// Model is the product name of the target TCB. Empty means absent.
	Model string

	// Version is the revision string of the target TCB. Empty means absent.
	Version string

	// SVN is the security version number of the target TCB.
	SVN *int

	// Layer is the DICE layer this measurement was taken at.
	Layer *int

	// Index enumerates measured assets within one target TCB and layer.
	Index *int

	// FWIDs are the measurements of the target TCB. The ASN.1 type is
	// FWIDLIST, a SEQUENCE SIZE (1..MAX) OF FWID, so a non-nil value always
	// holds at least one entry.
	FWIDs []FWID

	// Flags are the operational states the issuing layer declares the target
	// TCB to be in. Nil means the field was absent, which the specification
	// defines as all four states inactive.
	Flags *OperationalFlags

	// VendorInfo is vendor-defined device state, section 6.1.1.1(e).
	//
	// It does NOT carry the verifier's challenge. The nonce travels in the
	// eat_nonce claim of the tcg-dice-UCCS-evidence extension, which is the
	// specification's own mechanism and is where another DICE verifier looks
	// for it; see Challenge.
	VendorInfo []byte

	// Type is a machine-readable description of what was measured.
	Type []byte
}

// FWID is one firmware measurement of the target TCB.
//
//	FWID ::= SEQUENCE {
//	    hashAlg OBJECT IDENTIFIER,
//	    digest  OCTET STRING
//	}
type FWID struct {
	// HashAlg identifies the hash function that produced Digest.
	HashAlg asn1.ObjectIdentifier

	// Digest is the measurement of firmware, initialisation values or other
	// settings of the target TCB.
	Digest []byte
}

// OperationalFlags are the four simultaneous operational states a DICE layer
// can declare about the target TCB.
//
//	OperationalFlags ::= BIT STRING {
//	    notConfigured (0),
//	    notSecure     (1),
//	    recovery      (2),
//	    debug         (3)
//	}
//
// A set bit means the state is active. Each of the four means the target TCB
// is not in its trustworthy operating state, so a verifier treats them as
// claims to act on rather than metadata.
type OperationalFlags struct {
	// NotConfigured: the target TCB requires further information to operate.
	NotConfigured bool

	// NotSecure: the target TCB is not secure.
	//
	// The AVR device identity profile sets this whenever the device reports a
	// software-only tier, because a root of trust that is not in hardware is
	// exactly the claim this bit exists to make.
	NotSecure bool

	// Recovery: the target TCB is recovering from a failure.
	Recovery bool

	// Debug: the target TCB can be debugged.
	Debug bool
}

// Ueid is the decoded tcg-dice-Ueid extension value, the ASN.1 type TcgUeid.
//
//	TcgUeid ::= SEQUENCE {
//	    ueid OCTET STRING
//	}
type Ueid struct {
	// Value is the device's unique identifier.
	Value []byte
}

// Any reports whether any operational state is active.
func (f OperationalFlags) Any() bool {
	return f.NotConfigured || f.NotSecure || f.Recovery || f.Debug
}

// String renders the active operational states for an operator reading a
// refusal, or "none" when the target TCB declared itself in none of them.
func (f OperationalFlags) String() string {
	active := make([]string, 0, operationalFlagCount)
	for _, state := range []struct {
		name string
		on   bool
	}{
		{"notConfigured", f.NotConfigured},
		{"notSecure", f.NotSecure},
		{"recovery", f.Recovery},
		{"debug", f.Debug},
	} {
		if state.on {
			active = append(active, state.name)
		}
	}
	if len(active) == 0 {
		return "none"
	}

	var sb bytes.Buffer
	for i, name := range active {
		if i > 0 {
			sb.WriteByte('|')
		}
		sb.WriteString(name)
	}
	return sb.String()
}

// BitString encodes the flags as the DER BIT STRING the extension carries.
//
// DER requires the minimal encoding of a named bit list, so trailing clear bits
// are removed and an all-clear value encodes as a zero-length BIT STRING. That
// is what makes re-encoding a parsed structure reproduce the bytes it came
// from.
func (f OperationalFlags) BitString() asn1.BitString {
	var value byte
	for _, state := range []struct {
		bit int
		on  bool
	}{
		{bitNotConfigured, f.NotConfigured},
		{bitNotSecure, f.NotSecure},
		{bitRecovery, f.Recovery},
		{bitDebug, f.Debug},
	} {
		if state.on {
			value |= 0x80 >> state.bit
		}
	}

	length := 0
	for bit := 0; bit < operationalFlagCount; bit++ {
		if value&(0x80>>bit) != 0 {
			length = bit + 1
		}
	}
	if length == 0 {
		return asn1.BitString{}
	}
	return asn1.BitString{Bytes: []byte{value}, BitLength: length}
}

// operationalFlagsFromBitString decodes a flags BIT STRING.
//
// A bit beyond the four named states is refused rather than ignored: it is the
// device declaring an operational state, and a verifier that drops it reports
// a device as sound on the strength of a claim it did not read.
func operationalFlagsFromBitString(bits asn1.BitString) (*OperationalFlags, error) {
	if bits.BitLength > operationalFlagCount {
		return nil, &errs.Detail{
			Err:    ErrUnknownOperationalFlag,
			Detail: "flags carries " + strconv.Itoa(bits.BitLength) + " bits, and only 4 operational states are defined",
		}
	}
	return &OperationalFlags{
		NotConfigured: bits.At(bitNotConfigured) == 1,
		NotSecure:     bits.At(bitNotSecure) == 1,
		Recovery:      bits.At(bitRecovery) == 1,
		Debug:         bits.At(bitDebug) == 1,
	}, nil
}

// MarshalTcbInfo encodes a DiceTcbInfo extension value.
//
// The fields are encoded one at a time and concatenated, then wrapped in a
// SEQUENCE, rather than marshalled from a struct with `optional,tag:N` tags.
// encoding/asn1 omits any optional field holding its type's zero value, which
// for this structure means layer 0, index 0 and svn 0 -- all meaningful --
// vanish from the encoding. Writing the fields out individually is what keeps
// "absent" and "zero" distinguishable on the wire.
func MarshalTcbInfo(info *TcbInfo) ([]byte, error) {
	if info == nil {
		return nil, ErrNilTcbInfo
	}

	var body bytes.Buffer

	for _, field := range []struct {
		tag   int
		value string
	}{
		{tagVendor, info.Vendor},
		{tagModel, info.Model},
		{tagVersion, info.Version},
	} {
		if field.value == "" {
			continue
		}
		der, err := asn1.MarshalWithParams(field.value, implicitParams(field.tag)+",utf8")
		if err != nil {
			return nil, &errs.Joined{Lead: ErrMalformedTcbInfo, Detail: "could not encode a string field", Cause: err}
		}
		body.Write(der)
	}

	for _, field := range []struct {
		tag   int
		value *int
	}{
		{tagSVN, info.SVN},
		{tagLayer, info.Layer},
		{tagIndex, info.Index},
	} {
		if field.value == nil {
			continue
		}
		if *field.value < 0 {
			return nil, ErrNegativeTcbInfoValue
		}
		der, err := asn1.MarshalWithParams(*field.value, implicitParams(field.tag))
		if err != nil {
			return nil, &errs.Joined{Lead: ErrMalformedTcbInfo, Detail: "could not encode an integer field", Cause: err}
		}
		body.Write(der)
	}

	if len(info.FWIDs) > 0 {
		for _, fwid := range info.FWIDs {
			if err := validateFWID(fwid); err != nil {
				return nil, err
			}
		}
		der, err := asn1.MarshalWithParams(info.FWIDs, implicitParams(tagFWIDs))
		if err != nil {
			return nil, &errs.Joined{Lead: ErrMalformedTcbInfo, Detail: "could not encode fwids", Cause: err}
		}
		body.Write(der)
	}

	if info.Flags != nil {
		der, err := asn1.MarshalWithParams(info.Flags.BitString(), implicitParams(tagFlags))
		if err != nil {
			return nil, &errs.Joined{Lead: ErrMalformedTcbInfo, Detail: "could not encode flags", Cause: err}
		}
		body.Write(der)
	}

	for _, field := range []struct {
		tag   int
		value []byte
	}{
		{tagVendorInfo, info.VendorInfo},
		{tagType, info.Type},
	} {
		if len(field.value) == 0 {
			continue
		}
		der, err := asn1.MarshalWithParams(field.value, implicitParams(field.tag))
		if err != nil {
			return nil, &errs.Joined{Lead: ErrMalformedTcbInfo, Detail: "could not encode an octet string field", Cause: err}
		}
		body.Write(der)
	}

	return marshalSequence(body.Bytes(), ErrMalformedTcbInfo)
}

// ParseTcbInfo decodes a DiceTcbInfo extension value.
//
// The SEQUENCE is walked element by element rather than unmarshalled into a
// tagged struct, which is the same choice MarshalTcbInfo makes and for the same
// reason: it is the only way to see that a field was present at all.
func ParseTcbInfo(der []byte) (*TcbInfo, error) {
	elements, err := sequenceElements(der, ErrMalformedTcbInfo)
	if err != nil {
		return nil, err
	}

	info := &TcbInfo{}
	previousTag := -1
	for _, element := range elements {
		if element.Class != asn1.ClassContextSpecific {
			return nil, &errs.Detail{
				Err:    ErrMalformedTcbInfo,
				Detail: "field is not context-specific, so it names no DiceTcbInfo member",
			}
		}
		if element.Tag <= previousTag {
			return nil, &errs.Detail{
				Err:    ErrTcbInfoFieldOrder,
				Detail: "field [" + strconv.Itoa(element.Tag) + "] does not follow [" + strconv.Itoa(previousTag) + "]",
			}
		}
		previousTag = element.Tag

		decode, known := tcbInfoDecoders[element.Tag]
		if !known {
			return nil, &errs.Detail{
				Err:    ErrUnknownTcbInfoField,
				Detail: "field [" + strconv.Itoa(element.Tag) + "] is not one of the ten DiceTcbInfo members",
			}
		}
		if err := decode(info, element); err != nil {
			return nil, err
		}
	}

	return info, nil
}

// tcbInfoDecoders dispatches a DiceTcbInfo field to its decoder by context tag.
var tcbInfoDecoders = map[int]func(*TcbInfo, asn1.RawValue) error{
	tagVendor:     func(i *TcbInfo, e asn1.RawValue) error { return decodeString(e, &i.Vendor) },
	tagModel:      func(i *TcbInfo, e asn1.RawValue) error { return decodeString(e, &i.Model) },
	tagVersion:    func(i *TcbInfo, e asn1.RawValue) error { return decodeString(e, &i.Version) },
	tagSVN:        func(i *TcbInfo, e asn1.RawValue) error { return decodeInt(e, &i.SVN) },
	tagLayer:      func(i *TcbInfo, e asn1.RawValue) error { return decodeInt(e, &i.Layer) },
	tagIndex:      func(i *TcbInfo, e asn1.RawValue) error { return decodeInt(e, &i.Index) },
	tagFWIDs:      decodeFWIDs,
	tagFlags:      decodeFlags,
	tagVendorInfo: func(i *TcbInfo, e asn1.RawValue) error { return decodeOctets(e, &i.VendorInfo) },
	tagType:       func(i *TcbInfo, e asn1.RawValue) error { return decodeOctets(e, &i.Type) },
}

// decodeString reads an implicitly tagged UTF8String.
//
// The tag is IMPLICIT, so the element's content bytes are the string's own
// content and there is no inner header to strip.
func decodeString(element asn1.RawValue, out *string) error {
	if element.IsCompound {
		return &errs.Detail{Err: ErrMalformedTcbInfo, Detail: "a UTF8String field is encoded as constructed"}
	}
	if !utf8.Valid(element.Bytes) {
		return &errs.Detail{Err: ErrMalformedTcbInfo, Detail: "a UTF8String field is not valid UTF-8"}
	}
	*out = string(element.Bytes)
	return nil
}

// decodeInt reads an implicitly tagged INTEGER by restoring the universal tag
// the IMPLICIT encoding replaced and handing the result to encoding/asn1, which
// enforces the minimal-length rule DER requires of an integer.
func decodeInt(element asn1.RawValue, out **int) error {
	var value int
	if err := decodeImplicit(element, asn1.TagInteger, false, &value); err != nil {
		return err
	}
	if value < 0 {
		return ErrNegativeTcbInfoValue
	}
	*out = &value
	return nil
}

// decodeOctets reads an implicitly tagged OCTET STRING.
func decodeOctets(element asn1.RawValue, out *[]byte) error {
	if element.IsCompound {
		return &errs.Detail{Err: ErrMalformedTcbInfo, Detail: "an OCTET STRING field is encoded as constructed"}
	}
	*out = bytes.Clone(element.Bytes)
	return nil
}

// decodeFWIDs reads the implicitly tagged FWIDLIST.
func decodeFWIDs(info *TcbInfo, element asn1.RawValue) error {
	var fwids []FWID
	if err := decodeImplicit(element, asn1.TagSequence, true, &fwids); err != nil {
		return err
	}
	// FWIDLIST is SEQUENCE SIZE (1..MAX) OF FWID: an empty list is a fwids
	// field that measures nothing, which the type does not permit.
	if len(fwids) == 0 {
		return &errs.Detail{Err: ErrMalformedFWID, Detail: "fwids is present but empty"}
	}
	for _, fwid := range fwids {
		if err := validateFWID(fwid); err != nil {
			return err
		}
	}
	info.FWIDs = fwids
	return nil
}

// decodeFlags reads the implicitly tagged OperationalFlags BIT STRING.
func decodeFlags(info *TcbInfo, element asn1.RawValue) error {
	var bits asn1.BitString
	if err := decodeImplicit(element, asn1.TagBitString, false, &bits); err != nil {
		return err
	}
	flags, err := operationalFlagsFromBitString(bits)
	if err != nil {
		return err
	}
	info.Flags = flags
	return nil
}

// validateFWID rejects an FWID that names no measurement.
func validateFWID(fwid FWID) error {
	if len(fwid.HashAlg) == 0 {
		return &errs.Detail{Err: ErrMalformedFWID, Detail: "hashAlg is empty"}
	}
	if len(fwid.Digest) == 0 {
		return &errs.Detail{Err: ErrMalformedFWID, Detail: "digest is empty"}
	}
	return nil
}

// MarshalUeid encodes a TcgUeid extension value.
func MarshalUeid(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, ErrEmptyUeid
	}
	der, err := asn1.Marshal(Ueid{Value: value})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedUeid, Detail: "could not encode the ueid", Cause: err}
	}
	return der, nil
}

// ParseUeid decodes a TcgUeid extension value.
func ParseUeid(der []byte) (*Ueid, error) {
	var ueid Ueid
	rest, err := asn1.Unmarshal(der, &ueid)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedUeid, Detail: "could not decode the TcgUeid sequence", Cause: err}
	}
	if len(rest) > 0 {
		return nil, &errs.Detail{Err: ErrMalformedUeid, Detail: "trailing data after the TcgUeid sequence"}
	}
	if len(ueid.Value) == 0 {
		return nil, ErrEmptyUeid
	}
	return &ueid, nil
}

// CreateTcbInfoExtension builds the tcg-dice-TcbInfo certificate extension.
//
// The extension is marked critical, as DICE Attestation Architecture section
// 6.1.1 says it SHOULD be: a relying party that cannot read what the device
// measured must not treat the certificate as an attestation of anything.
func CreateTcbInfoExtension(info *TcbInfo) (pkix.Extension, error) {
	value, err := MarshalTcbInfo(info)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: OIDTcbInfo, Critical: true, Value: value}, nil
}

// CreateUeidExtension builds the tcg-dice-Ueid certificate extension.
//
// It is not marked critical. The UEID names the device; it makes no claim a
// relying party must understand before trusting the certificate, and a
// critical extension no general-purpose client recognises would make the
// certificate unusable for ordinary TLS.
func CreateUeidExtension(value []byte) (pkix.Extension, error) {
	der, err := MarshalUeid(value)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: OIDUeid, Critical: false, Value: der}, nil
}

// TcbInfoFromCertificate extracts and decodes the tcg-dice-TcbInfo extension.
// It returns ErrTcbInfoNotFound when the certificate carries none.
func TcbInfoFromCertificate(cert *x509.Certificate) (*TcbInfo, error) {
	value, err := extensionValue(cert, OIDTcbInfo, ErrTcbInfoNotFound)
	if err != nil {
		return nil, err
	}
	return ParseTcbInfo(value)
}

// UeidFromCertificate extracts and decodes the tcg-dice-Ueid extension.
// It returns ErrUeidNotFound when the certificate carries none.
func UeidFromCertificate(cert *x509.Certificate) (*Ueid, error) {
	value, err := extensionValue(cert, OIDUeid, ErrUeidNotFound)
	if err != nil {
		return nil, err
	}
	return ParseUeid(value)
}

// DeviceUeid returns the device's identifier from wherever the certificate
// states it: the tcg-dice-Ueid extension, or the ueid claim (ClaimUeid) of the
// tcg-dice-UCCS-evidence extension. Both are DICE Attestation Architecture
// placements of the same datum, and a device carries the one it can afford.
//
// A certificate that states it in both places must state the same value. Two
// answers would make the identity depend on which a reader happened to
// consult, so a disagreement is ErrUeidConflict and not a choice. A certificate
// that states it in neither returns ErrUeidNotFound.
func DeviceUeid(cert *x509.Certificate) ([]byte, error) {
	fromExtension, err := UeidFromCertificate(cert)
	if err != nil && !errors.Is(err, ErrUeidNotFound) {
		return nil, err
	}

	claims, err := UccsFromCertificate(cert)
	if err != nil && !errors.Is(err, ErrUccsEvidenceNotFound) {
		return nil, err
	}
	var fromClaim []byte
	if claims != nil {
		fromClaim, err = claims.Ueid()
		if err != nil && !errors.Is(err, ErrUeidNotFound) {
			return nil, err
		}
	}

	switch {
	case fromExtension != nil && fromClaim != nil:
		if !bytes.Equal(fromExtension.Value, fromClaim) {
			return nil, &errs.Detail{
				Err:    ErrUeidConflict,
				Detail: "extension " + hex.EncodeToString(fromExtension.Value) + ", claim " + hex.EncodeToString(fromClaim),
			}
		}
		return fromClaim, nil
	case fromExtension != nil:
		return fromExtension.Value, nil
	case fromClaim != nil:
		return fromClaim, nil
	default:
		return nil, ErrUeidNotFound
	}
}

// diceEvidenceOIDs are the extensions whose presence marks a certificate as
// device-resident rather than part of the issuing authority's chain, and which
// this package is able to decode.
//
// The list is one place rather than three because it answers one question in
// three callers: HasExtensions uses it to apply the hardware key constraint,
// withDICEExtensionsHandled to clear the critical-extension entries
// crypto/x509 would otherwise refuse the chain over, and both are wrong the
// moment they disagree about what DICE evidence is.
var diceEvidenceOIDs = []asn1.ObjectIdentifier{OIDTcbInfo, OIDUeid, OIDUccsEvidence}

// isDICEEvidence reports whether the OID names an evidence extension this
// package decodes.
func isDICEEvidence(oid asn1.ObjectIdentifier) bool {
	for _, evidence := range diceEvidenceOIDs {
		if oid.Equal(evidence) {
			return true
		}
	}
	return false
}

// HasExtensions reports whether the certificate carries any DICE evidence
// extension, which is what marks it as device-resident rather than part of the
// issuing authority's chain.
func HasExtensions(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, extension := range cert.Extensions {
		if isDICEEvidence(extension.Id) {
			return true
		}
	}
	return false
}

// Challenge returns the verifier nonce the device echoed into its
// tcg-dice-UCCS-evidence extension.
//
// The nonce is the eat_nonce claim (key 10) of the CWT claims set that
// extension carries --
// the specification's own mechanism, section 6.1.4, rather than a repurposed
// field. A timestamp is not an alternative because a DICE device has no clock:
// freshness here is the verifier's nonce or it is nothing.
//
// Every failure is reported and none of them falls back to
// DiceTcbInfo.vendorInfo. A leaf with no UCCS extension returns
// ErrUccsEvidenceNotFound and a claims set with no nonce returns
// ErrNonceClaimMissing; the freshness gate refuses both, but an operator needs
// to know which happened, and a device that put its nonce somewhere other than
// where the specification says must not verify on that account.
func Challenge(leaf *x509.Certificate) ([]byte, error) {
	claims, err := UccsFromCertificate(leaf)
	if err != nil {
		return nil, err
	}
	return claims.Nonce, nil
}

// extensionValue returns the raw value of one extension.
func extensionValue(cert *x509.Certificate, oid asn1.ObjectIdentifier, absent error) ([]byte, error) {
	if cert == nil {
		return nil, ErrNilCertificate
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(oid) {
			return extension.Value, nil
		}
	}
	return nil, absent
}

// implicitParams renders the encoding/asn1 field parameters that produce an
// IMPLICIT context-specific tag.
func implicitParams(tag int) string {
	return "tag:" + strconv.Itoa(tag)
}

// marshalSequence wraps already-encoded elements in a universal SEQUENCE.
func marshalSequence(elements []byte, lead error) ([]byte, error) {
	der, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      elements,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: lead, Detail: "could not wrap the fields in a sequence", Cause: err}
	}
	return der, nil
}

// sequenceElements splits a DER SEQUENCE into its elements, refusing anything
// that is not exactly one well-formed SEQUENCE.
func sequenceElements(der []byte, lead error) ([]asn1.RawValue, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, &errs.Joined{Lead: lead, Detail: "could not decode the outer sequence", Cause: err}
	}
	if len(rest) > 0 {
		return nil, &errs.Detail{Err: lead, Detail: "trailing data after the outer sequence"}
	}
	if outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, &errs.Detail{Err: lead, Detail: "the extension value is not a sequence"}
	}

	var elements []asn1.RawValue
	remaining := outer.Bytes
	for len(remaining) > 0 {
		var element asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &element)
		if err != nil {
			return nil, &errs.Joined{Lead: lead, Detail: "could not decode a field", Cause: err}
		}
		elements = append(elements, element)
	}
	return elements, nil
}

// decodeImplicit decodes the content of an IMPLICIT-tagged element.
//
// An IMPLICIT tag replaces the universal tag of the value it wraps, so the
// content bytes alone are not something encoding/asn1 can decode. Restoring the
// universal header and decoding the result is what lets the standard library do
// the work -- including the DER checks it makes on integers and bit strings,
// which a hand-rolled reader of the content bytes would have to reimplement and
// would get wrong.
func decodeImplicit(element asn1.RawValue, universalTag int, compound bool, out any) error {
	if element.IsCompound != compound {
		return &errs.Detail{
			Err:    ErrMalformedTcbInfo,
			Detail: "field [" + strconv.Itoa(element.Tag) + "] has the wrong constructed bit for its type",
		}
	}

	restored, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        universalTag,
		IsCompound: compound,
		Bytes:      element.Bytes,
	})
	if err != nil {
		return &errs.Joined{Lead: ErrMalformedTcbInfo, Detail: "could not restore the universal tag of a field", Cause: err}
	}

	rest, err := asn1.Unmarshal(restored, out)
	if err != nil {
		return &errs.Joined{
			Lead:   ErrMalformedTcbInfo,
			Detail: "field [" + strconv.Itoa(element.Tag) + "] could not be decoded",
			Cause:  err,
		}
	}
	if len(rest) > 0 {
		return &errs.Detail{
			Err:    ErrMalformedTcbInfo,
			Detail: "trailing data inside field [" + strconv.Itoa(element.Tag) + "]",
		}
	}
	return nil
}
