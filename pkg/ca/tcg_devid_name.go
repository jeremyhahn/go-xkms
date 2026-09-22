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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TCG DevID subjectAltName construction.
//
// TCG TPM 2.0 Keys for Device Identity and Attestation v1.00 r12 §8.1 requires
// two otherNames inside the non-critical subjectAltName of every IDevID and IAK
// certificate: an RFC 4108 hardwareModuleName describing the TPM, and an RFC
// 4043 permanentIdentifier correlating certificates issued to the same TPM.
// Both are derived from the endorsement key, so both are computed here from the
// EK certificate the TCG-CSR-IDEVID carries.

// ekPubkeyPermIDPrefix is the UTF-8 string prefixed to a bare EK public key
// before digesting it. TCG DevID v1 r12 §8.1 (spec text line 2955): "the
// identifierValue is a digest of a concatenation of the UTF8 string 'EkPubkey'
// (terminating NULL not included) with the binary EK public key."
const ekPubkeyPermIDPrefix = "EkPubkey"

// oidSubjectDirectoryAttributes is the subjectDirectoryAttributes extension,
// RFC 5280 section 4.2.1.8, one of the two places a TCG EK certificate may
// record the TPM manufacturer.
var oidSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}

// TCGDeviceIdentity is the pair of subjectAltName otherNames a DevID
// certificate must carry, already reduced to their textual forms so a test can
// pin them without decoding ASN.1.
type TCGDeviceIdentity struct {
	// HardwareSerialNumber is the RFC 4108 hwSerialNum.
	HardwareSerialNumber string

	// PermanentIdentifier is the RFC 4043 identifierValue.
	PermanentIdentifier string
}

// OtherNames renders the identity as the two subjectAltName otherNames of TCG
// DevID v1 r12 §8.1, in the order the specification lists them.
func (id TCGDeviceIdentity) OtherNames() ([]OtherName, error) {
	hwName, err := MarshalHardwareModuleName(OIDTCGHwTypeTPM2, []byte(id.HardwareSerialNumber))
	if err != nil {
		return nil, err
	}
	permID, err := MarshalPermanentIdentifier(id.PermanentIdentifier, OIDTCGOnEKPermIdSha256)
	if err != nil {
		return nil, err
	}
	return []OtherName{
		{TypeID: OIDHardwareModuleName, Value: hwName},
		{TypeID: OIDPermanentIdentifier, Value: permID},
	}, nil
}

// TCGDeviceIdentityFromEKCertificate derives both §8.1 names from a TPM's
// endorsement key certificate.
//
// hwSerialNum, per §8.1 (spec text lines 2901-2905): "the hwSerialNum is
// created by concatenating three ASCII values: The TCG TPM Manufacturer code,
// the EK Authority Key Identifier and the EK CertificateSerialNumber. These
// three fields SHALL be separated by a colon (':') character. The three values
// SHALL be listed in the order specified above."
//
// The specification does not say how the authority key identifier — an OCTET
// STRING — and the serial number — an INTEGER — become ASCII. Both are rendered
// here as lowercase hexadecimal with no separators, the serial number from its
// unpadded big-endian magnitude. That choice is pinned by test so it cannot
// drift; a certificate already issued cannot be re-derived under a different
// rendering.
//
// identifierValue, per §8.1 (spec text line 2953): "the identifierValue is a
// digest of the DER form of the TPM EK certificate, which is then converted to
// hexadecimal form using the UTF8 character set." §8.1 (line 2866) fixes the
// digest: "Within the subjectAltName extension, where a digest is required, the
// hash algorithm SHALL be SHA-256."
//
// manufacturerOverride supplies the TCG TPM manufacturer code for an EK
// certificate that does not record one — a certificate this CA issued itself,
// for instance. The code carried by the EK certificate always wins, and when
// neither source has one issuance is refused with ErrTCGEKManufacturerUnknown
// rather than a name that identifies the wrong TPM.
func TCGDeviceIdentityFromEKCertificate(
	ekCert *x509.Certificate,
	manufacturerOverride string,
) (TCGDeviceIdentity, error) {
	if ekCert == nil {
		return TCGDeviceIdentity{}, &errs.Detail{
			Err:    ErrTCGMissingEKCert,
			Detail: "the hardware module name and permanent identifier are derived from the endorsement key certificate",
		}
	}

	manufacturer, err := TCGTPMManufacturer(ekCert)
	if err != nil {
		manufacturer = strings.TrimSpace(manufacturerOverride)
		if manufacturer == "" {
			return TCGDeviceIdentity{}, err
		}
	}

	if len(ekCert.AuthorityKeyId) == 0 {
		return TCGDeviceIdentity{}, &errs.Detail{
			Err:    ErrTCGInvalidEKCert,
			Detail: "the endorsement key certificate has no authority key identifier, which the hardware module name requires",
		}
	}
	if ekCert.SerialNumber == nil || ekCert.SerialNumber.Sign() < 0 {
		return TCGDeviceIdentity{}, &errs.Detail{
			Err:    ErrTCGInvalidEKCert,
			Detail: "the endorsement key certificate has no non-negative serial number",
		}
	}

	digest := sha256.Sum256(ekCert.Raw)

	return TCGDeviceIdentity{
		HardwareSerialNumber: strings.Join([]string{
			manufacturer,
			hex.EncodeToString(ekCert.AuthorityKeyId),
			hex.EncodeToString(ekCert.SerialNumber.Bytes()),
		}, ":"),
		PermanentIdentifier: hex.EncodeToString(digest[:]),
	}, nil
}

// TCGDeviceIdentityFromEKPublicKey derives both §8.1 names for a TPM that has
// no endorsement key certificate.
//
// §8.1 (spec text line 2907): "When the TPM does not have an EK certificate,
// the hwSerialNum is a digest of the EK Certificate public key." §8.1 (line
// 2955) gives the permanent identifier the "EkPubkey" prefix. Both digests are
// SHA-256 over the DER SubjectPublicKeyInfo, the only self-describing encoding
// of a public key an X.509 certificate path has; §8.1 requires SHA-256 and does
// not fix the encoding, so this one is pinned by test.
func TCGDeviceIdentityFromEKPublicKey(ekPubDER []byte) (TCGDeviceIdentity, error) {
	if len(ekPubDER) == 0 {
		return TCGDeviceIdentity{}, &errs.Detail{
			Err:    ErrTCGInvalidPublicKey,
			Detail: "an endorsement key is required to derive the hardware module name",
		}
	}

	hwDigest := sha256.Sum256(ekPubDER)
	permDigest := sha256.Sum256(append([]byte(ekPubkeyPermIDPrefix), ekPubDER...))

	return TCGDeviceIdentity{
		HardwareSerialNumber: hex.EncodeToString(hwDigest[:]),
		PermanentIdentifier:  hex.EncodeToString(permDigest[:]),
	}, nil
}

// TCGTPMManufacturer returns the TCG TPM manufacturer code an endorsement key
// certificate records under tcg-at-tpmManufacturer (2.23.133.2.1).
//
// The TCG EK Credential Profile allows the attribute in three places, and
// manufacturers use all three: the subject distinguished name, the
// subjectDirectoryAttributes extension, and a directoryName inside
// subjectAltName — the last being usual because an EK certificate's subject is
// often empty. All three are searched, in that order.
//
// Returns ErrTCGEKManufacturerUnknown when the certificate records no code.
func TCGTPMManufacturer(ekCert *x509.Certificate) (string, error) {
	if ekCert == nil {
		return "", &errs.Detail{Err: ErrTCGMissingEKCert, Detail: "no certificate to read the manufacturer from"}
	}
	if value := manufacturerFromNames(ekCert.Subject.Names, ekCert.Extensions); value != "" {
		return value, nil
	}
	return "", &errs.Detail{
		Err:    ErrTCGEKManufacturerUnknown,
		Detail: "the endorsement key certificate records no tcg-at-tpmManufacturer (2.23.133.2.1) attribute",
	}
}

// TCGTPMManufacturerFromCSR returns the TCG TPM manufacturer code a
// certificate signing request asks to have recorded, read from the same three
// places TCGTPMManufacturer searches in a certificate. An endorse-01 client
// places it in a subjectAltName directoryName, so the endorsement key
// certificate issued for it carries the code a later DevID enrollment needs.
//
// The value is the requester's claim and is returned as found; callers
// validate it with ValidateTCGTPMManufacturer. Returns
// ErrTCGEKManufacturerUnknown when the request carries no code.
func TCGTPMManufacturerFromCSR(csr *x509.CertificateRequest) (string, error) {
	if csr == nil {
		return "", &errs.Detail{Err: ErrInvalidCSR, Detail: "no certificate request to read the manufacturer from"}
	}
	if value := manufacturerFromNames(csr.Subject.Names, csr.Extensions); value != "" {
		return value, nil
	}
	return "", &errs.Detail{
		Err:    ErrTCGEKManufacturerUnknown,
		Detail: "the certificate request carries no tcg-at-tpmManufacturer (2.23.133.2.1) attribute",
	}
}

// ValidateTCGTPMManufacturer reports whether code is a TCG TPM manufacturer
// code in the form tcg-at-tpmManufacturer carries: "id:" followed by the
// 32-bit TPM_PT_MANUFACTURER value as eight uppercase hexadecimal digits, e.g.
// "id:49465800" for Infineon. This is the form the tpm2 package reports in
// PropertiesFixed.ManufacturerCode. Returns ErrTCGInvalidManufacturerCode.
func ValidateTCGTPMManufacturer(code string) error {
	digits, ok := strings.CutPrefix(code, tcgManufacturerCodePrefix)
	if !ok || len(digits) != tcgManufacturerCodeDigits {
		return &errs.Detail{Err: ErrTCGInvalidManufacturerCode, Detail: fmt.Sprintf("%q", code)}
	}
	for _, digit := range digits {
		if (digit < '0' || digit > '9') && (digit < 'A' || digit > 'F') {
			return &errs.Detail{Err: ErrTCGInvalidManufacturerCode, Detail: fmt.Sprintf("%q", code)}
		}
	}
	return nil
}

// tcgManufacturerCodePrefix and tcgManufacturerCodeDigits describe the
// tcg-at-tpmManufacturer value form: "id:" and eight hexadecimal digits.
const (
	tcgManufacturerCodePrefix = "id:"
	tcgManufacturerCodeDigits = 8
)

// TCGTPMManufacturerSubjectAltName builds a subjectAltName extension carrying
// only tcg-at-tpmManufacturer, in the directoryName the TCG EK Credential
// Profile uses. An endorse-01 client puts it in its certificate request so the
// endorsement key certificate issued for it records the code, which
// TCGTPMManufacturerFromCSR reads back. Returns ErrTCGInvalidManufacturerCode
// for a code not in the tcg-at-tpmManufacturer form.
func TCGTPMManufacturerSubjectAltName(subject pkix.Name, code string) (pkix.Extension, error) {
	if err := ValidateTCGTPMManufacturer(code); err != nil {
		return pkix.Extension{}, err
	}
	return BuildSubjectAltName(subject, nil, nil, nil, nil, nil, []pkix.Name{tpmManufacturerDirectoryName(code)})
}

// tpmManufacturerDirectoryName is the subjectAltName directoryName the TCG EK
// Credential Profile uses to carry tcg-at-tpmManufacturer.
func tpmManufacturerDirectoryName(code string) pkix.Name {
	return pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: OIDTCGAttributeTPMManufacturer, Value: code},
		},
	}
}

// manufacturerFromNames searches a distinguished name, then the
// subjectDirectoryAttributes and subjectAltName extensions, for
// tcg-at-tpmManufacturer, and returns the empty string when none records it.
func manufacturerFromNames(subject []pkix.AttributeTypeAndValue, extensions []pkix.Extension) string {
	if value := attributeValue(subject, OIDTCGAttributeTPMManufacturer); value != "" {
		return value
	}
	for _, ext := range extensions {
		switch {
		case ext.Id.Equal(oidSubjectDirectoryAttributes):
			if value := manufacturerFromDirectoryAttributes(ext.Value); value != "" {
				return value
			}
		case ext.Id.Equal(oidSubjectAltNameExt):
			if value := manufacturerFromSubjectAltName(ext.Value); value != "" {
				return value
			}
		}
	}
	return ""
}

// directoryAttribute is one entry of an RFC 5280 subjectDirectoryAttributes
// extension: SEQUENCE OF Attribute, Attribute ::= SEQUENCE { type, values }.
type directoryAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// manufacturerFromDirectoryAttributes reads tcg-at-tpmManufacturer out of an
// encoded subjectDirectoryAttributes extension. An extension that cannot be
// decoded yields no manufacturer rather than an error: the caller has two more
// places to look, and a malformed extension is not evidence about any of them.
func manufacturerFromDirectoryAttributes(value []byte) string {
	var attributes []directoryAttribute
	if _, err := asn1.Unmarshal(value, &attributes); err != nil {
		return ""
	}
	for _, attribute := range attributes {
		if !attribute.Type.Equal(OIDTCGAttributeTPMManufacturer) {
			continue
		}
		for _, raw := range attribute.Values {
			var decoded string
			if _, err := asn1.Unmarshal(raw.FullBytes, &decoded); err == nil && decoded != "" {
				return decoded
			}
		}
	}
	return ""
}

// manufacturerFromSubjectAltName reads tcg-at-tpmManufacturer out of a
// directoryName GeneralName inside an encoded subjectAltName extension, where
// the TCG EK Credential Profile usually places it.
func manufacturerFromSubjectAltName(value []byte) string {
	var names asn1.RawValue
	if _, err := asn1.Unmarshal(value, &names); err != nil {
		return ""
	}

	rest := names.Bytes
	for len(rest) > 0 {
		var name asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &name)
		if err != nil {
			return ""
		}
		rest = remaining

		// directoryName [4] EXPLICIT Name -- explicit because Name is a CHOICE.
		if name.Class != asn1.ClassContextSpecific || name.Tag != 4 {
			continue
		}
		var rdns pkix.RDNSequence
		if _, err := asn1.Unmarshal(name.Bytes, &rdns); err != nil {
			continue
		}
		var subject pkix.Name
		subject.FillFromRDNSequence(&rdns)
		if found := attributeValue(subject.Names, OIDTCGAttributeTPMManufacturer); found != "" {
			return found
		}
	}
	return ""
}

// attributeValue returns the string value of the first attribute of the given
// type, or the empty string.
func attributeValue(attributes []pkix.AttributeTypeAndValue, oid asn1.ObjectIdentifier) string {
	for _, attribute := range attributes {
		if !attribute.Type.Equal(oid) {
			continue
		}
		if value, ok := attribute.Value.(string); ok {
			return value
		}
	}
	return ""
}
