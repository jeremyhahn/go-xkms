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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

// TCG DevID certificate conformance.
//
// Everything here is asserted on the ISSUED DER, parsed back, because that is
// what a relying party receives. A template can hold a field that never reaches
// the certificate -- crypto/x509 drops a subjectAltName it was not asked to
// encode, for one -- so a test that reads the template proves nothing about the
// credential.
//
// Reference: TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12
// (2021-10-08), §8.1 "DevID Certificate Fields Summary" and §8.2 "TCG OIDs".

// parsedOtherNames decodes the otherName entries of a certificate's
// subjectAltName, keyed by type-id. It walks the extension by hand: crypto/x509
// discards otherNames when it parses a certificate, so the only way to see them
// is to read the extension.
func parsedOtherNames(t *testing.T, cert *x509.Certificate) map[string][]byte {
	t.Helper()

	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			if ext.Critical {
				t.Error("TCG DevID §8.1: the subjectAltName SHOULD NOT be critical")
			}
			raw = ext.Value
		}
	}
	if raw == nil {
		t.Fatal("certificate has no subjectAltName extension")
	}

	var names asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &names); err != nil {
		t.Fatalf("decode GeneralNames: %v", err)
	}

	found := make(map[string][]byte)
	rest := names.Bytes
	for len(rest) > 0 {
		var name asn1.RawValue
		remaining, err := asn1.Unmarshal(rest, &name)
		if err != nil {
			t.Fatalf("decode GeneralName: %v", err)
		}
		rest = remaining
		if name.Class != asn1.ClassContextSpecific || name.Tag != 0 {
			continue
		}

		var typeID asn1.ObjectIdentifier
		valueBytes, err := asn1.Unmarshal(name.Bytes, &typeID)
		if err != nil {
			t.Fatalf("decode otherName type-id: %v", err)
		}
		var wrapped asn1.RawValue
		if _, err := asn1.Unmarshal(valueBytes, &wrapped); err != nil {
			t.Fatalf("decode otherName value: %v", err)
		}
		found[typeID.String()] = wrapped.Bytes
	}
	return found
}

// requireDevIDSubjectAltName asserts the two otherNames TCG DevID §8.1 makes a
// SHALL, and returns them decoded.
func requireDevIDSubjectAltName(
	t *testing.T,
	cert *x509.Certificate,
) (TCGHardwareModuleName, TCGPermanentIdentifier) {
	t.Helper()

	others := parsedOtherNames(t, cert)

	hwRaw, ok := others[OIDHardwareModuleName.String()]
	if !ok {
		t.Fatal("TCG DevID §8.1 SHALL: subjectAltName carries no id-on-hardwareModuleName otherName")
	}
	hwName, err := ParseHardwareModuleNameExtension(hwRaw)
	if err != nil {
		t.Fatalf("decode hardwareModuleName: %v", err)
	}
	if !hwName.HWType.Equal(OIDTCGHwTypeTPM2) {
		t.Errorf("hwType = %v, want the TPM 2.0 hwType %v", hwName.HWType, OIDTCGHwTypeTPM2)
	}

	permRaw, ok := others[OIDPermanentIdentifier.String()]
	if !ok {
		t.Fatal("TCG DevID §8.1 SHALL: subjectAltName carries no id-on-permanentIdentifier otherName")
	}
	permID, err := ParsePermanentIdentifierExtension(permRaw)
	if err != nil {
		t.Fatalf("decode permanentIdentifier: %v", err)
	}
	if !permID.Assigner.Equal(OIDTCGOnEKPermIdSha256) {
		t.Errorf("assigner = %v, want tcg-on-ekPermIdSha256 %v", permID.Assigner, OIDTCGOnEKPermIdSha256)
	}

	return hwName, permID
}

// TestTCGDevID_IssuedCertificatesCarrySection81SubjectAltName is the §8.1 SHALL
// on both credentials of one enrollment, read off the issued DER.
//
// The hwSerialNum is pinned exactly. Every one of its three components is fixed
// by the fixture -- the manufacturer code recorded in the endorsement key
// certificate, that certificate's authority key identifier, and its serial
// number -- so the whole string is a constant, and the rendering of the two
// binary components into ASCII cannot drift without this failing.
func TestTCGDevID_IssuedCertificatesCarrySection81SubjectAltName(t *testing.T) {
	ca := createTestCAForTCG(t)
	device, _, iakDER, idevidDER := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)

	// "<TCG TPM Manufacturer code>:<EK Authority Key Identifier>:<EK
	// CertificateSerialNumber>", colon-separated, in that order (§8.1).
	const wantHWSerial = "id:53544D20:a1b2c3d4e5:0102030405"

	// hex(SHA-256(DER of the EK certificate)), computed here rather than by the
	// function under test.
	ekDigest := sha256.Sum256(device.csr.CsrContents.EkCert)
	wantPermID := hex.EncodeToString(ekDigest[:])

	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"iak", iakDER},
		{"idevid", idevidDER},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := parseDER(t, tc.der)
			hwName, permID := requireDevIDSubjectAltName(t, cert)

			if got := string(hwName.HWSerial); got != wantHWSerial {
				t.Errorf("hwSerialNum = %q, want %q", got, wantHWSerial)
			}
			if permID.IdentifierValue != wantPermID {
				t.Errorf("identifierValue = %q, want %q", permID.IdentifierValue, wantPermID)
			}

			// §8.1: "The subject field's DN encoding SHOULD include the
			// 'serialNumber' attribute with the device's unique serial number."
			if cert.Subject.SerialNumber != softwareCSRSerial {
				t.Errorf("Subject.SerialNumber = %q, want %q", cert.Subject.SerialNumber, softwareCSRSerial)
			}

			// §8.1: the certificate serial number is 64 to 160 bits.
			bits := cert.SerialNumber.BitLen()
			if bits < 64 || bits > 160 {
				t.Errorf("certificate serial number is %d bits, want 64..160", bits)
			}
			if cert.SerialNumber.Sign() < 0 {
				t.Error("certificate serial number must be non-negative")
			}

			// §8.1: an IDevID/IAK "is expected to exist for as long as the host
			// module remains operational"; notAfter is 99991231235959Z.
			if !cert.NotAfter.Equal(tcgNotAfter) {
				t.Errorf("NotAfter = %v, want %v", cert.NotAfter, tcgNotAfter)
			}
		})
	}
}

// TestTCGDevID_IssuedCertificatesCarrySection82Policies pins the §8.2
// assertions and the §8.1 key usage and extended key usage on the issued DER.
func TestTCGDevID_IssuedCertificatesCarrySection82Policies(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, _, iakDER, idevidDER := enrollSoftwareDevice(t, ca, softwareCSRModel, softwareCSRSerial)

	iak := parseDER(t, iakDER)
	idevid := parseDER(t, idevidDER)

	hasPolicy := func(cert *x509.Certificate, oid x509.OID) bool {
		for _, policy := range cert.Policies {
			if policy.Equal(oid) {
				return true
			}
		}
		return false
	}
	hasUnknownEKU := func(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
		for _, eku := range cert.UnknownExtKeyUsage {
			if eku.Equal(oid) {
				return true
			}
		}
		return false
	}

	// §8.1: "The Certificate Policy extension MUST be present."
	if len(iak.Policies) == 0 || len(idevid.Policies) == 0 {
		t.Fatal("TCG DevID §8.1 MUST: the certificate policy extension is absent")
	}

	// §8.2: an IAK asserts residency and restricted. verifiedTPMRestricted
	// "MUST NOT be combined with TCG-CE-FixedTPM".
	if !hasPolicy(iak, TCGVerifiedTPMResidencyPolicy) {
		t.Error("IAK is missing tcg-cap-verifiedTPMResidency")
	}
	if !hasPolicy(iak, TCGVerifiedTPMRestrictedPolicy) {
		t.Error("IAK is missing tcg-cap-verifiedTPMRestricted")
	}
	if hasPolicy(iak, TCGVerifiedTPMFixedPolicy) {
		t.Error("TCG DevID §8.2 MUST NOT: the IAK combines verifiedTPMFixed with verifiedTPMRestricted")
	}

	// §8.2: an IDevID asserts residency and fixed, never restricted -- the
	// identity key is created Unrestricted so that it can sign arbitrary data.
	if !hasPolicy(idevid, TCGVerifiedTPMResidencyPolicy) {
		t.Error("IDevID is missing tcg-cap-verifiedTPMResidency")
	}
	if !hasPolicy(idevid, TCGVerifiedTPMFixedPolicy) {
		t.Error("IDevID is missing tcg-cap-verifiedTPMFixed")
	}
	if hasPolicy(idevid, TCGVerifiedTPMRestrictedPolicy) {
		t.Error("TCG DevID §8.2 MUST NOT: the IDevID combines verifiedTPMRestricted with verifiedTPMFixed")
	}

	// §8.1: the tcg-cap-* assertions are policy identifiers carrying "No data",
	// never standalone extensions.
	for _, cert := range []*x509.Certificate{iak, idevid} {
		for _, oid := range []asn1.ObjectIdentifier{
			OIDTCGVerifiedTPMResidency, OIDTCGVerifiedTPMFixed, OIDTCGVerifiedTPMRestricted,
		} {
			if hasExtensionOID(cert, oid) {
				t.Errorf("%s must not appear as a standalone extension", oid)
			}
		}
	}

	// §8.1 Extended Key Usage: "the one TCG OID most appropriate for the type
	// of key used", one each and not the other.
	if !hasUnknownEKU(iak, OIDTCGVerifiedTPMRestricted) {
		t.Error("IAK extended key usage is missing the restricted TCG OID")
	}
	if hasUnknownEKU(iak, OIDTCGVerifiedTPMFixed) {
		t.Error("IAK extended key usage must carry only one TCG OID")
	}
	if !hasUnknownEKU(idevid, OIDTCGVerifiedTPMFixed) {
		t.Error("IDevID extended key usage is missing the fixed TCG OID")
	}
	if hasUnknownEKU(idevid, OIDTCGVerifiedTPMRestricted) {
		t.Error("IDevID extended key usage must carry only one TCG OID")
	}

	// §8.1 Table 22: digitalSignature, and for a non-Combined IDevID nothing
	// else -- keyEncipherment belongs to a Combined key, which the CA refuses.
	for name, cert := range map[string]*x509.Certificate{"iak": iak, "idevid": idevid} {
		if cert.KeyUsage != x509.KeyUsageDigitalSignature {
			t.Errorf("%s key usage = %b, want digitalSignature only", name, cert.KeyUsage)
		}
	}
}

// TestSignTCGCSRIDevID_RefusesCSRWithoutEKCertificate: the §8.1 subjectAltName
// is derived from the endorsement key certificate, and §6.2.2 step 4b puts that
// certificate in the request. A CSR without one cannot be certified.
func TestSignTCGCSRIDevID_RefusesCSRWithoutEKCertificate(t *testing.T) {
	ca := createTestCAForTCG(t)
	device := buildSoftwareTCGCSRWithEK(t, softwareCSRModel, softwareCSRSerial, false)

	signerKey := generateTestECDSAKey(t)
	request := createTestCertRequest(t, signerKey, createSelfSignedCACert(t, signerKey))

	_, _, err := ca.SignTCGCSRIDevID(context.Background(), device.csr, request)
	if !errors.Is(err, ErrTCGInvalidEKCert) {
		t.Fatalf("error = %v, want %v", err, ErrTCGInvalidEKCert)
	}
}

// TestTCGDeviceIdentityFromEKCertificate_RefusesUnknownManufacturer: without a
// manufacturer code the hwSerialNum would name the wrong TPM, so issuance stops
// rather than guessing.
func TestTCGDeviceIdentityFromEKCertificate_RefusesUnknownManufacturer(t *testing.T) {
	cert := issueTestEKCertificate(t, pkix.Name{CommonName: "anonymous-ek"}, nil)

	_, err := TCGDeviceIdentityFromEKCertificate(cert, "")
	if !errors.Is(err, ErrTCGEKManufacturerUnknown) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKManufacturerUnknown)
	}

	// A code supplied by the operator stands in for a certificate that records
	// none, and the certificate's own code always wins over it.
	identity, err := TCGDeviceIdentityFromEKCertificate(cert, "id:FFFFFFFF")
	if err != nil {
		t.Fatalf("unexpected error with an operator-supplied code: %v", err)
	}
	if want := "id:FFFFFFFF:" + hex.EncodeToString(cert.AuthorityKeyId); len(identity.HardwareSerialNumber) < len(want) ||
		identity.HardwareSerialNumber[:len(want)] != want {
		t.Errorf("hwSerialNum = %q, want the prefix %q", identity.HardwareSerialNumber, want)
	}
}

// TestTCGTPMManufacturer_ReadsSubjectAltNameDirectoryName covers the placement
// real endorsement key certificates use: the subject is empty and the TCG
// attributes live in a directoryName inside subjectAltName.
func TestTCGTPMManufacturer_ReadsSubjectAltNameDirectoryName(t *testing.T) {
	const manufacturer = "id:49465800"

	rdns := pkix.RDNSequence{pkix.RelativeDistinguishedNameSET{
		pkix.AttributeTypeAndValue{Type: OIDTCGAttributeTPMManufacturer, Value: manufacturer},
	}}
	nameDER, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("marshal RDN sequence: %v", err)
	}
	directoryName, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: nameDER,
	})
	if err != nil {
		t.Fatalf("marshal directoryName: %v", err)
	}
	generalNames, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: directoryName,
	})
	if err != nil {
		t.Fatalf("marshal GeneralNames: %v", err)
	}

	cert := issueTestEKCertificate(t, pkix.Name{CommonName: "ek-in-san"}, []pkix.Extension{{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: generalNames,
	}})

	got, err := TCGTPMManufacturer(cert)
	if err != nil {
		t.Fatalf("TCGTPMManufacturer: %v", err)
	}
	if got != manufacturer {
		t.Errorf("manufacturer = %q, want %q", got, manufacturer)
	}
}

// TestTCGTPMManufacturer_ReadsSubjectDirectoryAttributes covers the other
// placement the TCG EK Credential Profile allows.
func TestTCGTPMManufacturer_ReadsSubjectDirectoryAttributes(t *testing.T) {
	const manufacturer = "id:414D4400"

	value, err := asn1.Marshal([]directoryAttribute{{
		Type:   OIDTCGAttributeTPMManufacturer,
		Values: []asn1.RawValue{mustMarshalRawUTF8(t, manufacturer)},
	}})
	if err != nil {
		t.Fatalf("marshal subjectDirectoryAttributes: %v", err)
	}

	cert := issueTestEKCertificate(t, pkix.Name{CommonName: "ek-in-sda"}, []pkix.Extension{{
		Id:    oidSubjectDirectoryAttributes,
		Value: value,
	}})

	got, err := TCGTPMManufacturer(cert)
	if err != nil {
		t.Fatalf("TCGTPMManufacturer: %v", err)
	}
	if got != manufacturer {
		t.Errorf("manufacturer = %q, want %q", got, manufacturer)
	}
}

// TestTCGDeviceIdentityFromEKPublicKey pins the §8.1 method-2 derivation, used
// when the TPM has no endorsement key certificate, against digests computed by
// hand from a fixed input.
func TestTCGDeviceIdentityFromEKPublicKey(t *testing.T) {
	// sha256("test-ek-public-key-der") and
	// sha256("EkPubkey" || "test-ek-public-key-der").
	const (
		wantHWSerial = "f1ffc680ddd5c30039ea008d7d12c3e8a2b3d809662b88a569be95e8584e8905"
		wantPermID   = "28a184b273084dc67aa18cf13d6bbc07da44fef7807f506d791c85a1652ef86d"
	)

	identity, err := TCGDeviceIdentityFromEKPublicKey([]byte("test-ek-public-key-der"))
	if err != nil {
		t.Fatalf("TCGDeviceIdentityFromEKPublicKey: %v", err)
	}
	if identity.HardwareSerialNumber != wantHWSerial {
		t.Errorf("hwSerialNum = %q, want %q", identity.HardwareSerialNumber, wantHWSerial)
	}
	if identity.PermanentIdentifier != wantPermID {
		t.Errorf("identifierValue = %q, want %q", identity.PermanentIdentifier, wantPermID)
	}

	if _, err := TCGDeviceIdentityFromEKPublicKey(nil); !errors.Is(err, ErrTCGInvalidPublicKey) {
		t.Fatalf("error for an absent key = %v, want %v", err, ErrTCGInvalidPublicKey)
	}
}

// TestBuildSubjectAltName_KeepsStandardNames proves the shared encoder does not
// lose the names crypto/x509 would have written, which is the whole reason it
// has to write them.
func TestBuildSubjectAltName_KeepsStandardNames(t *testing.T) {
	value, err := MarshalPermanentIdentifier("perm", OIDTCGOnEKPermIdSha256)
	if err != nil {
		t.Fatalf("marshal permanent identifier: %v", err)
	}

	ext, err := BuildSubjectAltName(
		pkix.Name{CommonName: "device"},
		[]string{"device.example.com"},
		[]string{"ops@example.com"},
		nil,
		nil,
		[]OtherName{{TypeID: OIDPermanentIdentifier, Value: value}},
	)
	if err != nil {
		t.Fatalf("BuildSubjectAltName: %v", err)
	}

	// Round-trip through a real certificate: the parser is the reader whose
	// opinion matters.
	cert := issueTestEKCertificate(t, pkix.Name{CommonName: "device"}, []pkix.Extension{ext})
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "device.example.com" {
		t.Errorf("DNSNames = %v, want [device.example.com]", cert.DNSNames)
	}
	if len(cert.EmailAddresses) != 1 || cert.EmailAddresses[0] != "ops@example.com" {
		t.Errorf("EmailAddresses = %v, want [ops@example.com]", cert.EmailAddresses)
	}
	if _, ok := parsedOtherNames(t, cert)[OIDPermanentIdentifier.String()]; !ok {
		t.Error("the permanent identifier otherName did not survive encoding")
	}
}

// TestBuildSubjectAltName_RefusesEmptyAndMalformed covers the error paths: an
// extension with no names at all is prohibited by RFC 5280, and an otherName
// without a type or a value cannot be encoded.
func TestBuildSubjectAltName_RefusesEmptyAndMalformed(t *testing.T) {
	if _, err := BuildSubjectAltName(pkix.Name{CommonName: "d"}, nil, nil, nil, nil, nil); !errors.Is(err, ErrInvalidCertificate) {
		t.Errorf("error for no names = %v, want %v", err, ErrInvalidCertificate)
	}
	if _, err := BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]OtherName{{Value: []byte{0x05, 0x00}}}); !errors.Is(err, ErrTCGExtensionEncoding) {
		t.Errorf("error for a typeless otherName = %v, want %v", err, ErrTCGExtensionEncoding)
	}
	if _, err := BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]OtherName{{TypeID: OIDPermanentIdentifier}}); !errors.Is(err, ErrTCGExtensionEncoding) {
		t.Errorf("error for a valueless otherName = %v, want %v", err, ErrTCGExtensionEncoding)
	}
}

// issueTestEKCertificate signs a self-signed certificate standing in for a
// manufacturer's endorsement key certificate.
func issueTestEKCertificate(t *testing.T, subject pkix.Name, extensions []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(0x0A0B0C0D0E),
		Subject:         subject,
		AuthorityKeyId:  []byte{0x11, 0x22, 0x33},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return parseDER(t, der)
}

// mustMarshalRawUTF8 encodes a UTF8String as a RawValue for a SET OF.
func mustMarshalRawUTF8(t *testing.T, value string) asn1.RawValue {
	t.Helper()
	der, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		t.Fatalf("marshal utf8 string: %v", err)
	}
	return asn1.RawValue{FullBytes: der}
}
