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

package truststore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// generateSelfSignedCert creates a self-signed certificate where both subject
// and issuer fields match. The subjectCN, subjectOrg, isCA, extKeyUsage, and
// extraExtensions are all configurable for classification testing.
func generateSelfSignedCert(
	t *testing.T,
	subjectCN string,
	subjectOrg []string,
	isCA bool,
	extKeyUsage []x509.ExtKeyUsage,
	extraExtensions []pkix.Extension,
) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   subjectCN,
			Organization: subjectOrg,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtKeyUsage:           extKeyUsage,
		ExtraExtensions:       extraExtensions,
	}

	// Self-signed: template is both the certificate and the parent.
	// The parsed cert's Issuer will equal the template's Subject.
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	return cert
}

// generateSignedCert creates a leaf certificate signed by a separate parent CA.
// This produces a cert where the issuer fields come from the parent's subject,
// allowing tests to control the issuer independently from the subject.
func generateSignedCert(
	t *testing.T,
	subjectCN string,
	subjectOrg []string,
	issuerCN string,
	issuerOrg []string,
	isCA bool,
	extKeyUsage []x509.ExtKeyUsage,
	extraExtensions []pkix.Extension,
) *x509.Certificate {
	t.Helper()

	// Generate parent CA key and certificate.
	parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate parent ECDSA key: %v", err)
	}

	parentSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate parent serial number: %v", err)
	}

	parentTemplate := &x509.Certificate{
		SerialNumber: parentSerial,
		Subject: pkix.Name{
			CommonName:   issuerCN,
			Organization: issuerOrg,
		},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	parentDER, err := x509.CreateCertificate(rand.Reader, parentTemplate, parentTemplate, &parentKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("failed to create parent certificate: %v", err)
	}

	parentCert, err := x509.ParseCertificate(parentDER)
	if err != nil {
		t.Fatalf("failed to parse parent certificate: %v", err)
	}

	// Generate leaf key and certificate signed by the parent.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf ECDSA key: %v", err)
	}

	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate leaf serial number: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   subjectCN,
			Organization: subjectOrg,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtKeyUsage:           extKeyUsage,
		ExtraExtensions:       extraExtensions,
	}

	// Signed by parent: the leaf cert's Issuer comes from parentCert's Subject.
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, parentCert, &leafKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return leaf
}

// TestClassifyCertificate_AndroidAttestationOIDIsNotAndroidHardware guards
// #1312: the Android key attestation extension belongs on a device leaf,
// never on a root, and anyone can put the OID on a certificate they mint. A
// self-signed CA carrying it is classified like any other self-signed CA,
// never as an Android attestation anchor.
func TestClassifyCertificate_AndroidAttestationOIDIsNotAndroidHardware(t *testing.T) {
	androidOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	ext := pkix.Extension{
		Id:    androidOID,
		Value: []byte{0x30, 0x00}, // minimal ASN.1 SEQUENCE
	}

	tests := []struct {
		name string
		isCA bool
		want CertPurpose
	}{
		{"self-signed CA", true, PurposeUserCA},
		{"self-signed leaf", false, PurposeGeneral},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := generateSelfSignedCert(t,
				"Android Test",
				[]string{"Test Org"},
				tt.isCA,
				nil,
				[]pkix.Extension{ext},
			)

			if got := ClassifyCertificate(cert); got != tt.want {
				t.Errorf("ClassifyCertificate() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClassifyCertificate_ForgedGoogleAttestationRootIsNotAndroidHardware
// guards #1304: a self-signed CA whose DN names "Google ... Attestation" is
// anyone's to mint, so the names alone must not file it as an Android
// attestation anchor. It is classified like any other self-signed CA.
func TestClassifyCertificate_ForgedGoogleAttestationRootIsNotAndroidHardware(t *testing.T) {
	cert := generateSelfSignedCert(t,
		"Google Hardware Attestation Root",
		[]string{"Google LLC"},
		true,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeUserCA {
		t.Errorf("ClassifyCertificate() = %q, want %q for a self-signed CA that only names Google", got, PurposeUserCA)
	}
}

// TestClassifyCertificate_GoogleNamedIssuerIsNotAndroidHardware guards the
// issued-certificate half of #1304: a certificate whose issuer DN claims a
// Google attestation CA is not an attestation anchor on that claim alone.
func TestClassifyCertificate_GoogleNamedIssuerIsNotAndroidHardware(t *testing.T) {
	cert := generateSignedCert(t,
		"Device Key",
		[]string{"Device Vendor"},
		"Google Hardware Attestation Intermediate",
		[]string{"Google LLC"},
		false,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeGeneral {
		t.Errorf("ClassifyCertificate() = %q, want %q for a certificate whose issuer only names Google", got, PurposeGeneral)
	}
}

// TestClassifyCertificate_EmbeddedGoogleRootsAreAndroidHardware proves the
// genuine Google Hardware Attestation Roots still classify as Android
// hardware anchors -- including the RSA roots, whose DN carries only a
// serial number and never matched the issuer-name heuristic this replaced.
func TestClassifyCertificate_EmbeddedGoogleRootsAreAndroidHardware(t *testing.T) {
	roots := LoadEmbeddedRoots(PurposeAndroidHardware)
	if len(roots) == 0 {
		t.Fatal("no embedded Google Hardware Attestation Roots")
	}
	for i, root := range roots {
		if got := ClassifyCertificate(root); got != PurposeAndroidHardware {
			t.Errorf("ClassifyCertificate(embedded root %d, %s) = %q, want %q",
				i, root.Subject, got, PurposeAndroidHardware)
		}
	}
}

func TestClassifyCertificate_TPMManufacturer(t *testing.T) {
	manufacturers := []struct {
		name string
		org  string
	}{
		{"Intel", "Intel Corporation"},
		{"AMD", "Advanced Micro Devices (AMD)"},
		{"Infineon", "Infineon Technologies AG"},
		{"Nuvoton", "Nuvoton Technology Corporation"},
		{"STMicroelectronics", "STMicroelectronics NV"},
		{"NationZ", "NationZ Technologies Inc"},
		{"Atmel", "Atmel Corporation"},
		{"Broadcom", "Broadcom Inc"},
		{"Qualcomm", "Qualcomm Technologies"},
	}

	for _, mfg := range manufacturers {
		t.Run(mfg.name, func(t *testing.T) {
			// Self-signed so issuer org == subject org.
			cert := generateSelfSignedCert(t,
				mfg.name+" TPM EK CA",
				[]string{mfg.org},
				false,
				nil,
				nil,
			)

			got := ClassifyCertificate(cert)
			if got != PurposeTPMManufacturer {
				t.Errorf("ClassifyCertificate() with org %q = %q, want %q",
					mfg.org, got, PurposeTPMManufacturer)
			}
		})
	}
}

func TestClassifyCertificate_TCGExtensionPrefix(t *testing.T) {
	// 2.23.133.8.1 is the TCG EK certificate attribute OID.
	tcgOID := asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	ext := pkix.Extension{
		Id:    tcgOID,
		Value: []byte{0x05, 0x00}, // ASN.1 NULL
	}

	cert := generateSelfSignedCert(t,
		"Some TPM Vendor",
		[]string{"Unknown TPM Vendor"},
		false,
		nil,
		[]pkix.Extension{ext},
	)

	got := ClassifyCertificate(cert)
	if got != PurposeTPMManufacturer {
		t.Errorf("ClassifyCertificate() = %q, want %q", got, PurposeTPMManufacturer)
	}
}

func TestClassifyCertificate_IDevIDIssuer(t *testing.T) {
	// Use generateSignedCert so the parent's subject (containing "IDevID")
	// becomes the leaf cert's issuer CN.
	cert := generateSignedCert(t,
		"Device Identity",
		[]string{"Enterprise Corp"},
		"Enterprise IDevID CA",
		[]string{"Enterprise Corp"},
		false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeIDevIDIssuer {
		t.Errorf("ClassifyCertificate() = %q, want %q", got, PurposeIDevIDIssuer)
	}
}

func TestClassifyCertificate_IDevIDIssuer_ClientAuth(t *testing.T) {
	cert := generateSignedCert(t,
		"Device Identity",
		[]string{"Enterprise Corp"},
		"Enterprise IDevID CA",
		[]string{"Enterprise Corp"},
		false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeIDevIDIssuer {
		t.Errorf("ClassifyCertificate() = %q, want %q", got, PurposeIDevIDIssuer)
	}
}

func TestClassifyCertificate_IDevIDIssuer_NoEKU(t *testing.T) {
	// IDevID in issuer CN but no ServerAuth or ClientAuth EKU should not
	// classify as IDevID issuer; falls through to general.
	cert := generateSignedCert(t,
		"Device Identity",
		[]string{"Enterprise Corp"},
		"Enterprise IDevID CA",
		[]string{"Enterprise Corp"},
		false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeGeneral {
		t.Errorf("ClassifyCertificate() = %q, want %q (IDevID CN without auth EKU)", got, PurposeGeneral)
	}
}

func TestClassifyCertificate_UserCA(t *testing.T) {
	// The existing generateTestCert creates a self-signed CA where
	// subject == issuer and IsCA == true, so it should classify as UserCA.
	cert := generateTestCert(t, "My Organization CA")

	got := ClassifyCertificate(cert)
	if got != PurposeUserCA {
		t.Errorf("ClassifyCertificate() = %q, want %q", got, PurposeUserCA)
	}
}

func TestClassifyCertificate_General(t *testing.T) {
	// A leaf cert issued by a non-special CA, with no matching properties.
	cert := generateSignedCert(t,
		"web-server.example.com",
		[]string{"Example Inc"},
		"Some Issuer CA",
		[]string{"Example Inc"},
		false,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeGeneral {
		t.Errorf("ClassifyCertificate() = %q, want %q", got, PurposeGeneral)
	}
}

func TestClassifyCertificate_General_NonCANonSpecial(t *testing.T) {
	// A self-signed non-CA cert with no special properties classifies as general.
	cert := generateSelfSignedCert(t,
		"plain-service.example.com",
		[]string{"Example Inc"},
		false,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeGeneral {
		t.Errorf("ClassifyCertificate() = %q, want %q", got, PurposeGeneral)
	}
}

func TestClassifyCertificate_PriorityOrder(t *testing.T) {
	// A certificate with both the Android attestation OID and an Intel
	// issuer organization classifies as a TPM manufacturer: the OID confers
	// nothing (#1312), so it cannot outrank the manufacturer match.
	androidOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}
	ext := pkix.Extension{
		Id:    androidOID,
		Value: []byte{0x30, 0x00},
	}

	cert := generateSelfSignedCert(t,
		"Intel Attestation Root",
		[]string{"Intel Corporation"},
		false,
		nil,
		[]pkix.Extension{ext},
	)

	got := ClassifyCertificate(cert)
	if got != PurposeTPMManufacturer {
		t.Errorf("ClassifyCertificate() = %q, want %q (the Android OID must not outrank the TPM manufacturer match)",
			got, PurposeTPMManufacturer)
	}
}

func TestClassifyCertificate_PriorityTPMOverIDevID(t *testing.T) {
	// TPM manufacturer match takes priority over IDevID issuer heuristic.
	// The parent CA subject becomes the leaf's issuer. Use an Intel org so
	// the manufacturer check fires before the IDevID heuristic.
	cert := generateSignedCert(t,
		"Device Identity",
		[]string{"Intel Corporation"},
		"Intel IDevID CA",
		[]string{"Intel Corporation"},
		false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeTPMManufacturer {
		t.Errorf("ClassifyCertificate() = %q, want %q (TPM manufacturer should take priority over IDevID)",
			got, PurposeTPMManufacturer)
	}
}

func TestClassifyCertificate_UserCA_SameSubjectIssuer(t *testing.T) {
	// Verify the UserCA check requires both CN match and org match.
	cert := generateSelfSignedCert(t,
		"Internal Root CA",
		[]string{"My Company"},
		true,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeUserCA {
		t.Errorf("ClassifyCertificate() = %q, want %q", got, PurposeUserCA)
	}
}

func TestClassifyCertificate_UserCA_NotCA(t *testing.T) {
	// A self-signed cert that is NOT a CA should not classify as UserCA.
	cert := generateSelfSignedCert(t,
		"Self Signed Leaf",
		[]string{"My Company"},
		false,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got == PurposeUserCA {
		t.Errorf("ClassifyCertificate() = %q, want anything other than %q for non-CA self-signed cert",
			got, PurposeUserCA)
	}
}

func TestHasOIDPrefix(t *testing.T) {
	// 2.23.133.2.1 starts with the TCG base OID 2.23.133.
	tcgChild := asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	ext := pkix.Extension{
		Id:    tcgChild,
		Value: []byte{0x05, 0x00},
	}

	cert := generateSelfSignedCert(t,
		"TCG Cert",
		[]string{"Test"},
		false,
		nil,
		[]pkix.Extension{ext},
	)

	prefix := asn1.ObjectIdentifier{2, 23, 133}
	if !hasOIDPrefix(cert, prefix) {
		t.Error("hasOIDPrefix() = false, want true for extension OID 2.23.133.2.1 with prefix 2.23.133")
	}
}

func TestHasOIDPrefix_NoMatch(t *testing.T) {
	// Extension OID 1.2.3.4 does not start with 2.23.133.
	unrelatedOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	ext := pkix.Extension{
		Id:    unrelatedOID,
		Value: []byte{0x05, 0x00},
	}

	cert := generateSelfSignedCert(t,
		"Unrelated Cert",
		[]string{"Test"},
		false,
		nil,
		[]pkix.Extension{ext},
	)

	prefix := asn1.ObjectIdentifier{2, 23, 133}
	if hasOIDPrefix(cert, prefix) {
		t.Error("hasOIDPrefix() = true, want false for extension OID 1.2.3.4 with prefix 2.23.133")
	}
}

func TestHasOIDPrefix_ExactMatch(t *testing.T) {
	// Extension OID that exactly matches the prefix (no additional components).
	exactOID := asn1.ObjectIdentifier{2, 23, 133}
	ext := pkix.Extension{
		Id:    exactOID,
		Value: []byte{0x05, 0x00},
	}

	cert := generateSelfSignedCert(t,
		"Exact TCG",
		[]string{"Test"},
		false,
		nil,
		[]pkix.Extension{ext},
	)

	prefix := asn1.ObjectIdentifier{2, 23, 133}
	if !hasOIDPrefix(cert, prefix) {
		t.Error("hasOIDPrefix() = false, want true for exact OID match with prefix")
	}
}

func TestHasOIDPrefix_ShorterThanPrefix(t *testing.T) {
	// Extension OID that is shorter than the prefix should not match.
	shortOID := asn1.ObjectIdentifier{2, 23}
	ext := pkix.Extension{
		Id:    shortOID,
		Value: []byte{0x05, 0x00},
	}

	cert := generateSelfSignedCert(t,
		"Short OID",
		[]string{"Test"},
		false,
		nil,
		[]pkix.Extension{ext},
	)

	prefix := asn1.ObjectIdentifier{2, 23, 133}
	if hasOIDPrefix(cert, prefix) {
		t.Error("hasOIDPrefix() = true, want false for OID shorter than prefix")
	}
}

func TestHasOIDPrefix_NoExtensions(t *testing.T) {
	cert := generateTestCert(t, "No Extra Extensions")

	// Use a prefix that would not match the standard CA extensions.
	prefix := asn1.ObjectIdentifier{2, 23, 133}
	if hasOIDPrefix(cert, prefix) {
		t.Error("hasOIDPrefix() = true, want false for standard CA cert with no TCG extensions")
	}
}

func TestClassifyCertificate_MultipleExtensions(t *testing.T) {
	// A cert with multiple extensions, one of them the Android attestation
	// OID, is still not an Android hardware anchor (#1312).
	unrelatedOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 15}
	androidOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

	extensions := []pkix.Extension{
		{Id: unrelatedOID, Value: []byte{0x30, 0x00}},
		{Id: androidOID, Value: []byte{0x30, 0x00}},
	}

	cert := generateSelfSignedCert(t,
		"Multi Extension",
		[]string{"Test"},
		false,
		nil,
		extensions,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeGeneral {
		t.Errorf("ClassifyCertificate() = %q, want %q for cert with Android OID among multiple extensions",
			got, PurposeGeneral)
	}
}

func TestClassifyCertificate_GoogleIssuerNoAttestation(t *testing.T) {
	// A Google LLC certificate that is not an embedded attestation root is
	// not an Android hardware anchor.
	cert := generateSelfSignedCert(t,
		"Google Trust Services",
		[]string{"Google LLC"},
		false,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got == PurposeAndroidHardware {
		t.Errorf("ClassifyCertificate() = %q, want anything other than %q for Google issuer without Attestation in CN",
			got, PurposeAndroidHardware)
	}
}

func TestClassifyCertificate_CaseInsensitiveManufacturer(t *testing.T) {
	// Manufacturer lookup should be case-insensitive.
	cert := generateSelfSignedCert(t,
		"INTEL TPM EK",
		[]string{"INTEL CORPORATION"},
		false,
		nil,
		nil,
	)

	got := ClassifyCertificate(cert)
	if got != PurposeTPMManufacturer {
		t.Errorf("ClassifyCertificate() = %q, want %q for uppercase manufacturer name",
			got, PurposeTPMManufacturer)
	}
}
