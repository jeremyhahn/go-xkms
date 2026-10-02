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
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

// =============================================================================
// WebAuthn L2 §8.3.1 TPM Attestation Statement Certificate Requirements
// =============================================================================
//
// go-xkms#715 brings the tcg-kp-EKCertificate / tcg-kp-AIKCertificate
// Extended Key Usage encoding and the AK/IAK Basic Constraints assertion into
// line with WebAuthn L2 §8.3.1 and go-webauthn's "tpm" attestation format
// verifier. The Subject field requirement (§8.3.1 requirement 2, "MUST be set
// to empty") is deliberately NOT addressed here: TCG TPM 2.0 Keys for Device
// Identity and Attestation v1.00 r12 §8 mandates the opposite ("the subject
// field MUST contain a unique X.500 Distinguished Name") for the IAK/AK, and
// go-xkms's certificate store is keyed by Subject.CommonName
// (pkg/certstore.CertStore, compositeCertStore.StoreCertificate). The owner
// resolved that contradiction (option A): the IAK/AK certificate keeps its
// TCG DevID Subject, as these tests assume, and a second key -- the Local
// Attestation Key, a Restricted signing child of the Platform SRK certified
// by the IAK via TPM2_Certify -- carries the empty-Subject WebAuthn profile
// certificate instead. See tcg_lak.go and tcg_lak_test.go for the LAK's
// certificate issuance and the requirement 2 (empty Subject) assertion.

// oidExtendedKeyUsage and tpmBasicConstraints reproduce, byte for byte, how
// go-webauthn@v0.17.4's "tpm" attestation format verifier
// (protocol/attestation_tpm.go) decodes the ExtKeyUsage and BasicConstraints
// extensions off an AIK certificate: asn1.Unmarshal the raw extension value
// into exactly these shapes. Using the same decode here is what makes
// TestIssueAKCertificate_EKUDecodesLikeGoWebAuthn and
// TestSignTCGCSRIDevID_IAKEKUDecodesLikeGoWebAuthn evidence that the
// certificate would pass go-webauthn's own parser, not just this package's
// idea of where the OID lives.
var oidExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
var oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}

type tpmBasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// decodeEKULikeGoWebAuthn parses a certificate's ExtKeyUsage extension the
// way go-webauthn's tpm format handler does and reports whether oid appears
// among its values. It fails the test outright if the extension is absent or
// malformed, since go-webauthn treats both as "AIK certificate missing EKU".
func decodeEKULikeGoWebAuthn(t *testing.T, cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	t.Helper()
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtendedKeyUsage) {
			continue
		}
		var eku []asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(ext.Value, &eku)
		if err != nil {
			t.Fatalf("ExtKeyUsage extension malformed: %v", err)
		}
		if len(rest) != 0 {
			t.Fatalf("ExtKeyUsage extension contains extra data")
		}
		for _, got := range eku {
			if got.Equal(oid) {
				return true
			}
		}
		return false
	}
	t.Fatal("certificate has no ExtKeyUsage extension")
	return false
}

// decodeBasicConstraintsLikeGoWebAuthn parses a certificate's BasicConstraints
// extension the way go-webauthn's tpm format handler does. An absent
// extension decodes to the zero value (IsCA false), matching go-webauthn's
// own behaviour: the extension is optional per WebAuthn L2 §8.3.1
// requirement 6's neighbouring commentary, so requirement 5 ("MUST have the
// CA component set to false") is satisfied either way.
func decodeBasicConstraintsLikeGoWebAuthn(t *testing.T, cert *x509.Certificate) tpmBasicConstraints {
	t.Helper()
	var constraints tpmBasicConstraints
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidBasicConstraints) {
			continue
		}
		rest, err := asn1.Unmarshal(ext.Value, &constraints)
		if err != nil {
			t.Fatalf("BasicConstraints extension malformed: %v", err)
		}
		if len(rest) != 0 {
			t.Fatalf("BasicConstraints extension contains extra data")
		}
		return constraints
	}
	return constraints
}

// TestIssueEKCertificate_EKUInStandardExtension proves tcg-kp-EKCertificate
// (2.23.133.8.1) is carried in the certificate's standard ExtKeyUsage
// extension via UnknownExtKeyUsage, not as a standalone extension under the
// OID's own Id -- the encoding requireTCGEKCertificateEKU (run against every
// EK certificate chain before IAK/IDevID issuance) and a conformant relying
// party both read.
func TestIssueEKCertificate_EKUInStandardExtension(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	ekKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Test EK WebAuthn Profile"

	cert, err := ca.IssueEKCertificate(context.Background(), request, ekKey.Public())
	if err != nil {
		t.Fatalf("IssueEKCertificate() returned unexpected error: %v", err)
	}

	found := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDTCGKpEKCertificate) {
			found = true
			break
		}
	}
	if !found {
		t.Error("EK certificate UnknownExtKeyUsage does not carry tcg-kp-EKCertificate")
	}

	// The old encoding -- a standalone extension whose own Id is
	// tcg-kp-EKCertificate -- must not reappear alongside the fix.
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGKpEKCertificate) {
			t.Error("tcg-kp-EKCertificate must not also appear as a standalone extension")
		}
	}

	if !decodeEKULikeGoWebAuthn(t, cert, OIDTCGKpEKCertificate) {
		t.Error("tcg-kp-EKCertificate not found when the ExtKeyUsage extension is decoded the way a relying party would decode it")
	}
}

// TestIssueAKCertificate_WebAuthnProfile proves an AK certificate issued
// through IssueAKCertificate carries tcg-kp-AIKCertificate inside its
// standard ExtKeyUsage extension and explicitly asserts BasicConstraints
// with CA:false -- WebAuthn L2 §8.3.1 requirements 4 and 5.
func TestIssueAKCertificate_WebAuthnProfile(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	akKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Test AK WebAuthn Profile"

	cert, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() returned unexpected error: %v", err)
	}

	found := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDTCGKpAIKCertificate) {
			found = true
			break
		}
	}
	if !found {
		t.Error("AK certificate UnknownExtKeyUsage does not carry tcg-kp-AIKCertificate")
	}

	if !cert.BasicConstraintsValid {
		t.Error("AK certificate must assert a Basic Constraints extension (WebAuthn L2 §8.3.1 requirement 5)")
	}
	if cert.IsCA {
		t.Error("AK certificate Basic Constraints must have CA:false")
	}
}

// TestIssueAKCertificate_EKUDecodesLikeGoWebAuthn is
// TestIssueAKCertificate_WebAuthnProfile's evidence that a real "tpm" format
// verifier, not just this package's own field checks, would accept the
// certificate's Extended Key Usage and Basic Constraints: it decodes both
// extensions exactly as go-webauthn@v0.17.4's attestation_tpm.go does.
func TestIssueAKCertificate_EKUDecodesLikeGoWebAuthn(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	akKey := generateTestECDSAKey(t)

	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "Test AK go-webauthn Decode"

	cert, err := ca.IssueAKCertificate(context.Background(), request, akKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() returned unexpected error: %v", err)
	}

	if !decodeEKULikeGoWebAuthn(t, cert, OIDTCGKpAIKCertificate) {
		t.Error("tcg-kp-AIKCertificate not found when the ExtKeyUsage extension is decoded the way go-webauthn decodes it")
	}

	constraints := decodeBasicConstraintsLikeGoWebAuthn(t, cert)
	if constraints.IsCA {
		t.Error("go-webauthn's own BasicConstraints decode reports IsCA true; requirement 5 would fail")
	}
}

// TestSignTCGCSRIDevID_IAKWebAuthnProfile is the same proof as
// TestIssueAKCertificate_WebAuthnProfile for the IAK certificate issued by
// the production TCG-CSR-IDEVID enrollment path (SignTCGCSRIDevID), which is
// what a real device's "xkey tpm iak csr" flow drives.
func TestSignTCGCSRIDevID_IAKWebAuthnProfile(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, _, iakDER, _ := enrollSoftwareDevice(t, ca, softwareCSRModel, "SN-715")

	iakCert, err := x509.ParseCertificate(iakDER)
	if err != nil {
		t.Fatalf("failed to parse issued IAK certificate: %v", err)
	}

	found := false
	for _, oid := range iakCert.UnknownExtKeyUsage {
		if oid.Equal(OIDTCGKpAIKCertificate) {
			found = true
			break
		}
	}
	if !found {
		t.Error("IAK certificate UnknownExtKeyUsage does not carry tcg-kp-AIKCertificate")
	}

	if !iakCert.BasicConstraintsValid {
		t.Error("IAK certificate must assert a Basic Constraints extension (WebAuthn L2 §8.3.1 requirement 5)")
	}
	if iakCert.IsCA {
		t.Error("IAK certificate Basic Constraints must have CA:false")
	}

	if !decodeEKULikeGoWebAuthn(t, iakCert, OIDTCGKpAIKCertificate) {
		t.Error("tcg-kp-AIKCertificate not found when the ExtKeyUsage extension is decoded the way go-webauthn decodes it")
	}
	constraints := decodeBasicConstraintsLikeGoWebAuthn(t, iakCert)
	if constraints.IsCA {
		t.Error("go-webauthn's own BasicConstraints decode reports IsCA true; requirement 5 would fail")
	}
}
