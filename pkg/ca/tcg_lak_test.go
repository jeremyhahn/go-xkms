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

// These tests drive IssueLAKCertificate -- the WebAuthn Level 2 §8.3.1
// profile certificate go-xkms#715 issues for a Local Attestation Key -- with
// a TPM2_Certify evidence structure assembled entirely in software, the same
// strategy tcg_iak_certstore_test.go uses for SignTCGCSRIDevID. The IAK
// certificate the evidence is checked against is issued through the real
// IssueAKCertificate path, so the LAK tests exercise production EKU and
// chain-verification logic, not a hand-built stand-in.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	gotpm "github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
)

// lakFixturePublicArea encodes an ECDSA P-256 public key as a minimal
// TPMT_PUBLIC, sufficient for VerifyCertifyByCertificate's Name computation.
// Unlike eccPublicArea (tcg_iak_certstore_test.go) it carries no TCG DevID Key
// Policy: the LAK is an ordinary Platform-SRK child key, not a DevID key, and
// the CA's LAK verification path never builds a DevID admin-policy session
// against it.
func lakFixturePublicArea(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	uncompressed, err := pub.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	coordLen := (len(uncompressed) - 1) / 2
	area := gotpm.TPMTPublic{
		Type:    gotpm.TPMAlgECC,
		NameAlg: gotpm.TPMAlgSHA256,
		ObjectAttributes: gotpm.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
			Restricted:          true,
		},
		Parameters: gotpm.NewTPMUPublicParms(gotpm.TPMAlgECC, &gotpm.TPMSECCParms{
			CurveID: gotpm.TPMECCNistP256,
			Scheme: gotpm.TPMTECCScheme{
				Scheme: gotpm.TPMAlgECDSA,
				Details: gotpm.NewTPMUAsymScheme(gotpm.TPMAlgECDSA,
					&gotpm.TPMSSigSchemeECDSA{HashAlg: gotpm.TPMAlgSHA256}),
			},
		}),
		Unique: gotpm.NewTPMUPublicID(gotpm.TPMAlgECC, &gotpm.TPMSECCPoint{
			X: gotpm.TPM2BECCParameter{Buffer: uncompressed[1 : 1+coordLen]},
			Y: gotpm.TPM2BECCParameter{Buffer: uncompressed[1+coordLen:]},
		}),
	}
	return gotpm.Marshal(area)
}

// buildLAKCertifyEvidence produces the TPM2_Certify attestation of a LAK
// public area, signed by iakKey, in the ASN.1 DER form
// pkg/tpm2.CertifyResult.Signature and VerifyCertifyByCertificate both use
// for ECDSA (unlike the raw r||s form a TCG-CSR-IDEVID carries).
func buildLAKCertifyEvidence(t *testing.T, iakKey *ecdsa.PrivateKey, lakPubArea, nonce []byte) (certifyInfo, signature []byte) {
	t.Helper()
	subject, err := gotpm.Unmarshal[gotpm.TPMTPublic](lakPubArea)
	if err != nil {
		t.Fatalf("unmarshal lak public area: %v", err)
	}
	name, err := gotpm.ObjectName(subject)
	if err != nil {
		t.Fatalf("compute lak name: %v", err)
	}
	attest := gotpm.TPMSAttest{
		Magic:     gotpm.TPMGeneratedValue,
		Type:      gotpm.TPMSTAttestCertify,
		ExtraData: gotpm.TPM2BData{Buffer: nonce},
		Attested: gotpm.NewTPMUAttest(gotpm.TPMSTAttestCertify, &gotpm.TPMSCertifyInfo{
			Name:          *name,
			QualifiedName: *name,
		}),
	}
	certifyInfo = gotpm.Marshal(attest)
	digest := sha256.Sum256(certifyInfo)
	signature, err = ecdsa.SignASN1(rand.Reader, iakKey, digest[:])
	if err != nil {
		t.Fatalf("sign certify info: %v", err)
	}
	return certifyInfo, signature
}

// issueTestIAKCertificate issues an IAK certificate through the production
// IssueAKCertificate path: a real EKU-bearing, chain-verifiable fixture
// rather than a hand-assembled one.
func issueTestIAKCertificate(t *testing.T, ca *CA, signerKey crypto.Signer, issuerCert *x509.Certificate, iakKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	request := createTestCertRequest(t, signerKey, issuerCert)
	request.Subject.CommonName = "iak-lak-fixture"
	cert, err := ca.IssueAKCertificate(context.Background(), request, iakKey.Public())
	if err != nil {
		t.Fatalf("IssueAKCertificate() for IAK fixture: %v", err)
	}
	return cert
}

// lakTestRequest builds a CertificateRequest carrying the TPM device
// attributes IssueLAKCertificate requires.
func lakTestRequest(t *testing.T, signerKey crypto.Signer, issuerCert *x509.Certificate) *CertificateRequest {
	t.Helper()
	request := createTestCertRequest(t, signerKey, issuerCert)
	request.TPMManufacturer = "id:49465800"
	request.TPMModel = "NPCT6xx"
	request.TPMFirmwareVersion = "7.2.3.1"
	return request
}

// =============================================================================
// IssueLAKCertificate: success and profile shape
// =============================================================================

func TestIssueLAKCertificate_WebAuthnProfile(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	iakCert := issueTestIAKCertificate(t, ca, signerKey, issuerCert, iakKey)

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate lak key: %v", err)
	}
	lakPubArea := lakFixturePublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificate_WebAuthnProfile")
	certifyInfo, sig := buildLAKCertifyEvidence(t, iakKey, lakPubArea, nonce)

	request := lakTestRequest(t, signerKey, issuerCert)
	evidence := &LAKCertificationEvidence{
		CertifyInfo:        certifyInfo,
		Signature:          sig,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IAKCertificate:     iakCert,
		LAKPublicArea:      lakPubArea,
		Nonce:              nonce,
	}

	cert, err := ca.IssueLAKCertificate(context.Background(), request, evidence)
	if err != nil {
		t.Fatalf("IssueLAKCertificate() returned unexpected error: %v", err)
	}

	// Requirement 2: empty Subject.
	if cert.Subject.String() != "" {
		t.Errorf("LAK Subject = %q, want empty", cert.Subject.String())
	}

	// Requirement 3: critical subjectAltName carrying the TCG device triple.
	foundSAN := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltNameExt) {
			foundSAN = true
			if !ext.Critical {
				t.Error("LAK subjectAltName extension must be critical when the Subject is empty")
			}
		}
	}
	if !foundSAN {
		t.Fatal("LAK certificate carries no subjectAltName extension")
	}
	others, err := ParseOtherNames(cert.Extensions)
	if err != nil {
		t.Fatalf("ParseOtherNames() error: %v", err)
	}
	if len(others) != 0 {
		t.Errorf("LAK subjectAltName carries %d otherName(s), want 0 (only directoryName)", len(others))
	}

	// Requirement 4: tcg-kp-AIKCertificate EKU.
	if !hasEKUOID(cert, OIDTCGKpAIKCertificate) {
		t.Error("LAK certificate UnknownExtKeyUsage does not carry tcg-kp-AIKCertificate")
	}

	// Requirement 5: Basic Constraints CA:false.
	if !cert.BasicConstraintsValid {
		t.Error("LAK certificate must assert a Basic Constraints extension")
	}
	if cert.IsCA {
		t.Error("LAK certificate Basic Constraints must have CA:false")
	}

	// The certified key is the LAK's, not the IAK's.
	lakPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !lakPub.Equal(&lakKey.PublicKey) {
		t.Error("LAK certificate does not certify the LAK public key")
	}

	// Stored and retrievable by its SPKI thumbprint, since it has no CN.
	stored, err := ca.certStore.GetCertificate(certstore.CertificateKey(cert))
	if err != nil {
		t.Fatalf("LAK certificate not retrievable from the store: %v", err)
	}
	if string(stored.Raw) != string(cert.Raw) {
		t.Error("stored LAK record differs from the certificate returned to the caller")
	}
}

func TestIssueLAKCertificate_EKUDecodesLikeGoWebAuthn(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	iakCert := issueTestIAKCertificate(t, ca, signerKey, issuerCert, iakKey)

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate lak key: %v", err)
	}
	lakPubArea := lakFixturePublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificate_EKUDecodesLikeGoWebAuthn")
	certifyInfo, sig := buildLAKCertifyEvidence(t, iakKey, lakPubArea, nonce)

	request := lakTestRequest(t, signerKey, issuerCert)
	cert, err := ca.IssueLAKCertificate(context.Background(), request, &LAKCertificationEvidence{
		CertifyInfo:        certifyInfo,
		Signature:          sig,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IAKCertificate:     iakCert,
		LAKPublicArea:      lakPubArea,
		Nonce:              nonce,
	})
	if err != nil {
		t.Fatalf("IssueLAKCertificate() returned unexpected error: %v", err)
	}

	if !decodeEKULikeGoWebAuthn(t, cert, OIDTCGKpAIKCertificate) {
		t.Error("tcg-kp-AIKCertificate not found when the ExtKeyUsage extension is decoded the way go-webauthn decodes it")
	}
	constraints := decodeBasicConstraintsLikeGoWebAuthn(t, cert)
	if constraints.IsCA {
		t.Error("go-webauthn's own BasicConstraints decode reports IsCA true; requirement 5 would fail")
	}
}

// =============================================================================
// IssueLAKCertificate: failure cases
// =============================================================================

func TestIssueLAKCertificate_NotInitialized(t *testing.T) {
	ca := createUninitializedTestCA(t)
	_, err := ca.IssueLAKCertificate(context.Background(), &CertificateRequest{}, &LAKCertificationEvidence{IAKCertificate: &x509.Certificate{}})
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("error = %v, want ErrNotInitialized", err)
	}
}

func TestIssueLAKCertificate_NilEvidence(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, err := ca.IssueLAKCertificate(context.Background(), &CertificateRequest{}, nil)
	if !errors.Is(err, ErrTCGLAKEvidenceRequired) {
		t.Fatalf("error = %v, want ErrTCGLAKEvidenceRequired", err)
	}
}

func TestIssueLAKCertificate_NilIAKCertificate(t *testing.T) {
	ca := createTestCAForTCG(t)
	_, err := ca.IssueLAKCertificate(context.Background(), &CertificateRequest{}, &LAKCertificationEvidence{})
	if !errors.Is(err, ErrTCGLAKEvidenceRequired) {
		t.Fatalf("error = %v, want ErrTCGLAKEvidenceRequired", err)
	}
}

func TestIssueLAKCertificate_MissingDeviceAttributes(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)
	request := createTestCertRequest(t, signerKey, issuerCert) // no TPM* fields set

	_, err := ca.IssueLAKCertificate(context.Background(), request, &LAKCertificationEvidence{
		IAKCertificate: issuerCert,
	})
	if !errors.Is(err, ErrTCGLAKDeviceAttributesRequired) {
		t.Fatalf("error = %v, want ErrTCGLAKDeviceAttributesRequired", err)
	}
}

// TestIssueLAKCertificate_TamperedCertifyInfo proves a certifyInfo byte
// flipped after signing is refused: the signature no longer verifies over the
// tampered bytes.
func TestIssueLAKCertificate_TamperedCertifyInfo(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	iakCert := issueTestIAKCertificate(t, ca, signerKey, issuerCert, iakKey)

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate lak key: %v", err)
	}
	lakPubArea := lakFixturePublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificate_TamperedCertifyInfo")
	certifyInfo, sig := buildLAKCertifyEvidence(t, iakKey, lakPubArea, nonce)

	// Flip a byte well inside the structure (past the fixed TPM_GENERATED
	// magic) so the signature check -- not an earlier parse failure -- is
	// what refuses this.
	tampered := append([]byte(nil), certifyInfo...)
	tampered[len(tampered)-1] ^= 0xFF

	request := lakTestRequest(t, signerKey, issuerCert)
	_, err = ca.IssueLAKCertificate(context.Background(), request, &LAKCertificationEvidence{
		CertifyInfo:        tampered,
		Signature:          sig,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IAKCertificate:     iakCert,
		LAKPublicArea:      lakPubArea,
		Nonce:              nonce,
	})
	if !errors.Is(err, ErrTCGCSRVerificationFailed) {
		t.Fatalf("error = %v, want ErrTCGCSRVerificationFailed", err)
	}
}

// TestIssueLAKCertificate_WrongIAK proves evidence signed by an IAK other
// than the one presented is refused: the signature does not verify under the
// presented certificate's public key.
func TestIssueLAKCertificate_WrongIAK(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	iakCert := issueTestIAKCertificate(t, ca, signerKey, issuerCert, iakKey)

	// A second, otherwise identically-issued IAK whose key signs the
	// evidence instead of the one in the certificate presented.
	otherIAKKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other iak key: %v", err)
	}

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate lak key: %v", err)
	}
	lakPubArea := lakFixturePublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificate_WrongIAK")
	certifyInfo, sig := buildLAKCertifyEvidence(t, otherIAKKey, lakPubArea, nonce)

	request := lakTestRequest(t, signerKey, issuerCert)
	_, err = ca.IssueLAKCertificate(context.Background(), request, &LAKCertificationEvidence{
		CertifyInfo:        certifyInfo,
		Signature:          sig,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IAKCertificate:     iakCert,
		LAKPublicArea:      lakPubArea,
		Nonce:              nonce,
	})
	if !errors.Is(err, ErrTCGCSRVerificationFailed) {
		t.Fatalf("error = %v, want ErrTCGCSRVerificationFailed", err)
	}
}

// TestIssueLAKCertificate_IAKNotTrusted proves an IAK certificate that was
// not issued by the certificate about to sign the LAK -- a self-signed
// certificate over the same IAK key, say -- is refused.
func TestIssueLAKCertificate_IAKNotTrusted(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	// Issued by a different, unrelated CA than the one about to sign the LAK.
	untrustedSignerKey := generateTestECDSAKey(t)
	untrustedIssuerCert := createSelfSignedCACert(t, untrustedSignerKey)
	untrustedIAKCert := issueTestIAKCertificate(t, ca, untrustedSignerKey, untrustedIssuerCert, iakKey)

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate lak key: %v", err)
	}
	lakPubArea := lakFixturePublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificate_IAKNotTrusted")
	certifyInfo, sig := buildLAKCertifyEvidence(t, iakKey, lakPubArea, nonce)

	request := lakTestRequest(t, signerKey, issuerCert)
	_, err = ca.IssueLAKCertificate(context.Background(), request, &LAKCertificationEvidence{
		CertifyInfo:        certifyInfo,
		Signature:          sig,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IAKCertificate:     untrustedIAKCert,
		LAKPublicArea:      lakPubArea,
		Nonce:              nonce,
	})
	if !errors.Is(err, ErrTCGIAKUntrusted) {
		t.Fatalf("error = %v, want ErrTCGIAKUntrusted", err)
	}
}

// TestIssueLAKCertificate_NonEmptySubjectRefusedByVerifier proves a relying
// party's own verifier -- not just the CA -- refuses a certificate whose
// Subject is not empty. decodeEKULikeGoWebAuthn's sibling checks reproduce
// go-webauthn's "tpm" attestation format decode; this test is the Subject
// counterpart, pinning requirement 2 the way go-webauthn's
// aikCert.Subject.String() != "" check reads it. IssueLAKCertificate itself
// never produces a non-empty Subject (CertificateSpec.Subject is always
// pkix.Name{}), so the non-empty certificate here is the IAK's own TCG
// DevID-shaped certificate -- proof that it, unlike the LAK, would fail a
// strict relying party's requirement 2 and is why go-xkms#715 issues a
// separate LAK rather than reusing the IAK certificate for WebAuthn.
func TestIssueLAKCertificate_NonEmptySubjectRefusedByVerifier(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	iakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate iak key: %v", err)
	}
	iakCert := issueTestIAKCertificate(t, ca, signerKey, issuerCert, iakKey)
	// This is the WebAuthn L2 §8.3.1 requirement 2 check, reproduced exactly
	// as go-webauthn's attestation_tpm.go applies it
	// (aikCert.Subject.String() != ""): a strict verifier would refuse the
	// IAK's own TCG DevID-shaped certificate outright, which is why
	// go-xkms#715 issues a separate LAK rather than reusing it.
	if iakCert.Subject.String() == "" {
		t.Fatal("fixture IAK certificate unexpectedly has an empty Subject; it must carry a TCG DevID Subject for this test to be meaningful")
	}

	lakKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate lak key: %v", err)
	}
	lakPubArea := lakFixturePublicArea(t, &lakKey.PublicKey)
	nonce := []byte("nonce-TestIssueLAKCertificate_NonEmptySubjectRefusedByVerifier")
	certifyInfo, sig := buildLAKCertifyEvidence(t, iakKey, lakPubArea, nonce)

	request := lakTestRequest(t, signerKey, issuerCert)
	cert, err := ca.IssueLAKCertificate(context.Background(), request, &LAKCertificationEvidence{
		CertifyInfo:        certifyInfo,
		Signature:          sig,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IAKCertificate:     iakCert,
		LAKPublicArea:      lakPubArea,
		Nonce:              nonce,
	})
	if err != nil {
		t.Fatalf("IssueLAKCertificate() returned unexpected error: %v", err)
	}
	if cert.Subject.String() != "" {
		t.Fatalf("LAK certificate Subject = %q, want empty: a strict WebAuthn verifier would refuse it", cert.Subject.String())
	}
}

func TestIssueLAKCertificate_InvalidTPMManufacturerCode(t *testing.T) {
	ca := createTestCAForTCG(t)
	signerKey := generateTestECDSAKey(t)
	issuerCert := createSelfSignedCACert(t, signerKey)

	request := lakTestRequest(t, signerKey, issuerCert)
	request.TPMManufacturer = "not-a-tcg-code"

	_, err := ca.IssueLAKCertificate(context.Background(), request, &LAKCertificationEvidence{
		IAKCertificate: issuerCert,
	})
	if !errors.Is(err, ErrTCGInvalidManufacturerCode) {
		t.Fatalf("error = %v, want ErrTCGInvalidManufacturerCode", err)
	}
}

func TestIssueLAKCertificate_SatisfiesTCGCAInterface(t *testing.T) {
	var tcgCA TCGCA = createTestCAForTCG(t)
	_, err := tcgCA.IssueLAKCertificate(context.Background(), &CertificateRequest{}, nil)
	if !errors.Is(err, ErrTCGLAKEvidenceRequired) {
		t.Fatalf("error = %v, want ErrTCGLAKEvidenceRequired through the interface", err)
	}
}
