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

package mtls

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // deprecated package used only to build an
	// "unsupported public key type" certificate for negative-path testing.
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// ---------------------------------------------------------------------------
// DSA certificate helper — DSA is the one x509-parseable public key type that
// is NOT ECDSA/RSA/Ed25519, so it is the tool for exercising the "unsupported
// public key type" branches in validatePublicKeyType and Verify's type
// switch. crypto/x509.CreateCertificate refuses to embed a *dsa.PublicKey
// (it rejects the SPKI at creation time), so the certificate DER is built by
// hand with encoding/asn1 and fed straight to parseCertPEM/x509.ParseCertificate,
// which — unlike CreateCertificate — still parses legacy DSA SubjectPublicKeyInfo
// records. The signature bytes are never verified by ParseCertificate, so an
// arbitrary placeholder is sufficient.
// ---------------------------------------------------------------------------

type asn1AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type asn1SubjectPublicKeyInfo struct {
	Algorithm asn1AlgorithmIdentifier
	PublicKey asn1.BitString
}

type asn1TBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm asn1AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           struct{ NotBefore, NotAfter time.Time }
	Subject            asn1.RawValue
	PublicKey          asn1SubjectPublicKeyInfo
}

type asn1Certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm asn1AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

var (
	oidPublicKeyDSA           = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidSignatureSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// generateDSAKey generates a DSA key pair for a test that needs one to
// exercise the mtls Factor's rejection of an unsupported public key type,
// and reports whether the caller can continue using it. DSA is refused
// outright under GODEBUG=fips140=only (crypto/dsa is not part of the Go
// Cryptographic Module), so this asserts that refusal and reports ok=false
// instead of letting the caller dereference a zero-value key -- the
// rejection this package's own tests exist to prove happens one layer up,
// inside crypto/dsa, in that mode.
func generateDSAKey(t *testing.T) (dsa.PrivateKey, bool) {
	t.Helper()
	var params dsa.Parameters
	err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
	if err != nil {
		if fips140.Enforced() {
			return dsa.PrivateKey{}, false
		}
		t.Fatalf("dsa.GenerateParameters: %v", err)
	}
	var priv dsa.PrivateKey
	priv.Parameters = params
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil {
		t.Fatalf("dsa.GenerateKey: %v", err)
	}
	return priv, true
}

// dsaCertPEM hand-builds a PEM CERTIFICATE block whose SubjectPublicKeyInfo
// carries a DSA public key — a type parseCertPEM/x509.ParseCertificate will
// happily parse, but that the mtls Factor does not support for signing. The
// bool return is false when DSA key generation was refused for the expected
// GODEBUG=fips140=only reason (see generateDSAKey); the caller must return
// immediately in that case.
func dsaCertPEM(t *testing.T, notAfter time.Time) (string, bool) {
	t.Helper()

	priv, ok := generateDSAKey(t)
	if !ok {
		return "", false
	}
	params := priv.Parameters

	dsaParamsDER, err := asn1.Marshal(struct{ P, Q, G *big.Int }{params.P, params.Q, params.G})
	if err != nil {
		t.Fatalf("marshal dsa params: %v", err)
	}
	yDER, err := asn1.Marshal(priv.Y)
	if err != nil {
		t.Fatalf("marshal dsa Y: %v", err)
	}

	name := pkix.Name{CommonName: "dsa-cert-test"}
	nameDER, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		t.Fatalf("marshal name: %v", err)
	}

	tbs := asn1TBSCertificate{
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: asn1AlgorithmIdentifier{Algorithm: oidSignatureSHA256WithRSA},
		Issuer:             asn1.RawValue{FullBytes: nameDER},
		Validity: struct{ NotBefore, NotAfter time.Time }{
			NotBefore: time.Now().UTC().Add(-time.Hour),
			NotAfter:  notAfter.UTC(),
		},
		Subject: asn1.RawValue{FullBytes: nameDER},
		PublicKey: asn1SubjectPublicKeyInfo{
			Algorithm: asn1AlgorithmIdentifier{
				Algorithm:  oidPublicKeyDSA,
				Parameters: asn1.RawValue{FullBytes: dsaParamsDER},
			},
			PublicKey: asn1.BitString{Bytes: yDER, BitLength: len(yDER) * 8},
		},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshal tbsCertificate: %v", err)
	}

	cert := asn1Certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: asn1AlgorithmIdentifier{Algorithm: oidSignatureSHA256WithRSA},
		SignatureValue:     asn1.BitString{Bytes: []byte{0x00, 0x01, 0x02, 0x03}, BitLength: 32},
	}
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}

	return string(pemEncodeCertificate(certDER)), true
}

// pemEncodeCertificate wraps raw DER bytes in a PEM CERTIFICATE block.
func pemEncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ---------------------------------------------------------------------------
// Enroll — unsupported public key type
// ---------------------------------------------------------------------------

// TestMTLSFactor_Enroll_RejectsUnsupportedPublicKeyType verifies that Enroll
// rejects a structurally valid certificate whose public key is not one of
// ECDSA/RSA/Ed25519 (validatePublicKeyType's default branch).
func TestMTLSFactor_Enroll_RejectsUnsupportedPublicKeyType(t *testing.T) {
	certPEM, ok := dsaCertPEM(t, time.Now().Add(24*time.Hour))
	if !ok {
		return
	}

	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": certPEM},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(dsa cert) err = %v, want EnrollmentInvalidError", err)
	}
}

// ---------------------------------------------------------------------------
// validatePublicKeyType — direct unit coverage
// ---------------------------------------------------------------------------

// TestValidatePublicKeyType_RejectsDSA verifies validatePublicKeyType directly
// rejects a DSA public key, independent of the Enroll call path.
func TestValidatePublicKeyType_RejectsDSA(t *testing.T) {
	priv, ok := generateDSAKey(t)
	if !ok {
		return
	}

	if err := validatePublicKeyType(&priv.PublicKey); err == nil {
		t.Fatal("validatePublicKeyType(dsa pubkey) = nil, want error")
	}
}

// TestValidatePublicKeyType_AcceptsSupportedTypes verifies the accept path
// for all three supported public key types.
func TestValidatePublicKeyType_AcceptsSupportedTypes(t *testing.T) {
	ecKP := ecdsaKeyPair(t, time.Now().Add(time.Hour))
	rsaKP := rsaKeyPair(t, time.Now().Add(time.Hour))
	edKP := ed25519KeyPair(t, time.Now().Add(time.Hour))

	for name, certPEM := range map[string]string{"ecdsa": ecKP.certPEM, "rsa": rsaKP.certPEM, "ed25519": edKP.certPEM} {
		cert, err := parseCertPEM([]byte(certPEM))
		if err != nil {
			t.Fatalf("%s: parseCertPEM: %v", name, err)
		}
		if err := validatePublicKeyType(cert.PublicKey); err != nil {
			t.Fatalf("%s: validatePublicKeyType = %v, want nil", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Verify — unsupported public key type (bypasses Enroll's own validation by
// injecting the DSA cert directly into challenge.MethodData, exactly as a
// tampered or legacy-enrolled record would appear to Verify).
// ---------------------------------------------------------------------------

// TestMTLSFactor_Verify_RejectsUnsupportedPublicKeyType verifies that Verify's
// algorithm type switch falls through to the default "unsupported public key
// type" branch when the enrolled certificate carries a DSA key.
func TestMTLSFactor_Verify_RejectsUnsupportedPublicKeyType(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	certPEM, ok := dsaCertPEM(t, time.Now().Add(24*time.Hour))
	if !ok {
		return
	}
	cert, err := parseCertPEM([]byte(certPEM))
	if err != nil {
		t.Fatalf("parseCertPEM(dsa cert): %v", err)
	}

	challenge := &qrdbsdk.AuthFactorChallenge{
		ChallengeID: "chal-1",
		Nonce:       []byte("0123456789012345678901234567890"),
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
		MethodData: map[string]any{
			methodDataEnrolledKey: base64.StdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo),
		},
	}

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: []byte("irrelevant")})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(dsa cert) err = %v, want VerificationFailedError", err)
	}
}

// ---------------------------------------------------------------------------
// Verify — RSA / Ed25519 wrong-signature rejection (mirrors the existing
// ECDSA TestMTLSFactor_Verify_RejectsWrongSignature so all three algorithms
// have an explicit invalid-signature regression test).
// ---------------------------------------------------------------------------

// TestMTLSFactor_Verify_RSA_RejectsWrongSignature verifies that an RSA
// signature which fails PKCS#1 v1.5 verification is rejected.
func TestMTLSFactor_Verify_RSA_RejectsWrongSignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := rsaKeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	// A well-formed but wrong RSA signature (signed with a different key).
	otherKP := rsaKeyPair(t, time.Now().Add(24*time.Hour))

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: otherKP.sign(challenge.Nonce)}); !errors.As(err, &failed) {
		t.Fatalf("Verify(rsa wrong key) err = %v, want VerificationFailedError", err)
	}
}

// TestMTLSFactor_Verify_Ed25519_RejectsWrongSignature verifies that an
// Ed25519 signature produced by the wrong key is rejected.
func TestMTLSFactor_Verify_Ed25519_RejectsWrongSignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := ed25519KeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	wrongSig := ed25519.Sign(wrongPriv, challenge.Nonce)

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: wrongSig}); !errors.As(err, &failed) {
		t.Fatalf("Verify(ed25519 wrong key) err = %v, want VerificationFailedError", err)
	}
}

// ---------------------------------------------------------------------------
// parseCertPEM — structurally valid PEM/base64 but malformed DER, distinct
// from the existing "no PEM block" and "wrong block type" cases.
// ---------------------------------------------------------------------------

// TestParseCertPEM_RejectsMalformedDER verifies that a syntactically valid
// PEM CERTIFICATE block whose payload is not valid ASN.1 DER surfaces the
// underlying x509.ParseCertificate error.
func TestParseCertPEM_RejectsMalformedDER(t *testing.T) {
	data := pemEncodeCertificate([]byte{0x00, 0x01, 0x02, 0x03})
	if _, err := parseCertPEM(data); err == nil {
		t.Fatal("expected error for malformed certificate DER")
	}
}

// ---------------------------------------------------------------------------
// RSA/Ed25519 stray-signature parity: exercise rsa.VerifyPKCS1v15's own
// error path with a structurally invalid (too-short) signature, mirroring
// TestVerifyECDSA_RejectsGarbageASN1's coverage of the ECDSA helper.
// ---------------------------------------------------------------------------

// TestMTLSFactor_Verify_RSA_RejectsGarbageSignature verifies that a
// structurally invalid (non-modulus-length) RSA signature is rejected via
// the rsa.VerifyPKCS1v15 error path rather than panicking.
func TestMTLSFactor_Verify_RSA_RejectsGarbageSignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	kp := rsaKeyPair(t, time.Now().Add(24*time.Hour))

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"cert_pem": kp.certPEM},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: []byte("short")}); !errors.As(err, &failed) {
		t.Fatalf("Verify(rsa garbage sig) err = %v, want VerificationFailedError", err)
	}
}
