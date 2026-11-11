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
	"crypto/ed25519"
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
	challengemsg "github.com/jeremyhahn/go-xkms/pkg/factor/internal/challenge"
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

// The DSA domain parameters (P, Q, G) and public value Y below are a fixed
// test vector, generated once offline with dsa.GenerateParameters
// (L1024N160) and dsa.GenerateKey. The tests only need a certificate whose
// SubjectPublicKeyInfo carries a DSA key, so fixed values keep them running
// under GODEBUG=fips140=only, where crypto/dsa refuses to generate keys.
const (
	dsaTestP = "97101b0525bd252815aed72e87710a32cc9c8988d41ce99fa52f2d645c965e881d8a6f459a60acd02b7898cdf19eb2cb0fb7b81ec0258e82f760593bd74d834c3c38ebdf3c6d48b393b3a0f2de2c735f3c677f77ab74cadf21250b69939c76a0550a89f0dee0a07bb136d1d4f121cd61fc1b946a72f1facabed5a88c4cdb2cdb"
	dsaTestQ = "a904c9be0baec888b3642ca799061f77233c581f"
	dsaTestG = "46aafba87c9f48d063bd9d2fdae02053494b1ffb9765388466453dea86d50e12cad4e74e1499eb7a15a8c3832fb4d791584beb19bbd88008a1df0c15de66391149ef7de2746a43309b01332b0fd5c0352fd515817e39dd637340976042853da88d8b170c1a0e64167a1518e16b5726f0673513d76d80f42ee20052d03c9c1706"
	dsaTestY = "110faa7f86617005f34becb972df32bbb55b2685f231339f1c655b2c819df44934f5278aab14743eca4ac5f4ecd89bcec3a801921971885e4970215eacce22d16ca453f5b86637a3e044e423b97a51f2a49e5c6041edd30de30cbbcf99bb539f89ceb98e26e9266b55b2e05ecb2bfdcc55136865c01c1d4677d4fb8e106efc33"
)

// hexInt parses a hex constant of the DSA test vector.
func hexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("parse hex integer %q", s)
	}
	return n
}

// dsaCertPEM hand-builds a PEM CERTIFICATE block whose SubjectPublicKeyInfo
// carries the fixed DSA test public key — a type parseCertPEM/x509.ParseCertificate
// will happily parse, but that the mtls Factor does not support for signing.
func dsaCertPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()

	dsaParamsDER, err := asn1.Marshal(struct{ P, Q, G *big.Int }{
		hexInt(t, dsaTestP), hexInt(t, dsaTestQ), hexInt(t, dsaTestG),
	})
	if err != nil {
		t.Fatalf("marshal dsa params: %v", err)
	}
	yDER, err := asn1.Marshal(hexInt(t, dsaTestY))
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

	return string(pemEncodeCertificate(certDER))
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
	certPEM := dsaCertPEM(t, time.Now().Add(24*time.Hour))

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
	certPEM := dsaCertPEM(t, time.Now().Add(24*time.Hour))
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
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: otherKP.sign(challengemsg.Message(challenge))}); !errors.As(err, &failed) {
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
	wrongSig := ed25519.Sign(wrongPriv, challengemsg.Message(challenge))

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
