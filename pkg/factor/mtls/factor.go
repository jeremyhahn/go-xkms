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

// Package mtls exposes a qrdbsdk.AuthFactorPlugin adapter for mTLS
// certificate-key possession proofs used in custodian enrollment and
// Shamir-unseal ceremonies. It implements qrdb's qrdbsdk.AuthFactorPlugin
// interface (Enroll, Challenge, Verify) by binding a PEM certificate to an
// enrollment and verifying that the respondent possesses the corresponding
// private key via a signature over a random nonce.
//
// Enrollment requires MethodParams["cert_pem"] containing a PEM CERTIFICATE
// block. The certificate PEM bytes are stored as Enrollment.PublicKey.
// Metadata records cert_cn, cert_serial, cert_not_before, cert_not_after
// (RFC 3339), cert_spki_thumbprint (the qrdb canonical SPKI SHA-256
// thumbprint), and ttl. These metadata keys match the names produced by
// xkmsctl's xkmsLoadCertCredentialAndMetadata, so client and server share one
// naming convention.
//
// Challenge issues a 32-byte crypto/rand nonce and embeds the enrolled
// certificate's public key (standard base64 PKIX DER) in
// MethodData["enrolled_public_key_der"] so that Verify can authenticate
// against the server-issued (not response-supplied) key. The certificate
// itself is never exposed: its issuer signature would tell a real holder
// from a decoy enrollment.
//
// Verify reads the enrolled key from challenge.MethodData
// ["enrolled_public_key_der"] — never from the response — and checks that
// response.Value is a valid signature over the nonce. ECDSA (ASN.1 DER,
// SHA-256 digest), RSA PKCS#1 v1.5 (SHA-256 digest), and Ed25519 (raw nonce)
// are all supported.
//
// Usage:
//
//	f := mtls.New(mtls.Config{})
//	registry.Register(f)
package mtls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strconv"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// FactorName is the canonical Factor.Name() return value for mTLS.
const FactorName = "mtls"

const (
	defaultChallengeTTLSeconds = 5 * 60
	nonceLength                = 32

	// methodDataEnrolledKey is the challenge MethodData key carrying the
	// enrolled certificate's PKIX public key, standard-base64 DER. Verify
	// reads the verification key from here and nowhere else, so a response
	// can never substitute its own key.
	methodDataEnrolledKey = "enrolled_public_key_der"
)

// Config configures an mTLS Factor. The zero value is valid.
type Config struct {
	// ChallengeTTLSeconds controls how long issued challenges remain valid.
	// Zero defaults to 300 (five minutes).
	ChallengeTTLSeconds int
}

// Factor implements qrdbsdk.AuthFactorPlugin for mTLS certificate-key
// possession proofs. Any X.509 certificate whose public key is ECDSA, RSA,
// or Ed25519 can be enrolled; no CA chain validation is performed (possession
// of the private key is the credential, not chain trust).
type Factor struct {
	cfg Config
}

// New constructs an mTLS Factor, applying canonical defaults.
func New(cfg Config) *Factor {
	if cfg.ChallengeTTLSeconds <= 0 {
		cfg.ChallengeTTLSeconds = defaultChallengeTTLSeconds
	}
	return &Factor{cfg: cfg}
}

// Name returns the canonical mTLS factor identifier "mtls".
func (f *Factor) Name() string { return FactorName }

// Enroll records the public credential from a PEM certificate. MethodParams
// accepts:
//
//	"cert_pem" string  PEM CERTIFICATE block (required)
//
// The enrollment stores the PEM bytes as PublicKey and records cert_cn,
// cert_serial, cert_not_before, cert_not_after (RFC 3339),
// cert_spki_thumbprint, and ttl in Metadata. The certificate must not be
// expired at enrollment time.
func (f *Factor) Enroll(_ context.Context, params *qrdbsdk.AuthFactorEnrollParams) (*qrdbsdk.AuthFactorEnrollment, error) {
	if params == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "params must not be nil"}
	}

	certPEM := stringParam(params.MethodParams["cert_pem"])
	if certPEM == "" {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "mtls: cert_pem is required"}
	}

	cert, err := parseCertPEM([]byte(certPEM))
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "mtls: " + err.Error()}
	}

	if time.Now().UTC().After(cert.NotAfter) {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{
			Reason: "mtls: certificate has expired (NotAfter " + cert.NotAfter.UTC().Format(time.RFC3339) + ")",
		}
	}

	// Validate the public key type is supported so that invalid material is
	// rejected at enrollment, not at verify time.
	if err := validatePublicKeyType(cert.PublicKey); err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "mtls: " + err.Error()}
	}

	thumbprint := qrdbsdk.ComputeSPKIThumbprint(cert)

	return &qrdbsdk.AuthFactorEnrollment{
		EnrollmentID: qrdbsdk.NewAuthFactorEnrollmentID(),
		UserID:       params.UserID,
		FactorName:   FactorName,
		TenantID:     params.TenantID,
		PublicKey:    []byte(certPEM),
		Metadata: map[string]string{
			"cert_cn":              cert.Subject.CommonName,
			"cert_serial":          cert.SerialNumber.String(),
			"cert_not_before":      cert.NotBefore.UTC().Format(time.RFC3339),
			"cert_not_after":       cert.NotAfter.UTC().Format(time.RFC3339),
			"cert_spki_thumbprint": thumbprint,
			"ttl":                  strconv.Itoa(f.cfg.ChallengeTTLSeconds),
		},
		EnrolledAt: time.Now().UTC(),
	}, nil
}

// Challenge produces a 32-byte random nonce the custodian must sign with the
// private key corresponding to their enrolled certificate. The certificate's
// public key is embedded in MethodData["enrolled_public_key_der"] so Verify
// can authenticate against the server-issued key without trusting the
// response. Only the key is exposed, never the certificate: a CA-issued
// certificate's signature verifies under the CA and a decoy's cannot, so
// exposing it would tell holders from decoys.
func (f *Factor) Challenge(_ context.Context, enrollment *qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorChallenge, error) {
	if enrollment == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "enrollment must not be nil"}
	}
	cert, err := parseCertPEM(enrollment.PublicKey)
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{
			EnrollmentID: enrollment.EnrollmentID,
			Reason:       "mtls: enrolled certificate: " + err.Error(),
		}
	}
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{
			EnrollmentID: enrollment.EnrollmentID,
			Reason:       "mtls: nonce rand.Read: " + err.Error(),
		}
	}
	ttl := f.cfg.ChallengeTTLSeconds
	if t, ok := enrollment.Metadata["ttl"]; ok {
		if v, err := strconv.Atoi(t); err == nil && v > 0 {
			ttl = v
		}
	}
	return &qrdbsdk.AuthFactorChallenge{
		ChallengeID:  qrdbsdk.NewAuthFactorChallengeID(),
		EnrollmentID: enrollment.EnrollmentID,
		Nonce:        nonce,
		ExpiresAt:    time.Now().UTC().Add(time.Duration(ttl) * time.Second),
		MethodData: map[string]any{
			methodDataEnrolledKey:  base64.StdEncoding.EncodeToString(cert.RawSubjectPublicKeyInfo),
			"cert_spki_thumbprint": enrollment.Metadata["cert_spki_thumbprint"],
			"cert_cn":              enrollment.Metadata["cert_cn"],
		},
	}, nil
}

// Verify checks that response.Value is a valid signature over the challenge
// nonce, produced by the private key corresponding to the enrolled
// certificate. The enrolled public key is read from
// challenge.MethodData["enrolled_public_key_der"] — never from the response —
// ensuring the key cannot be substituted by an attacker.
//
// Checks in order: challenge expiry, enrolled key decode, then
// algorithm-specific signature verification:
//   - ECDSA: ASN.1 DER (r,s) over SHA-256(nonce)
//   - RSA:   PKCS#1 v1.5 over SHA-256(nonce)
//   - Ed25519: raw signature over the raw nonce
func (f *Factor) Verify(_ context.Context, challenge *qrdbsdk.AuthFactorChallenge, response *qrdbsdk.AuthFactorResponse) error {
	if challenge == nil {
		return &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "challenge must not be nil"}
	}
	if response == nil {
		return &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "response must not be nil"}
	}
	if challenge.Expired() {
		return &qrdbsdk.AuthFactorChallengeExpiredError{ChallengeID: challenge.ChallengeID}
	}

	// Read the enrolled key from the server-issued challenge, not the response.
	encoded, ok := challenge.MethodData[methodDataEnrolledKey].(string)
	if !ok || encoded == "" {
		return &qrdbsdk.AuthFactorVerificationFailedError{
			FactorName: FactorName,
			Reason:     methodDataEnrolledKey + " missing from challenge MethodData",
		}
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "decode " + methodDataEnrolledKey + ": " + err.Error()}
	}
	enrolled, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "parse enrolled public key: " + err.Error()}
	}

	digest := sha256.Sum256(challenge.Nonce)

	switch pub := enrolled.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(pub, digest[:], response.Value)
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], response.Value); err != nil {
			return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "rsa signature invalid: " + err.Error()}
		}
		return nil
	case ed25519.PublicKey:
		// Ed25519 signs the raw nonce (not the SHA-256 digest).
		if !ed25519.Verify(pub, challenge.Nonce, response.Value) {
			return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "ed25519 signature invalid"}
		}
		return nil
	default:
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "unsupported public key type"}
	}
}

// parseCertPEM decodes the first PEM CERTIFICATE block from data and parses
// the X.509 certificate.
func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, &certParseError{reason: "no PEM block found"}
	}
	if block.Type != "CERTIFICATE" {
		return nil, &certParseError{reason: "expected CERTIFICATE PEM block, got " + block.Type}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &certParseError{reason: "x509.ParseCertificate: " + err.Error()}
	}
	return cert, nil
}

// validatePublicKeyType reports an error when the public key type is not
// supported for signing.
func validatePublicKeyType(pub any) error {
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return nil
	default:
		return &certParseError{reason: "unsupported public key type (want ECDSA, RSA, or Ed25519)"}
	}
}

// verifyECDSA verifies an ASN.1 DER (r,s) ECDSA signature over the
// pre-hashed digest.
func verifyECDSA(pub *ecdsa.PublicKey, digest, sig []byte) error {
	var dsaSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &dsaSig); err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "unmarshal ecdsa signature: " + err.Error()}
	}
	if dsaSig.R == nil || dsaSig.S == nil || dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "ecdsa signature contains non-positive component"}
	}
	if !ecdsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "ecdsa signature invalid"}
	}
	return nil
}

// stringParam returns a MethodParams value as a string when it is a string.
func stringParam(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// certParseError is a typed error for malformed or invalid certificate inputs.
type certParseError struct {
	reason string
}

// Error implements the error interface.
func (e *certParseError) Error() string { return e.reason }

// Compile-time interface assertion.
var _ qrdbsdk.AuthFactorPlugin = (*Factor)(nil)
