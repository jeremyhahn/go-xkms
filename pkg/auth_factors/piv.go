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

package auth_factors

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// PIVHardwareFactorVerifier adapts xkms's pkg/pivcert verification logic
// to qrdb's FactorVerifier interface. It is registered with the qrdb
// embedded transport via WithFactorVerifier so FactorClient.Verify routes
// PIV challenges through xkms's chain-validation and signature-verify
// helpers.
//
// The adapter's Verify path:
//
//  1. Confirm factor is active (RevokedAt == nil).
//  2. Decode the persisted certificate from factor.Metadata["cert_pem"],
//     or from factor.Metadata["cert_der"] when the persisted form is
//     base64-encoded DER.
//  3. Confirm the challenge's certificate fingerprint matches the
//     persisted lookup-key (factor.Credential is SHA-256(cert)).
//  4. Verify the chain against the supplied root pool.
//  5. Verify the signature over challenge.Nonce using the certificate's
//     public key.
//
// The trust roots are configured at construction time. Tests can pass an
// in-memory pool; production callers wire xkms's CA pool.
type PIVHardwareFactorVerifier struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

// NewPIVHardwareFactorVerifier constructs a verifier configured with the
// given trust roots. The roots pool must be non-nil; intermediates may
// be nil if the leaf chains directly to a root.
func NewPIVHardwareFactorVerifier(roots, intermediates *x509.CertPool) (*PIVHardwareFactorVerifier, error) {
	if roots == nil {
		return nil, &NilTrustPoolError{}
	}
	return &PIVHardwareFactorVerifier{roots: roots, intermediates: intermediates}, nil
}

// Type returns transport.FactorTypePIV.
func (v *PIVHardwareFactorVerifier) Type() qrdbtransport.FactorType {
	return qrdbtransport.FactorTypePIV
}

// Verify exercises xkms's PIV verification path for the given challenge
// against the persisted factor.
//
// Required challenge inputs:
//
//   - challenge.Nonce: the bytes the slot signed.
//   - challenge.Signature: DER-encoded ECDSA or RSA signature over Nonce.
//   - factor.Metadata["cert_pem"] or factor.Metadata["cert_der"]:
//     the slot certificate that holds the verification public key.
//     cert_pem is PEM; cert_der is standard base64 of the DER, because
//     Metadata is a string map that round-trips through JSON and raw DER
//     is not valid UTF-8. cert_pem wins when both are present.
func (v *PIVHardwareFactorVerifier) Verify(ctx context.Context, factor *qrdbsdk.AuthFactor, challenge qrdbtransport.VerifyChallenge) error {
	if v == nil || v.roots == nil {
		return &NilTrustPoolError{}
	}
	if factor == nil {
		return &MissingFactorError{}
	}
	if factor.RevokedAt != nil {
		return &qrdbsdk.FactorRevokedError{FactorID: factor.ID}
	}
	if factor.Type != qrdbsdk.AuthFactorPIV {
		return &qrdbsdk.FactorTypeUnsupportedError{Type: string(factor.Type)}
	}
	if len(challenge.Nonce) == 0 {
		return &MissingChallengeFieldError{Field: "nonce"}
	}
	if len(challenge.Signature) == 0 {
		return &MissingChallengeFieldError{Field: "signature"}
	}

	cert, err := decodeCertificate(factor)
	if err != nil {
		return err
	}

	// The persisted lookup-key is SHA-256(cert). Confirm the certificate
	// we just loaded matches that key.
	sum := sha256.Sum256(cert.Raw)
	if !bytes.Equal(sum[:], factor.Credential) {
		return &CredentialMismatchError{}
	}

	if err := pivcert.VerifyChain(cert, v.roots, v.intermediates); err != nil {
		return err
	}

	// Verify signature over the challenge nonce. The hash algorithm is
	// SHA-256 by default; PIV hardware ordinarily signs SHA-256(nonce).
	digest := sha256.Sum256(challenge.Nonce)
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], challenge.Signature) {
			return &SignatureVerifyError{Reason: "ECDSA verification failed"}
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], challenge.Signature); err != nil {
			return &SignatureVerifyError{Reason: "RSA verification failed: " + err.Error()}
		}
	default:
		return &UnsupportedPublicKeyError{}
	}
	return nil
}

// decodeCertificate pulls an x509.Certificate from the factor's metadata,
// accepting cert_pem (PEM) or cert_der (standard base64 of the DER).
func decodeCertificate(factor *qrdbsdk.AuthFactor) (*x509.Certificate, error) {
	if factor.Metadata != nil {
		if pemBytes := factor.Metadata["cert_pem"]; pemBytes != "" {
			block, _ := pem.Decode([]byte(pemBytes))
			if block == nil {
				return nil, &CertDecodeError{Reason: "invalid PEM"}
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, &CertDecodeError{Reason: "PEM parse: " + err.Error()}
			}
			return cert, nil
		}
		if derB64 := factor.Metadata["cert_der"]; derB64 != "" {
			// Metadata is a map[string]string that round-trips through JSON,
			// and raw DER is not valid UTF-8: it does not survive that trip
			// intact. cert_der is therefore standard base64, which does.
			der, err := base64.StdEncoding.DecodeString(derB64)
			if err != nil {
				return nil, &CertDecodeError{Reason: "DER base64 decode: " + err.Error()}
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, &CertDecodeError{Reason: "DER parse: " + err.Error()}
			}
			return cert, nil
		}
	}
	return nil, &MissingChallengeFieldError{Field: "cert_pem|cert_der"}
}

// Compile-time assertion against the interface mirror.
var _ qrdbPIVVerifier = (*PIVHardwareFactorVerifier)(nil)

// qrdbPIVVerifier mirrors the embedded.FactorVerifier shape locally so
// this package does not import the embedded sub-package directly.
type qrdbPIVVerifier interface {
	Type() qrdbtransport.FactorType
	Verify(ctx context.Context, factor *qrdbsdk.AuthFactor, challenge qrdbtransport.VerifyChallenge) error
}

// NilTrustPoolError is returned when the verifier is constructed with
// a nil roots pool.
type NilTrustPoolError struct{}

// Error implements error.
func (e *NilTrustPoolError) Error() string {
	return "auth_factors: piv: trust roots pool is nil"
}

// MissingChallengeFieldError is returned when the challenge omits a
// required field.
type MissingChallengeFieldError struct {
	Field string
}

// Error implements error.
func (e *MissingChallengeFieldError) Error() string {
	if e == nil || e.Field == "" {
		return "auth_factors: missing challenge field"
	}
	return "auth_factors: missing challenge field: " + e.Field
}

// SignatureVerifyError is returned when the signature does not validate
// against the certificate's public key.
type SignatureVerifyError struct {
	Reason string
}

// Error implements error.
func (e *SignatureVerifyError) Error() string {
	if e == nil || e.Reason == "" {
		return "auth_factors: signature verification failed"
	}
	return "auth_factors: signature verification failed: " + e.Reason
}

// UnsupportedPublicKeyError is returned when the certificate uses a key
// type the adapter does not know how to verify.
type UnsupportedPublicKeyError struct{}

// Error implements error.
func (e *UnsupportedPublicKeyError) Error() string {
	return "auth_factors: piv: unsupported certificate public key type"
}

// CertDecodeError is returned when the persisted certificate cannot be
// decoded from the factor metadata.
type CertDecodeError struct {
	Reason string
}

// Error implements error.
func (e *CertDecodeError) Error() string {
	if e == nil || e.Reason == "" {
		return "auth_factors: piv: certificate decode failed"
	}
	return "auth_factors: piv: certificate decode failed: " + e.Reason
}
