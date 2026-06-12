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
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// PKCS11FactorVerifier implements possession-only verification for PKCS#11 /
// HSM hardware keys. Unlike PIV, it performs NO certificate chain validation
// — the factor carries only the enrolled public key; trust is established by
// the enrollment path, not by a CA chain at login time.
//
// The adapter's Verify path:
//
//  1. Confirm factor is active (RevokedAt == nil).
//  2. Confirm factor type is pkcs11.
//  3. Confirm challenge carries a non-empty Nonce and Signature.
//  4. Decode the public key from factor.Metadata["public_key_pem"] (PEM
//     "PUBLIC KEY" block, parsed via x509.ParsePKIXPublicKey) or fall back
//     to factor.Metadata["public_key_der"] (standard base64-encoded PKIX DER).
//  5. Verify SHA-256(PKIX DER of the decoded key) == factor.Credential. This
//     is the canonical PKCS#11 lookup-key binding (same hash that enrollment
//     stores as Credential).
//  6. Verify the signature over the nonce using the decoded public key:
//     - ECDSA: ecdsa.VerifyASN1 over SHA-256(nonce).
//     - RSA:   rsa.VerifyPKCS1v15 over SHA-256(nonce) with crypto.SHA256.
//     - Ed25519: ed25519.Verify over the raw nonce bytes (no pre-hash).
type PKCS11FactorVerifier struct{}

// NewPKCS11FactorVerifier constructs a PKCS11FactorVerifier. The verifier has
// no external dependencies — all required data (public key, credential hash)
// is embedded in the factor record at enrollment time.
func NewPKCS11FactorVerifier() *PKCS11FactorVerifier {
	return &PKCS11FactorVerifier{}
}

// Type returns transport.FactorTypePKCS11.
func (v *PKCS11FactorVerifier) Type() qrdbtransport.FactorType {
	return qrdbtransport.FactorTypePKCS11
}

// Verify exercises the PKCS#11 possession-only verification path.
//
// Required challenge inputs:
//
//   - challenge.Nonce: the bytes the HSM key signed.
//   - challenge.Signature: the DER-encoded ECDSA / RSA-PKCS1v15 signature
//     over SHA-256(Nonce), or the raw Ed25519 signature over Nonce.
//   - factor.Metadata["public_key_pem"] or factor.Metadata["public_key_der"]:
//     the enrolled SubjectPublicKeyInfo that holds the verification key.
func (v *PKCS11FactorVerifier) Verify(ctx context.Context, factor *qrdbsdk.AuthFactor, challenge qrdbtransport.VerifyChallenge) error {
	if factor == nil {
		return &MissingFactorError{}
	}
	if factor.RevokedAt != nil {
		return &qrdbsdk.FactorRevokedError{FactorID: factor.ID}
	}
	if factor.Type != qrdbsdk.AuthFactorPKCS11 {
		return &qrdbsdk.FactorTypeUnsupportedError{Type: string(factor.Type)}
	}
	if len(challenge.Nonce) == 0 {
		return &MissingChallengeFieldError{Field: "nonce"}
	}
	if len(challenge.Signature) == 0 {
		return &MissingChallengeFieldError{Field: "signature"}
	}

	pub, pkixDER, err := decodePublicKey(factor)
	if err != nil {
		return err
	}

	// The persisted lookup-key is SHA-256(SubjectPublicKeyInfo DER). Confirm
	// the key we just decoded matches the enrolled credential.
	sum := sha256.Sum256(pkixDER)
	if !bytes.Equal(sum[:], factor.Credential) {
		return &CredentialMismatchError{}
	}

	return verifyPKCS11Signature(pub, challenge.Nonce, challenge.Signature)
}

// decodePublicKey pulls a crypto.PublicKey and its raw PKIX DER bytes from
// the factor's metadata. It tries the PEM field first ("public_key_pem") and
// falls back to the base64-encoded DER field ("public_key_der").
func decodePublicKey(factor *qrdbsdk.AuthFactor) (any, []byte, error) {
	if factor.Metadata != nil {
		if pemStr := factor.Metadata["public_key_pem"]; pemStr != "" {
			block, _ := pem.Decode([]byte(pemStr))
			if block == nil {
				return nil, nil, &PublicKeyDecodeError{Reason: "invalid PEM block"}
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, nil, &PublicKeyDecodeError{Reason: "PEM: " + err.Error()}
			}
			return pub, block.Bytes, nil
		}
		if derB64 := factor.Metadata["public_key_der"]; derB64 != "" {
			der, err := base64.StdEncoding.DecodeString(derB64)
			if err != nil {
				return nil, nil, &PublicKeyDecodeError{Reason: "DER base64: " + err.Error()}
			}
			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				return nil, nil, &PublicKeyDecodeError{Reason: "DER parse: " + err.Error()}
			}
			return pub, der, nil
		}
	}
	return nil, nil, &MissingChallengeFieldError{Field: "public_key_pem|public_key_der"}
}

// verifyPKCS11Signature verifies the signature over the nonce using the
// provided public key. ECDSA and RSA sign SHA-256(nonce); Ed25519 signs the
// raw nonce bytes (Ed25519 pre-hashes internally).
func verifyPKCS11Signature(pub any, nonce, sig []byte) error {
	digest := sha256.Sum256(nonce)
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], sig) {
			return &SignatureVerifyError{Reason: "ECDSA verification failed"}
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
			return &SignatureVerifyError{Reason: "RSA verification failed: " + err.Error()}
		}
	case ed25519.PublicKey:
		// Ed25519 is defined over the raw message; the algorithm pre-hashes
		// internally. Do NOT pre-hash when calling ed25519.Verify.
		if !ed25519.Verify(key, nonce, sig) {
			return &SignatureVerifyError{Reason: "Ed25519 verification failed"}
		}
	default:
		return &UnsupportedPublicKeyError{}
	}
	return nil
}

// Compile-time assertion against the interface mirror.
var _ qrdbPKCS11Verifier = (*PKCS11FactorVerifier)(nil)

// qrdbPKCS11Verifier mirrors the embedded.FactorVerifier shape locally so
// this package does not import the embedded sub-package directly.
type qrdbPKCS11Verifier interface {
	Type() qrdbtransport.FactorType
	Verify(ctx context.Context, factor *qrdbsdk.AuthFactor, challenge qrdbtransport.VerifyChallenge) error
}

// PublicKeyDecodeError is returned when the enrolled public key cannot be
// decoded from the factor's metadata.
type PublicKeyDecodeError struct {
	// Reason is a human-readable explanation of the decode failure.
	Reason string
}

// Error implements error.
func (e *PublicKeyDecodeError) Error() string {
	if e == nil || e.Reason == "" {
		return "auth_factors: pkcs11: public key decode failed"
	}
	return "auth_factors: pkcs11: public key decode failed: " + e.Reason
}
