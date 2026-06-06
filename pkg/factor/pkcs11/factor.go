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

// Package pkcs11 exposes a qrdbsdk.AuthFactorPlugin adapter for PKCS#11 / HSM
// auth-factor tokens backed by go-xkms's canonical PKCS#11 stack. It implements
// qrdb's qrdbsdk.AuthFactorPlugin interface (Enroll, Challenge, Verify) using
// the public key material extracted from a configured slot/token.
//
// Enrollment captures the DER (PKIX) public key of an asymmetric key pair
// living on a PKCS#11 token together with the slot, token label, key id and
// signing algorithm. Challenge issues a random nonce. Verify checks the
// custodian's signature over the nonce against the enrolled public key using
// stdlib crypto (ECDSA or RSA). Verification deliberately does NOT require a
// live token: once enrolled, the public key is sufficient to validate any
// signature, exactly as the canonical PIV factor does. Signing (the private-key
// side) is performed by the holder of the token, e.g. via the go-xkms PKCS#11
// backend's Sign surface.
//
// Usage:
//
//	f := pkcs11.New(pkcs11.Config{})
//	registry.Register(f)
//
// The DER public key is supplied at enrollment time via MethodParams
// ("public_key_der"); for live-token deployments the caller obtains it from the
// go-xkms PKCS#11 backend (Backend.GetPublicKeyBytes -> x509.MarshalPKIXPublicKey).
package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
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

// FactorName is the canonical Factor.Name() return value for PKCS#11.
const FactorName = "pkcs11"

const (
	defaultChallengeTTLSeconds = 5 * 60
	defaultMechanism           = "CKM_ECDSA_SHA256"
	nonceLength                = 32
)

// Config configures a PKCS#11 Factor. The zero value is valid.
type Config struct {
	// DefaultMechanism is the PKCS#11 signing mechanism recorded on the
	// enrollment when MethodParams["mechanism"] is not supplied. Defaults to
	// "CKM_ECDSA_SHA256".
	DefaultMechanism string

	// ChallengeTTLSeconds controls how long issued challenges remain valid.
	// Zero defaults to 300 (five minutes).
	ChallengeTTLSeconds int
}

// Factor implements qrdbsdk.AuthFactorPlugin for PKCS#11 / HSM tokens. It is
// vendor-agnostic: any token whose public key is exported as DER (PKIX) can be
// enrolled and verified.
type Factor struct {
	cfg Config
}

// New constructs a PKCS#11 Factor, applying canonical defaults.
func New(cfg Config) *Factor {
	if cfg.DefaultMechanism == "" {
		cfg.DefaultMechanism = defaultMechanism
	}
	if cfg.ChallengeTTLSeconds <= 0 {
		cfg.ChallengeTTLSeconds = defaultChallengeTTLSeconds
	}
	return &Factor{cfg: cfg}
}

// Name returns the canonical PKCS#11 factor identifier "pkcs11".
func (f *Factor) Name() string { return FactorName }

// Enroll records the public key of a key pair resident on a PKCS#11 token.
// MethodParams accepts:
//
//	"public_key_der" string  base64-encoded DER (PKIX) public key (required)
//	"slot_id"        int     PKCS#11 slot index (recorded as metadata)
//	"token_label"    string  PKCS#11 token label (recorded as metadata)
//	"key_id"         string  CKA_ID / object label of the key pair
//	"mechanism"      string  signing mechanism (e.g., CKM_ECDSA_SHA256)
//
// The DER public key may alternatively be supplied as raw []byte under
// "public_key_der" for in-process callers that already hold the bytes.
func (f *Factor) Enroll(_ context.Context, params *qrdbsdk.AuthFactorEnrollParams) (*qrdbsdk.AuthFactorEnrollment, error) {
	if params == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "params must not be nil"}
	}

	der, err := extractDER(params.MethodParams["public_key_der"])
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "pkcs11: " + err.Error()}
	}

	// Validate the DER decodes to a supported asymmetric public key so that
	// invalid material is rejected at enrollment, not at verify time.
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "pkcs11: parse PKIX public key: " + err.Error()}
	}
	algorithm := publicKeyAlgorithm(pub)
	if algorithm == "" {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "pkcs11: unsupported public key type (want ECDSA or RSA)"}
	}

	mechanism := f.cfg.DefaultMechanism
	if m, ok := params.MethodParams["mechanism"].(string); ok && m != "" {
		mechanism = m
	}

	metadata := map[string]string{
		"algorithm": algorithm,
		"mechanism": mechanism,
		"ttl":       strconv.Itoa(f.cfg.ChallengeTTLSeconds),
	}
	if v := stringParam(params.MethodParams["key_id"]); v != "" {
		metadata["key_id"] = v
	}
	if v := stringParam(params.MethodParams["token_label"]); v != "" {
		metadata["token_label"] = v
	}
	if v := intParamString(params.MethodParams["slot_id"]); v != "" {
		metadata["slot"] = v
	}

	return &qrdbsdk.AuthFactorEnrollment{
		EnrollmentID: qrdbsdk.NewAuthFactorEnrollmentID(),
		UserID:       params.UserID,
		FactorName:   FactorName,
		TenantID:     params.TenantID,
		PublicKey:    der,
		Metadata:     metadata,
		EnrolledAt:   time.Now().UTC(),
	}, nil
}

// Challenge produces a 32-byte random nonce the custodian must sign with the
// private key on their PKCS#11 token.
func (f *Factor) Challenge(_ context.Context, enrollment *qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorChallenge, error) {
	if enrollment == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "enrollment must not be nil"}
	}
	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{
			EnrollmentID: enrollment.EnrollmentID,
			Reason:       "pkcs11: nonce rand.Read: " + err.Error(),
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
			"mechanism": enrollment.Metadata["mechanism"],
			"algorithm": enrollment.Metadata["algorithm"],
			"key_id":    enrollment.Metadata["key_id"],
		},
	}, nil
}

// Verify checks the DER-encoded signature in response.Value against the
// challenge nonce using the enrolled public key. The enrolled public key is
// taken from response.Metadata["public_key_der"] (base64 DER) when present,
// otherwise the verifier must be given the enrollment's PublicKey out of band;
// callers that hold the enrollment should set this field. ECDSA signatures are
// ASN.1 DER (r,s); RSA signatures are PKCS#1 v1.5 over SHA-256 of the nonce.
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

	der, err := publicKeyDERFromResponse(response)
	if err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: err.Error()}
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "parse public key: " + err.Error()}
	}

	digest := sha256.Sum256(challenge.Nonce)
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(key, digest[:], response.Value)
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], response.Value); err != nil {
			return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "rsa signature invalid: " + err.Error()}
		}
		return nil
	default:
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "unsupported public key type"}
	}
}

// publicKeyDERFromResponse resolves the enrolled DER public key. It prefers an
// explicit base64 value in the response metadata (the verifier echoes the
// enrolled key there) and falls back to a PEM PUBLIC KEY block for callers that
// supply PEM.
func publicKeyDERFromResponse(response *qrdbsdk.AuthFactorResponse) ([]byte, error) {
	if v, ok := response.Metadata["public_key_der"]; ok && v != "" {
		der, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, &derDecodeError{reason: "decode public_key_der: " + err.Error()}
		}
		return der, nil
	}
	if v, ok := response.Metadata["public_key_pem"]; ok && v != "" {
		block, _ := pem.Decode([]byte(v))
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, &derDecodeError{reason: "public_key_pem is not a PUBLIC KEY block"}
		}
		return block.Bytes, nil
	}
	return nil, &derDecodeError{reason: "public_key_der missing from response metadata"}
}

// verifyECDSA verifies an ASN.1 DER (r,s) ECDSA signature over the pre-hashed
// digest of the nonce.
func verifyECDSA(pub *ecdsa.PublicKey, digest, sig []byte) error {
	var dsaSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &dsaSig); err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "unmarshal signature: " + err.Error()}
	}
	if dsaSig.R == nil || dsaSig.S == nil || dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "signature contains non-positive component"}
	}
	if !ecdsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "signature invalid"}
	}
	return nil
}

// publicKeyAlgorithm classifies a parsed public key as "ecdsa" or "rsa".
func publicKeyAlgorithm(pub any) string {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return "ecdsa"
	case *rsa.PublicKey:
		return "rsa"
	default:
		return ""
	}
}

// extractDER accepts the public key DER as base64 string or raw []byte.
func extractDER(v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return nil, &derDecodeError{reason: "public_key_der is required"}
	case []byte:
		if len(t) == 0 {
			return nil, &derDecodeError{reason: "public_key_der is empty"}
		}
		return t, nil
	case string:
		if t == "" {
			return nil, &derDecodeError{reason: "public_key_der is empty"}
		}
		der, err := base64.StdEncoding.DecodeString(t)
		if err != nil {
			return nil, &derDecodeError{reason: "decode public_key_der: " + err.Error()}
		}
		return der, nil
	default:
		return nil, &derDecodeError{reason: "public_key_der must be a base64 string or []byte"}
	}
}

// stringParam returns a MethodParams value as a string when it is a string.
func stringParam(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// intParamString renders an integer-like MethodParams value as a string. JSON
// decoding yields float64 for numbers, so both int and float64 are handled.
func intParamString(v any) string {
	switch t := v.(type) {
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case string:
		return t
	default:
		return ""
	}
}

// derDecodeError is a typed error for malformed DER public key inputs.
type derDecodeError struct {
	reason string
}

// Error implements the error interface.
func (e *derDecodeError) Error() string { return e.reason }

// Compile-time interface assertion.
var _ qrdbsdk.AuthFactorPlugin = (*Factor)(nil)
