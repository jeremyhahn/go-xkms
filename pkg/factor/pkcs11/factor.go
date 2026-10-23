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
// custodian's signature over go-qrdb's challenge message
// (qrdbsdk.QuorumChallengeMessage of the challenge ID, its purpose and the
// nonce; never the bare nonce) against the enrolled public key using
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
	"math/big"
	"strconv"
	"strings"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	challengemsg "github.com/jeremyhahn/go-xkms/pkg/factor/internal/challenge"
)

// FactorName is the canonical Factor.Name() return value for PKCS#11.
const FactorName = "pkcs11"

const (
	defaultChallengeTTLSeconds = 5 * 60
	defaultMechanism           = "CKM_ECDSA_SHA256"
	// defaultRSAMechanism is the mechanism recorded when an RSA key is
	// enrolled without an explicit "mechanism" MethodParam. defaultMechanism
	// is ECDSA-only (CKM_ECDSA_SHA256), so an RSA enrollment needs its own
	// default rather than inheriting one that fails the algorithm/mechanism
	// consistency check below on every RSA enrollment.
	defaultRSAMechanism = "CKM_SHA256_RSA_PKCS"
	nonceLength         = 32

	// methodDataEnrolledKey is the challenge MethodData key carrying the
	// enrolled PKIX public key, standard-base64 DER. Verify reads the
	// verification key from here and nowhere else, so a response can never
	// substitute its own key.
	methodDataEnrolledKey = "enrolled_public_key_der"

	// methodDataMechanism is the challenge MethodData key carrying the
	// enrolled PKCS#11 signing mechanism (e.g. "CKM_ECDSA_SHA256"). Verify
	// checks a response against this mechanism, and this mechanism alone: it
	// is fixed at enrollment and is never renegotiated at verification, nor
	// chosen from anything the response supplies.
	methodDataMechanism = "mechanism"

	// responseMechanism is the qrdbsdk.AuthFactorResponse.Metadata key a
	// response may use to state which mechanism it was produced with. Verify
	// only ever compares it against the enrolled mechanism to refuse a
	// mismatch — never to select how the signature is checked.
	responseMechanism = "mechanism"
)

// Config configures a PKCS#11 Factor. The zero value is valid.
type Config struct {
	// DefaultMechanism is the PKCS#11 signing mechanism recorded on the
	// enrollment when MethodParams["mechanism"] is not supplied and the
	// enrolled key is ECDSA. Defaults to "CKM_ECDSA_SHA256". It applies only
	// to ECDSA enrollments: an RSA key enrolled without an explicit
	// "mechanism" gets the package's own RSA default (CKM_SHA256_RSA_PKCS)
	// instead, since a mechanism inconsistent with the enrolled key's
	// algorithm is refused at enrollment.
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
	if algorithm == "rsa" && mechanismFamily(mechanism) != "rsa" {
		mechanism = defaultRSAMechanism
	}
	if m, ok := params.MethodParams["mechanism"].(string); ok && m != "" {
		mechanism = m
	}
	if fam := mechanismFamily(mechanism); fam != algorithm {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{
			Reason: "pkcs11: mechanism " + mechanism + " is inconsistent with the enrolled " + algorithm + " key",
		}
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

// Challenge produces a 32-byte random nonce the custodian answers with the
// private key on their PKCS#11 token: a signature over go-qrdb's challenge
// message once go-qrdb has bound the challenge to its purpose. The enrolled public key is carried in
// MethodData["enrolled_public_key_der"] (standard base64 of the PKIX DER) and
// the enrolled mechanism is carried in MethodData["mechanism"], so Verify
// authenticates against the server-held enrollment — key and mechanism alike
// — rather than anything the response supplies.
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
			methodDataEnrolledKey: base64.StdEncoding.EncodeToString(enrollment.PublicKey),
			methodDataMechanism:   enrollment.Metadata["mechanism"],
			"algorithm":           enrollment.Metadata["algorithm"],
			"key_id":              enrollment.Metadata["key_id"],
		},
	}, nil
}

// Verify checks the signature in response.Value against go-qrdb's challenge
// message, qrdbsdk.QuorumChallengeMessage(ChallengeID,
// MethodData[qrdbsdk.QuorumChallengePurposeKey], Nonce), using the enrolled
// public key, so a proof made for another challenge or purpose never verifies. The key is read from
// challenge.MethodData["enrolled_public_key_der"] — never from the response —
// so an attacker cannot pass verification by signing with a key of their own
// and presenting it alongside the signature. ECDSA signatures are ASN.1 DER
// (r,s); RSA signatures are PKCS#1 v1.5; both are over SHA-256 of the message.
//
// The mechanism follows the same rule as the key: it is read from
// challenge.MethodData["mechanism"] — the mechanism recorded at enrollment —
// and is never chosen from anything response.Metadata names. Verify refuses
// when the enrolled mechanism is inconsistent with the enrolled key's
// algorithm (a corrupted or hand-edited enrollment), and refuses when the
// response names a mechanism other than the enrolled one, even if the
// signature itself is otherwise valid.
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
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "parse public key: " + err.Error()}
	}

	// The mechanism check applies only once the key type is known (ecdsa or
	// rsa); an unsupported key type is rejected by the type switch below with
	// its own message, unchanged from before this check existed.
	if algorithm := publicKeyAlgorithm(pub); algorithm != "" {
		mechanism, ok := challenge.MethodData[methodDataMechanism].(string)
		if !ok || mechanism == "" {
			return &qrdbsdk.AuthFactorVerificationFailedError{
				FactorName: FactorName,
				Reason:     methodDataMechanism + " missing from challenge MethodData",
			}
		}
		if fam := mechanismFamily(mechanism); fam != algorithm {
			return &qrdbsdk.AuthFactorVerificationFailedError{
				FactorName: FactorName,
				Reason:     "enrolled mechanism " + mechanism + " is inconsistent with the enrolled " + algorithm + " key",
			}
		}
		if named := response.Metadata[responseMechanism]; named != "" && named != mechanism {
			return &qrdbsdk.AuthFactorVerificationFailedError{
				FactorName: FactorName,
				Reason:     "response named mechanism " + named + ", enrolled mechanism is " + mechanism,
			}
		}
	}

	if len(challenge.Nonce) == 0 {
		return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: "challenge carries no nonce"}
	}
	// The token signs go-qrdb's challenge message, which binds the challenge
	// ID and purpose, never the bare nonce.
	digest := sha256.Sum256(challengemsg.Message(challenge))
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

// verifyECDSA verifies an ASN.1 DER (r,s) ECDSA signature over the pre-hashed
// digest of the challenge message.
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

// mechanismFamily classifies a PKCS#11 signing mechanism name by the public
// key algorithm it applies to, returning "ecdsa", "rsa", or "" for a
// mechanism belonging to neither family. It recognizes the mechanism by its
// PKCS#11 naming convention (every CKM_ECDSA* mechanism names an EC
// operation; every RSA mechanism carries "RSA" in its name, e.g.
// CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS_PSS) rather than by an
// exhaustive enumeration, so it does not need to be extended each time a new
// hash-width variant is added to a token's supported mechanism list.
func mechanismFamily(mechanism string) string {
	switch {
	case strings.HasPrefix(mechanism, "CKM_ECDSA"):
		return "ecdsa"
	case strings.Contains(mechanism, "RSA"):
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
