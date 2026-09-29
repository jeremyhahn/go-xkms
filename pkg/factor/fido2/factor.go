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

// Package fido2 exposes a qrdbsdk.AuthFactorPlugin adapter for FIDO2 / WebAuthn
// authenticators backed by go-xkms's canonical WebAuthn stack. It implements
// qrdb's qrdbsdk.AuthFactorPlugin interface (Enroll, Challenge, Verify) by
// validating a WebAuthn assertion against an enrolled COSE credential public
// key.
//
// Enrollment captures the credential's COSE-encoded public key (the
// authenticatorData attested credential key) plus the credential id and rp id.
// Challenge issues a random WebAuthn challenge nonce and carries the enrolled
// COSE key and rp id with it. Verify checks the assertion's rpIdHash and
// user-presence flag, the clientDataJSON ceremony type and challenge, then
// reconstructs the WebAuthn signed message -- authenticatorData ||
// SHA-256(clientDataJSON) -- and verifies the assertion signature against the
// enrolled COSE public key using the canonical go-webauthn webauthncose
// verifier. This is the same signature check the go-xkms WebAuthn relying
// party performs in FinishLogin; there is no stubbed always-pass path.
//
// Usage:
//
//	f := fido2.New(fido2.Config{RPID: "example.com"})
//	registry.Register(f)
package fido2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// FactorName is the canonical Factor.Name() return value for FIDO2.
const FactorName = "fido2"

const (
	defaultChallengeTTLSeconds = 5 * 60
	defaultRPID                = "localhost"
	challengeLength            = 32

	// methodDataEnrolledKey is the challenge MethodData key carrying the
	// enrolled COSE credential public key, standard base64. Verify reads the
	// verification key from here and nowhere else, so a response can never
	// substitute its own key.
	methodDataEnrolledKey = "enrolled_cose_public_key"

	// methodDataRPID is the challenge MethodData key carrying the enrolled
	// relying-party id, whose SHA-256 the assertion's authenticatorData must
	// begin with.
	methodDataRPID = "rp_id"
)

// Config configures a FIDO2 Factor. The zero value is valid.
type Config struct {
	// RPID is the WebAuthn Relying Party identifier recorded on enrollments
	// and challenges when MethodParams["rp_id"] is not supplied. Defaults to
	// "localhost".
	RPID string

	// ChallengeTTLSeconds controls how long issued challenges remain valid.
	// Zero defaults to 300 (five minutes).
	ChallengeTTLSeconds int
}

// Factor implements qrdbsdk.AuthFactorPlugin for FIDO2 / WebAuthn authenticators.
type Factor struct {
	cfg Config

	// local drives an attached authenticator for browser-free enrollment at
	// init. Nil for the ordinary server-side factor, where a browser has
	// already run the ceremony and Enroll only stores the result.
	local *LocalCeremony
}

// New constructs a FIDO2 Factor, applying canonical defaults.
func New(cfg Config) *Factor {
	if cfg.RPID == "" {
		cfg.RPID = defaultRPID
	}
	if cfg.ChallengeTTLSeconds <= 0 {
		cfg.ChallengeTTLSeconds = defaultChallengeTTLSeconds
	}
	return &Factor{cfg: cfg}
}

// NewWithLocalCeremony constructs a FIDO2 Factor that can also drive an
// attached authenticator over CTAP2.
//
// This is the init-time variant: it answers the ceremony's availability probe
// from real hardware, so a planned passkey factor with no key attached fails
// the preflight instead of partway through enrollment.
func NewWithLocalCeremony(cfg Config, local *LocalCeremony) *Factor {
	f := New(cfg)
	f.local = local
	return f
}

// Available reports whether a passkey can be enrolled right now, satisfying
// the ceremony's optional availability probe.
//
// A factor with no local ceremony reports available: the browser path needs no
// hardware attached to THIS host, and reporting otherwise would block every
// ordinary server deployment from listing fido2 as a usable factor.
func (f *Factor) Available(ctx context.Context) (bool, string) {
	if f == nil || f.local == nil {
		return true, ""
	}
	return f.local.Available(ctx)
}

// Name returns the canonical FIDO2 factor identifier "fido2".
func (f *Factor) Name() string { return FactorName }

// Enroll records a registered WebAuthn credential. MethodParams accepts:
//
//	"cose_public_key" string  base64-encoded COSE public key (required)
//	"credential_id"   string  base64url-encoded credential id (required)
//	"rp_id"           string  Relying Party id; defaults to Config.RPID
//	"aaguid"          string  authenticator AAGUID (recorded as metadata)
//
// The COSE public key may alternatively be supplied as raw []byte under
// "cose_public_key" for in-process callers that already hold the bytes. No
// private key material is stored.
func (f *Factor) Enroll(_ context.Context, params *qrdbsdk.AuthFactorEnrollParams) (*qrdbsdk.AuthFactorEnrollment, error) {
	if params == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "params must not be nil"}
	}

	cose, err := extractBytes(params.MethodParams["cose_public_key"])
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "fido2: cose_public_key " + err.Error()}
	}
	// Validate the COSE key parses to a supported credential key so malformed
	// material is rejected at enrollment, not at verify time.
	if _, err := webauthncose.ParsePublicKey(cose); err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "fido2: parse COSE public key: " + err.Error()}
	}

	credentialID := stringParam(params.MethodParams["credential_id"])
	if credentialID == "" {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "fido2: credential_id is required"}
	}

	rpID := f.cfg.RPID
	if v := stringParam(params.MethodParams["rp_id"]); v != "" {
		rpID = v
	}

	metadata := map[string]string{
		"credential_id": credentialID,
		"rp_id":         rpID,
		"ttl":           strconv.Itoa(f.cfg.ChallengeTTLSeconds),
	}
	if v := stringParam(params.MethodParams["aaguid"]); v != "" {
		metadata["aaguid"] = v
	}

	return &qrdbsdk.AuthFactorEnrollment{
		EnrollmentID: qrdbsdk.NewAuthFactorEnrollmentID(),
		UserID:       params.UserID,
		FactorName:   FactorName,
		TenantID:     params.TenantID,
		PublicKey:    cose,
		Metadata:     metadata,
		EnrolledAt:   time.Now().UTC(),
	}, nil
}

// Challenge produces a 32-byte random WebAuthn challenge the authenticator must
// sign as part of an assertion (navigator.credentials.get). The enrolled COSE
// public key (MethodData["enrolled_cose_public_key"], standard base64) and rp
// id (MethodData["rp_id"]) travel with the challenge so Verify checks the
// assertion against the server-held enrollment rather than anything the
// response supplies.
func (f *Factor) Challenge(_ context.Context, enrollment *qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorChallenge, error) {
	if enrollment == nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "enrollment must not be nil"}
	}
	nonce := make([]byte, challengeLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{
			EnrollmentID: enrollment.EnrollmentID,
			Reason:       "fido2: challenge rand.Read: " + err.Error(),
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
			"challenge_base64":    base64.RawURLEncoding.EncodeToString(nonce),
			methodDataRPID:        enrollment.Metadata["rp_id"],
			"credential_id":       enrollment.Metadata["credential_id"],
			methodDataEnrolledKey: base64.StdEncoding.EncodeToString(enrollment.PublicKey),
		},
	}, nil
}

// Verify validates a WebAuthn assertion against the enrolled credential. The
// response carries only the assertion itself:
//
//	response.Value                  assertion signature (ASN.1 DER for EC2/RSA, raw for OKP)
//	Metadata["authenticator_data"]  base64 raw authenticatorData
//	Metadata["client_data"]         base64 raw clientDataJSON
//
// The verification key and rp id come from the challenge
// (MethodData["enrolled_cose_public_key"] and MethodData["rp_id"]) — never from
// the response — so an attacker cannot pass verification by signing with a
// credential of their own and presenting its key alongside the assertion.
//
// Checks, following the WebAuthn assertion procedure: authenticatorData begins
// with SHA-256 of the enrolled rp id and has the user-present flag set;
// clientDataJSON is a "webauthn.get" ceremony whose challenge is the issued
// nonce (base64url); the signature over authenticatorData ||
// SHA-256(clientDataJSON) verifies under the enrolled COSE key.
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

	key, err := enrolledKey(challenge)
	if err != nil {
		return err
	}
	rpID, ok := challenge.MethodData[methodDataRPID].(string)
	if !ok || rpID == "" {
		return verificationFailed(methodDataRPID + " missing from challenge MethodData")
	}

	authData, err := decodeB64(response.Metadata["authenticator_data"])
	if err != nil {
		return verificationFailed("authenticator_data: " + err.Error())
	}
	clientData, err := decodeB64(response.Metadata["client_data"])
	if err != nil {
		return verificationFailed("client_data: " + err.Error())
	}

	// The authenticator scopes each credential to one relying party, and
	// records which in the rpIdHash. An assertion made for another RP, or
	// without the user touching the authenticator, is refused.
	var parsed protocol.AuthenticatorData
	if err := parsed.Unmarshal(authData); err != nil {
		return verificationFailed("authenticator_data: " + err.Error())
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(parsed.RPIDHash, rpIDHash[:]) != 1 {
		return verificationFailed("authenticator_data rpIdHash does not match the enrolled rp id")
	}
	if !parsed.Flags.UserPresent() {
		return verificationFailed("authenticator_data user-present flag is not set")
	}

	// Bind the assertion to this challenge: clientDataJSON must describe an
	// assertion ceremony over the exact challenge nonce, base64url-encoded per
	// the WebAuthn CollectedClientData format. This prevents replay of an
	// assertion produced for a different challenge, and the substitution of a
	// registration signature for an assertion.
	var collected protocol.CollectedClientData
	if err := json.Unmarshal(clientData, &collected); err != nil {
		return verificationFailed("client_data: " + err.Error())
	}
	if collected.Type != protocol.AssertCeremony {
		return verificationFailed("clientDataJSON type is " + string(collected.Type) + ", want " + string(protocol.AssertCeremony))
	}
	wantChallenge := base64.RawURLEncoding.EncodeToString(challenge.Nonce)
	if subtle.ConstantTimeCompare([]byte(collected.Challenge), []byte(wantChallenge)) != 1 {
		return verificationFailed("clientDataJSON does not bind the issued challenge")
	}

	// WebAuthn signs authenticatorData || SHA-256(clientDataJSON).
	clientDataHash := sha256.Sum256(clientData)
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)

	valid, err := webauthncose.VerifySignature(key, signed, response.Value)
	if err != nil {
		return verificationFailed("verify signature: " + err.Error())
	}
	if !valid {
		return verificationFailed("assertion signature invalid")
	}
	return nil
}

// enrolledKey parses the enrolled COSE credential public key the challenge
// carries. A challenge without one is refused: there is no other source.
func enrolledKey(challenge *qrdbsdk.AuthFactorChallenge) (any, error) {
	encoded, ok := challenge.MethodData[methodDataEnrolledKey].(string)
	if !ok || encoded == "" {
		return nil, verificationFailed(methodDataEnrolledKey + " missing from challenge MethodData")
	}
	cose, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, verificationFailed("decode " + methodDataEnrolledKey + ": " + err.Error())
	}
	key, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return nil, verificationFailed("parse COSE public key: " + err.Error())
	}
	return key, nil
}

// verificationFailed builds the factor's verification refusal.
func verificationFailed(reason string) *qrdbsdk.AuthFactorVerificationFailedError {
	return &qrdbsdk.AuthFactorVerificationFailedError{FactorName: FactorName, Reason: reason}
}

// decodeB64 decodes a metadata value that may be standard or raw-url base64.
func decodeB64(v string) ([]byte, error) {
	if v == "" {
		return nil, &decodeError{reason: "missing from response metadata"}
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, &decodeError{reason: "invalid base64: " + err.Error()}
	}
	return b, nil
}

// extractBytes accepts a value as base64 string or raw []byte.
func extractBytes(v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return nil, &decodeError{reason: "is required"}
	case []byte:
		if len(t) == 0 {
			return nil, &decodeError{reason: "is empty"}
		}
		return t, nil
	case string:
		if t == "" {
			return nil, &decodeError{reason: "is empty"}
		}
		return decodeB64(t)
	default:
		return nil, &decodeError{reason: "must be a base64 string or []byte"}
	}
}

// stringParam returns a MethodParams value as a string when it is a string.
func stringParam(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// decodeError is a typed error for malformed FIDO2 metadata inputs.
type decodeError struct {
	reason string
}

// Error implements the error interface.
func (e *decodeError) Error() string { return e.reason }

// Compile-time interface assertion.
var _ qrdbsdk.AuthFactorPlugin = (*Factor)(nil)
