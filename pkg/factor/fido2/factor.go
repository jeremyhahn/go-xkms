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
// authenticatorData attested credential key), the credential id, rp id, the
// expected clientData origin(s), and whether the assertion must carry user
// verification (not just presence). Challenge issues a random WebAuthn
// challenge nonce and carries the enrolled COSE key, rp id, origins, and UV
// requirement with it. Verify checks the assertion's rpIdHash and
// user-presence flag (and, when the enrollment requires it, the
// user-verified flag), the clientDataJSON ceremony type, challenge and
// origin (via the canonical go-webauthn protocol helpers), then reconstructs
// the WebAuthn signed message -- authenticatorData || SHA-256(clientDataJSON)
// -- and verifies the assertion signature against the enrolled COSE public
// key using the canonical go-webauthn webauthncose verifier. This is the
// same signature check the go-xkms WebAuthn relying party performs in
// FinishLogin; there is no stubbed always-pass path.
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
	"strings"
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

	// methodDataOrigins is the challenge MethodData key carrying the enrolled
	// expected clientData origin(s) ([]string). Verify refuses a response
	// whose clientDataJSON "origin" is not exactly one of these, per WebAuthn
	// L2/L3 assertion verification step 9.
	methodDataOrigins = "origins"

	// methodDataRequireUV is the challenge MethodData key carrying whether
	// the enrollment requires the assertion's user-verified flag, not just
	// user-presence.
	methodDataRequireUV = "require_uv"
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
//	"cose_public_key"             string  base64-encoded COSE public key (required)
//	"credential_id"               string  base64url-encoded credential id (required)
//	"rp_id"                       string  Relying Party id; defaults to Config.RPID
//	"aaguid"                      string  authenticator AAGUID (recorded as metadata)
//	"origins"                     string or []string  expected clientData origin(s);
//	                                      defaults to ["https://" + rp_id]
//	"require_user_verification"   bool    whether Verify requires the assertion's
//	                                      user-verified flag, not just user-presence;
//	                                      defaults to true, the WebAuthn/CTAP2 best
//	                                      practice for a factor used to unseal or
//	                                      authenticate
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

	origins, err := originsParam(params.MethodParams["origins"], rpID)
	if err != nil {
		return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "fido2: origins " + err.Error()}
	}

	requireUV := true
	if v, ok := params.MethodParams["require_user_verification"]; ok {
		requireUV, err = boolParam(v)
		if err != nil {
			return nil, &qrdbsdk.AuthFactorEnrollmentInvalidError{Reason: "fido2: require_user_verification " + err.Error()}
		}
	}

	metadata := map[string]string{
		"credential_id": credentialID,
		"rp_id":         rpID,
		"ttl":           strconv.Itoa(f.cfg.ChallengeTTLSeconds),
		"origins":       strings.Join(origins, ","),
		"require_uv":    strconv.FormatBool(requireUV),
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
// public key (MethodData["enrolled_cose_public_key"], standard base64), rp id
// (MethodData["rp_id"]), expected origin(s) (MethodData["origins"]) and the
// user-verification requirement (MethodData["require_uv"]) travel with the
// challenge so Verify checks the assertion against the server-held enrollment
// rather than anything the response supplies.
//
// An enrollment recorded before "origins" or "require_uv" existed (or with
// either otherwise malformed) leaves the corresponding MethodData key unset;
// Verify treats that the same as any other tampered or incomplete challenge
// and refuses.
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
	methodData := map[string]any{
		"challenge_base64":    base64.RawURLEncoding.EncodeToString(nonce),
		methodDataRPID:        enrollment.Metadata["rp_id"],
		"credential_id":       enrollment.Metadata["credential_id"],
		methodDataEnrolledKey: base64.StdEncoding.EncodeToString(enrollment.PublicKey),
	}
	if v := enrollment.Metadata["origins"]; v != "" {
		methodData[methodDataOrigins] = strings.Split(v, ",")
	}
	if v, err := strconv.ParseBool(enrollment.Metadata["require_uv"]); err == nil {
		methodData[methodDataRequireUV] = v
	}
	return &qrdbsdk.AuthFactorChallenge{
		ChallengeID:  qrdbsdk.NewAuthFactorChallengeID(),
		EnrollmentID: enrollment.EnrollmentID,
		Nonce:        nonce,
		ExpiresAt:    time.Now().UTC().Add(time.Duration(ttl) * time.Second),
		MethodData:   methodData,
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
// with SHA-256 of the enrolled rp id and has the user-present flag set (and,
// when the enrollment requires it, the user-verified flag); clientDataJSON is
// a "webauthn.get" ceremony whose challenge is the issued nonce (base64url)
// and whose origin exactly matches one the enrollment recorded; the signature
// over authenticatorData || SHA-256(clientDataJSON) verifies under the
// enrolled COSE key.
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

	// The enrollment records whether this factor requires user verification
	// (not just presence) — the WebAuthn/CTAP2 best practice default for a
	// factor used to unseal or authenticate. An enrollment recorded before
	// this requirement existed carries no MethodData for it and is refused,
	// same as any other missing enrollment field.
	requireUV, ok := challenge.MethodData[methodDataRequireUV].(bool)
	if !ok {
		return verificationFailed(methodDataRequireUV + " missing from challenge MethodData")
	}
	if requireUV && !parsed.Flags.UserVerified() {
		return verificationFailed("authenticator_data user-verified flag is not set")
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

	// The enrollment records the expected clientData origin(s); the
	// assertion's origin must exactly match one of them (WebAuthn L2/L3 §7.2
	// step 9), checked with the canonical go-webauthn origin comparator
	// rather than a naive string equality.
	origins, ok := challenge.MethodData[methodDataOrigins].([]string)
	if !ok || len(origins) == 0 {
		return verificationFailed(methodDataOrigins + " missing from challenge MethodData")
	}
	if !protocol.IsOriginInHaystack(collected.Origin, origins) {
		return verificationFailed("clientDataJSON origin does not match an enrolled origin")
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

// originsParam resolves the "origins" MethodParams value: a single origin
// string, a []string, or a []any of strings. Nil defaults to the single
// origin "https://" + rpID, the same default the FIDO2 local CTAP2 ceremony
// uses when driving an attached authenticator.
func originsParam(v any, rpID string) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return []string{"https://" + rpID}, nil
	case string:
		if t == "" {
			return nil, &decodeError{reason: "must not be empty"}
		}
		return []string{t}, nil
	case []string:
		if len(t) == 0 {
			return nil, &decodeError{reason: "must not be empty"}
		}
		out := make([]string, len(t))
		copy(out, t)
		return out, nil
	case []any:
		if len(t) == 0 {
			return nil, &decodeError{reason: "must not be empty"}
		}
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, &decodeError{reason: "must be non-empty strings"}
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, &decodeError{reason: "must be a string or []string"}
	}
}

// boolParam resolves a MethodParams value as a bool, accepting a native bool
// or a parseable string.
func boolParam(v any) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case string:
		b, err := strconv.ParseBool(t)
		if err != nil {
			return false, &decodeError{reason: "must be a bool"}
		}
		return b, nil
	default:
		return false, &decodeError{reason: "must be a bool"}
	}
}

// decodeError is a typed error for malformed FIDO2 metadata inputs.
type decodeError struct {
	reason string
}

// Error implements the error interface.
func (e *decodeError) Error() string { return e.reason }

// Compile-time interface assertion.
var _ qrdbsdk.AuthFactorPlugin = (*Factor)(nil)
