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
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// WebAuthnFactorVerifier adapts xkms's pkg/webauthn.Service to qrdb's
// FactorVerifier interface. It is registered with the qrdb embedded
// transport via WithFactorVerifier so FactorClient.Verify routes WebAuthn
// challenges through xkms's WebAuthn relying-party logic.
//
// The adapter's Verify path:
//
//  1. Confirm factor is active (RevokedAt == nil). qrdb's resolver
//     pre-checks but defense-in-depth here.
//  2. Confirm the persisted Credential lookup-key matches the challenge
//     identifier (FactorID or MethodMetadata["credential_id"]).
//  3. Drive xkms's webauthn.Service.FinishLogin with the supplied session
//     id (carried in MethodMetadata["session_id"]) and assertion bytes.
//     FinishLogin refuses an account that is not active or whose
//     auth-method policy withdraws WebAuthn, so no factor is satisfied for
//     it (go-xkms#1298).
//
// FactorClient.Enroll persists the credential record on the qrdb side and
// is the canonical path for new factors. Hardware-side enrollment is
// performed by xkms's BeginRegistration / FinishRegistration flow exposed
// through the xkms HTTP handlers; this adapter validates assertions only.
type WebAuthnFactorVerifier struct {
	service *xkmswebauthn.Service
}

// NewWebAuthnFactorVerifier constructs a verifier wrapping the given xkms
// webauthn service. The service must already be configured with a User /
// Session / Credential store.
func NewWebAuthnFactorVerifier(service *xkmswebauthn.Service) (*WebAuthnFactorVerifier, error) {
	if service == nil {
		return nil, &NilServiceError{Adapter: "webauthn"}
	}
	return &WebAuthnFactorVerifier{service: service}, nil
}

// Type returns transport.FactorTypeFIDO2.
func (v *WebAuthnFactorVerifier) Type() qrdbtransport.FactorType {
	return qrdbtransport.FactorTypeFIDO2
}

// Verify exercises xkms's WebAuthn verification path for the given
// challenge against the persisted factor.
//
// The challenge MUST carry:
//
//   - challenge.MethodMetadata["session_id"]: the WebAuthn session id
//     returned by an earlier BeginLogin call.
//   - challenge.MethodMetadata["assertion"]: the base64url-encoded
//     parsed assertion JSON. Implementations that pre-parse the
//     assertion may pass it via challenge.Signature.
//
// On success, returns nil. On any failure, returns a typed error.
func (v *WebAuthnFactorVerifier) Verify(ctx context.Context, factor *qrdbsdk.AuthFactor, challenge qrdbtransport.VerifyChallenge) error {
	if v.service == nil {
		return &NilServiceError{Adapter: "webauthn"}
	}
	if factor == nil {
		return &MissingFactorError{}
	}
	if factor.RevokedAt != nil {
		return &qrdbsdk.FactorRevokedError{FactorID: factor.ID}
	}
	if factor.Type != qrdbsdk.AuthFactorFIDO2 {
		return &qrdbsdk.FactorTypeUnsupportedError{Type: string(factor.Type)}
	}

	// Confirm the credential id matches what was enrolled. The challenge
	// either passes the credential id explicitly (preferred — the WebAuthn
	// assertion itself carries it) or we trust the FactorID alone.
	if credID := challenge.MethodMetadata["credential_id"]; credID != "" {
		if !bytes.Equal([]byte(credID), factor.Credential) && credID != string(factor.Credential) {
			return &CredentialMismatchError{}
		}
	}

	// Look up the underlying webauthn user by handle. The factor's
	// UserID is the qrdb uint64 user id; xkms webauthn uses an 8-byte
	// big-endian byte handle. xkmswebauthn.HandleFromUserID is the single
	// source of truth for that encoding (see pkg/webauthn/qrdb_userstore.go).
	// A caller that passes an opaque handle through
	// MethodMetadata["user_handle_b64"] wins out; otherwise we derive the
	// handle from factor.UserID so the assertion is scoped to the owning
	// user rather than relying solely on the discoverable-credential flow.
	if challenge.MethodMetadata == nil {
		return &MissingMethodMetadataError{Field: "session_id"}
	}
	sessionID := challenge.MethodMetadata["session_id"]
	if sessionID == "" {
		return &MissingMethodMetadataError{Field: "session_id"}
	}

	// Parse the WebAuthn assertion the client produced. It arrives either as
	// the base64url/JSON blob in MethodMetadata["assertion"] (the unified
	// login path threads it there) or, for callers that route it through the
	// signature field, in challenge.Signature.
	assertionRaw := challenge.MethodMetadata["assertion"]
	if assertionRaw == "" && len(challenge.Signature) > 0 {
		assertionRaw = string(challenge.Signature)
	}
	if assertionRaw == "" {
		return &MissingMethodMetadataError{Field: "assertion"}
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(assertionRaw))
	if err != nil {
		return &SignatureVerifyError{Reason: "parse webauthn assertion: " + err.Error()}
	}

	// Resolve the WebAuthn user handle. An explicit caller-supplied handle
	// wins; otherwise we derive it from the factor's qrdb uint64 user id so
	// the assertion is bound to the owning user. A zero UserID leaves the
	// handle nil, driving the discoverable-credential flow where the
	// assertion's credential id identifies the user within the session.
	var userID []byte
	if uh := challenge.MethodMetadata["user_handle_b64"]; uh != "" {
		if decoded, derr := base64.RawURLEncoding.DecodeString(uh); derr == nil {
			userID = decoded
		}
	}
	if userID == nil && factor.UserID != 0 {
		userID = xkmswebauthn.HandleFromUserID(factor.UserID)
	}

	// FinishLogin verifies the assertion signature, RP id/origin, and sign
	// counter against the stored credential and consumes the session. A nil
	// error means the proof-of-possession is valid.
	if _, _, ferr := v.service.FinishLogin(ctx, sessionID, userID, parsed); ferr != nil {
		return &SignatureVerifyError{Reason: "webauthn assertion verification failed: " + ferr.Error()}
	}
	return nil
}

// BeginChallenge implements the qrdb embedded FactorChallenger capability so
// WebAuthn login flows through the unified qrdb Begin/Finish ceremony. It opens
// a WebAuthn assertion ceremony on the relying-party service and returns the
// raw challenge bytes (qrdb's "nonce") plus the metadata the client needs to
// drive navigator.credentials.get() and that the verifier needs at FinishLogin:
//
//   - metadata["options"]:    the JSON PublicKeyCredentialRequestOptions.
//   - metadata["session_id"]: the RP session id (echoed back at Verify time).
//
// tenantID scopes per-tenant RP configuration; for a single-RP service it is
// advisory. An empty hint drives the discoverable-credential flow.
func (v *WebAuthnFactorVerifier) BeginChallenge(ctx context.Context, tenantID string, factorType qrdbtransport.FactorType, hint string) ([]byte, map[string]string, time.Time, error) {
	if v == nil || v.service == nil {
		return nil, nil, time.Time{}, &NilServiceError{Adapter: "webauthn"}
	}
	if factorType != qrdbtransport.FactorTypeFIDO2 {
		return nil, nil, time.Time{}, &qrdbsdk.FactorTypeUnsupportedError{Type: string(factorType)}
	}

	// A non-empty hint (username/email) scopes the ceremony to that user's
	// credentials; otherwise nil requests a discoverable-credential ceremony.
	// An account that may not log in (xkmswebauthn.CheckAccountStanding) is
	// treated exactly like an unknown hint, so the ceremony's shape does not
	// reveal its state; Verify refuses it regardless (go-xkms#1298).
	var userID []byte
	if hint != "" {
		if u, uErr := v.service.GetUserByEmail(ctx, hint); uErr == nil && u != nil && xkmswebauthn.CheckAccountStanding(u) == nil {
			userID = u.WebAuthnID()
		}
	}

	options, sessionID, err := v.service.BeginLogin(ctx, userID)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	meta := map[string]string{
		"session_id": sessionID,
		"options":    string(optionsJSON),
	}
	return []byte(options.Response.Challenge), meta, time.Time{}, nil
}

// Compile-time interface assertion. The qrdb embedded transport's
// FactorVerifier is the contract this adapter satisfies; it lives in
// the embedded sub-package, so we only confirm the structural method
// set here (Type / Verify) and assert at the registration site in
// pkg/sdk/auth.go.
var _ qrdbWebAuthnVerifier = (*WebAuthnFactorVerifier)(nil)

// qrdbWebAuthnVerifier mirrors the embedded.FactorVerifier shape so
// auth_factors does not import the embedded sub-package directly. The
// SDK wiring file performs the embedded.FactorVerifier registration.
type qrdbWebAuthnVerifier interface {
	Type() qrdbtransport.FactorType
	Verify(ctx context.Context, factor *qrdbsdk.AuthFactor, challenge qrdbtransport.VerifyChallenge) error
}

// NilServiceError is returned when the adapter is constructed with a
// nil service or used before a service is wired.
type NilServiceError struct {
	Adapter string
}

// Error implements error.
func (e *NilServiceError) Error() string {
	if e == nil || e.Adapter == "" {
		return "auth_factors: nil service"
	}
	return "auth_factors: nil " + e.Adapter + " service"
}

// MissingFactorError is returned when Verify is called with a nil
// factor argument.
type MissingFactorError struct{}

// Error implements error.
func (e *MissingFactorError) Error() string {
	return "auth_factors: factor is nil"
}

// CredentialMismatchError is returned when the challenge identifies a
// credential that does not match the persisted factor.
type CredentialMismatchError struct{}

// Error implements error.
func (e *CredentialMismatchError) Error() string {
	return "auth_factors: challenge credential does not match persisted factor"
}

// MissingMethodMetadataError is returned when the challenge omits a
// required MethodMetadata field.
type MissingMethodMetadataError struct {
	// Field is the missing key name.
	Field string
}

// Error implements error.
func (e *MissingMethodMetadataError) Error() string {
	if e == nil || e.Field == "" {
		return "auth_factors: missing method metadata"
	}
	return "auth_factors: missing method metadata: " + e.Field
}

// VerifyNotSupportedError is returned when the verifier cannot complete
// the requested verification path through this entry-point.
type VerifyNotSupportedError struct {
	Reason string
}

// Error implements error.
func (e *VerifyNotSupportedError) Error() string {
	if e == nil || e.Reason == "" {
		return "auth_factors: verification not supported"
	}
	return "auth_factors: verification not supported: " + e.Reason
}

// errBadChallenge is a sentinel wrapper to allow errors.Is() consumers
// to detect the unsupported path without type-asserting against the
// concrete type.
var errBadChallenge = errors.New("auth_factors: bad challenge")

// Is implements errors.Is for VerifyNotSupportedError so callers can
// treat the path as a generic bad-challenge condition when desired.
func (e *VerifyNotSupportedError) Is(target error) bool {
	return target == errBadChallenge
}
