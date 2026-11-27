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

package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// AssertionVerification is a WebAuthn assertion over a challenge the caller
// generated and holds, verified outside the Begin/Finish login ceremony.
type AssertionVerification struct {
	// Challenge is the raw challenge the caller issued. Required.
	Challenge []byte

	// RPID is the relying party ID whose SHA-256 the authenticator data must
	// carry. Empty uses the service's configured RP ID.
	RPID string

	// Origins are the origins clientDataJSON may name. Empty uses the
	// service's configured origins.
	Origins []string

	// RequireUserPresence refuses an assertion without the UP flag.
	RequireUserPresence bool

	// RequireUserVerification refuses an assertion without the UV flag.
	RequireUserVerification bool

	// Credential is the registered credential the assertion must be made
	// with: its ID, COSE public key and last sign counter. Required.
	Credential *Credential

	// Assertion is the client's response; its raw clientDataJSON,
	// authenticator data and signature are verified. Required.
	Assertion *protocol.ParsedCredentialAssertionData
}

// VerifyAssertion verifies an assertion over the caller's challenge
// (WebAuthn L3 §7.2): the ceremony type, challenge and origin of
// clientDataJSON, the RP ID hash, the required UP and UV flags, the
// signature against the credential's public key and the sign counter. It
// returns the authenticator's new sign counter. When the service's
// credential store holds the credential, the counter is checked against the
// stored value too and the new value is saved. Each failed check returns its
// own typed error, all matching ErrVerificationFailed.
func (s *Service) VerifyAssertion(ctx context.Context, req *AssertionVerification) (uint32, error) {
	if req == nil {
		return 0, &AssertionRequestError{Field: "AssertionVerification"}
	}
	if len(req.Challenge) == 0 {
		return 0, &AssertionRequestError{Field: "Challenge"}
	}
	if req.Credential == nil || len(req.Credential.ID) == 0 || len(req.Credential.PublicKey) == 0 {
		return 0, &AssertionRequestError{Field: "Credential"}
	}
	if req.Assertion == nil {
		return 0, &AssertionRequestError{Field: "Assertion"}
	}
	rpID, origins := req.RPID, req.Origins
	if s.config != nil {
		if rpID == "" {
			rpID = s.config.RPID
		}
		if len(origins) == 0 {
			origins = s.config.RPOrigins
		}
	}
	if rpID == "" {
		return 0, &AssertionRequestError{Field: "RPID"}
	}
	if len(origins) == 0 {
		return 0, &AssertionRequestError{Field: "Origins"}
	}

	raw := req.Assertion.Raw.AssertionResponse
	if !bytes.Equal(req.Assertion.RawID, req.Credential.ID) {
		return 0, &AssertionCredentialMismatchError{}
	}

	var clientData protocol.CollectedClientData
	if err := json.Unmarshal(raw.ClientDataJSON, &clientData); err != nil {
		return 0, &AssertionClientDataError{Err: err}
	}
	if clientData.Type != protocol.AssertCeremony {
		return 0, &AssertionCeremonyTypeError{Type: string(clientData.Type)}
	}
	got, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(clientData.Challenge, "="))
	if err != nil || subtle.ConstantTimeCompare(got, req.Challenge) != 1 {
		return 0, &AssertionChallengeMismatchError{}
	}
	if !slices.Contains(origins, clientData.Origin) {
		return 0, &AssertionOriginError{Origin: clientData.Origin}
	}

	var authData protocol.AuthenticatorData
	if err := authData.Unmarshal(raw.AuthenticatorData); err != nil {
		return 0, &AssertionAuthenticatorDataError{Err: err}
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(authData.RPIDHash, rpIDHash[:]) != 1 {
		return 0, &AssertionRPIDHashError{RPID: rpID}
	}
	if req.RequireUserPresence && !authData.Flags.HasUserPresent() {
		return 0, &AssertionUserPresenceError{}
	}
	if req.RequireUserVerification && !authData.Flags.HasUserVerified() {
		return 0, &AssertionUserVerificationError{}
	}

	key, err := webauthncose.ParsePublicKey(req.Credential.PublicKey)
	if err != nil {
		return 0, &AssertionSignatureError{Err: err}
	}
	clientDataHash := sha256.Sum256(raw.ClientDataJSON)
	ok, err := webauthncose.VerifySignature(key, slices.Concat([]byte(raw.AuthenticatorData), clientDataHash[:]), raw.Signature)
	if err != nil || !ok {
		return 0, &AssertionSignatureError{Err: err}
	}

	stored := req.Credential.Authenticator.SignCount
	var record *Credential
	if s.creds != nil {
		record, err = s.creds.GetByCredentialID(ctx, req.Credential.ID)
		switch {
		case err == nil:
			stored = max(stored, record.Authenticator.SignCount)
		case IsCredentialNotFound(err):
			record = nil
		default:
			return 0, WrapError("get credential", err)
		}
	}
	if (stored != 0 || authData.Counter != 0) && authData.Counter <= stored {
		return 0, &AssertionSignCountError{Stored: stored, Received: authData.Counter}
	}

	if record != nil {
		record.Authenticator.SignCount = authData.Counter
		record.LastUsedAt = time.Now().UTC()
		if err := s.creds.Update(ctx, record); err != nil {
			return 0, WrapError("update credential", err)
		}
	}
	return authData.Counter, nil
}

// AssertionRequestError reports an AssertionVerification missing a field
// VerifyAssertion needs.
type AssertionRequestError struct {
	// Field names the missing input.
	Field string
}

func (e *AssertionRequestError) Error() string {
	return "webauthn: assertion verification: missing " + e.Field
}

// Is matches ErrInvalidRequest.
func (e *AssertionRequestError) Is(target error) bool { return target == ErrInvalidRequest }

// AssertionCredentialMismatchError reports an assertion made with a
// credential other than the one the caller named.
type AssertionCredentialMismatchError struct{}

func (e *AssertionCredentialMismatchError) Error() string {
	return "webauthn: assertion credential ID does not match the stored credential"
}

// Is matches ErrVerificationFailed.
func (e *AssertionCredentialMismatchError) Is(target error) bool {
	return target == ErrVerificationFailed
}

// AssertionClientDataError reports clientDataJSON that does not parse.
type AssertionClientDataError struct {
	Err error
}

func (e *AssertionClientDataError) Error() string {
	return fmt.Sprintf("webauthn: assertion clientDataJSON: %v", e.Err)
}

func (e *AssertionClientDataError) Unwrap() error { return e.Err }

// Is matches ErrVerificationFailed.
func (e *AssertionClientDataError) Is(target error) bool { return target == ErrVerificationFailed }

// AssertionCeremonyTypeError reports clientDataJSON whose type is not
// "webauthn.get".
type AssertionCeremonyTypeError struct {
	// Type is the type clientDataJSON carries.
	Type string
}

func (e *AssertionCeremonyTypeError) Error() string {
	return fmt.Sprintf("webauthn: assertion clientDataJSON type %q is not webauthn.get", e.Type)
}

// Is matches ErrVerificationFailed.
func (e *AssertionCeremonyTypeError) Is(target error) bool { return target == ErrVerificationFailed }

// AssertionChallengeMismatchError reports clientDataJSON over a challenge
// other than the caller's.
type AssertionChallengeMismatchError struct{}

func (e *AssertionChallengeMismatchError) Error() string {
	return "webauthn: assertion challenge does not match the caller's challenge"
}

// Is matches ErrVerificationFailed.
func (e *AssertionChallengeMismatchError) Is(target error) bool {
	return target == ErrVerificationFailed
}

// AssertionOriginError reports clientDataJSON naming an origin not allowed.
type AssertionOriginError struct {
	// Origin is the origin clientDataJSON carries.
	Origin string
}

func (e *AssertionOriginError) Error() string {
	return fmt.Sprintf("webauthn: assertion origin %q is not allowed", e.Origin)
}

// Is matches ErrVerificationFailed.
func (e *AssertionOriginError) Is(target error) bool { return target == ErrVerificationFailed }

// AssertionAuthenticatorDataError reports authenticator data that does not
// parse.
type AssertionAuthenticatorDataError struct {
	Err error
}

func (e *AssertionAuthenticatorDataError) Error() string {
	return fmt.Sprintf("webauthn: assertion authenticator data: %v", e.Err)
}

func (e *AssertionAuthenticatorDataError) Unwrap() error { return e.Err }

// Is matches ErrVerificationFailed.
func (e *AssertionAuthenticatorDataError) Is(target error) bool {
	return target == ErrVerificationFailed
}

// AssertionRPIDHashError reports authenticator data whose RP ID hash is not
// SHA-256 of the expected RP ID.
type AssertionRPIDHashError struct {
	// RPID is the expected relying party ID.
	RPID string
}

func (e *AssertionRPIDHashError) Error() string {
	return fmt.Sprintf("webauthn: assertion RP ID hash does not match %q", e.RPID)
}

// Is matches ErrVerificationFailed.
func (e *AssertionRPIDHashError) Is(target error) bool { return target == ErrVerificationFailed }

// AssertionUserPresenceError reports an assertion without the UP flag the
// caller requires.
type AssertionUserPresenceError struct{}

func (e *AssertionUserPresenceError) Error() string {
	return "webauthn: assertion lacks the required user presence flag"
}

// Is matches ErrVerificationFailed.
func (e *AssertionUserPresenceError) Is(target error) bool { return target == ErrVerificationFailed }

// AssertionUserVerificationError reports an assertion without the UV flag
// the caller requires.
type AssertionUserVerificationError struct{}

func (e *AssertionUserVerificationError) Error() string {
	return "webauthn: assertion lacks the required user verification flag"
}

// Is matches ErrVerificationFailed.
func (e *AssertionUserVerificationError) Is(target error) bool {
	return target == ErrVerificationFailed
}

// AssertionSignatureError reports a signature the credential's public key
// does not verify, or a public key that does not parse.
type AssertionSignatureError struct {
	// Err is the parse or verification error, nil for a wrong signature.
	Err error
}

func (e *AssertionSignatureError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("webauthn: assertion signature: %v", e.Err)
	}
	return "webauthn: assertion signature does not verify"
}

func (e *AssertionSignatureError) Unwrap() error { return e.Err }

// Is matches ErrVerificationFailed.
func (e *AssertionSignatureError) Is(target error) bool { return target == ErrVerificationFailed }

// AssertionSignCountError reports a sign counter that did not advance past
// the stored one, a sign of a cloned authenticator or a replay.
type AssertionSignCountError struct {
	// Stored is the last counter the relying party recorded.
	Stored uint32
	// Received is the counter the assertion carries.
	Received uint32
}

func (e *AssertionSignCountError) Error() string {
	return fmt.Sprintf("webauthn: assertion sign counter %d does not exceed the stored %d", e.Received, e.Stored)
}

// Is matches ErrVerificationFailed and ErrClonedAuthenticator.
func (e *AssertionSignCountError) Is(target error) bool {
	return target == ErrVerificationFailed || target == ErrClonedAuthenticator
}
