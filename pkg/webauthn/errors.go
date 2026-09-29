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
	"errors"
	"fmt"
)

// Sentinel errors for WebAuthn operations.
var (
	// ErrUserNotFound is returned when a user cannot be found.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserAlreadyExists is returned when attempting to create a user that already exists.
	ErrUserAlreadyExists = errors.New("user already exists")

	// ErrCredentialNotFound is returned when a credential cannot be found.
	ErrCredentialNotFound = errors.New("credential not found")

	// ErrCredentialAlreadyExists is returned when attempting to register a duplicate credential.
	ErrCredentialAlreadyExists = errors.New("credential already exists")

	// ErrSessionNotFound is returned when a session cannot be found or has expired.
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when a session has expired.
	ErrSessionExpired = errors.New("session expired")

	// ErrInvalidSession is returned when session data is invalid.
	ErrInvalidSession = errors.New("invalid session data")

	// ErrInvalidCredential is returned when credential data is invalid.
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrInvalidRequest is returned when the request is malformed.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrInvalidResponse is returned when the authenticator response is invalid.
	ErrInvalidResponse = errors.New("invalid authenticator response")

	// ErrVerificationFailed is returned when credential verification fails.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrNoCredentials is returned when a user has no registered credentials.
	ErrNoCredentials = errors.New("user has no registered credentials")

	// ErrClonedAuthenticator is returned when a cloned authenticator is detected.
	ErrClonedAuthenticator = errors.New("cloned authenticator detected")

	// ErrNotConfigured is returned when the service is not properly configured.
	ErrNotConfigured = errors.New("webauthn service not configured")

	// ErrRegistrationRefused is returned by the public BeginRegistration when
	// the email may not start an unauthenticated registration ceremony: the
	// account already has one or more credentials (adding a passkey to it
	// requires a session authenticated as that account, see
	// BeginAddCredential — go-xkms#1294), or the email names no account and
	// the relying party has open sign-up turned off
	// (webauthn.allow_public_registration = false). Both cases return this
	// one error so the response does not reveal whether the account exists
	// (go-xkms#1296).
	ErrRegistrationRefused = errors.New("webauthn: registration refused; sign in to add a passkey to an existing account, or ask an administrator to provision one")

	// ErrSessionAccountMismatch is returned by BeginAddCredential when the
	// authenticated session does not identify an existing WebAuthn account:
	// the session was not minted for a WebAuthn account, or the account it
	// names no longer matches (unknown handle, or a different email).
	ErrSessionAccountMismatch = errors.New("webauthn: the authenticated session does not identify a webauthn account")

	// ErrCredentialOwnerMismatch is returned by CredentialStore.Update when
	// the stored credential belongs to a different user than the update
	// names. A credential's owner is fixed at registration.
	ErrCredentialOwnerMismatch = errors.New("credential belongs to a different user")

	// ErrCredentialUpdateConflict is returned by CredentialStore.Update when
	// the credential record changed between the owner check and the write
	// (a concurrent update or delete); the stale update is not applied.
	ErrCredentialUpdateConflict = errors.New("credential changed concurrently; update not applied")
)

// AccountNotActiveError reports an account whose lifecycle state does not
// permit authentication or passkey enrolment: anything other than
// qrdbsdk.LifecycleActive. It is operator detail; the Service never returns
// it to a client (see CheckAccountStanding).
type AccountNotActiveError struct {
	// Account is the account's WebAuthn name (its email login key).
	Account string

	// Lifecycle is the account's state, as the store reports it.
	Lifecycle string
}

// Error names the account and its state.
func (e *AccountNotActiveError) Error() string {
	return "webauthn: account " + e.Account + " is not active (lifecycle " + e.Lifecycle + ")"
}

// SessionLimitError reports that the session store already holds its
// maximum number of unfinished ceremonies, so a new ceremony cannot begin
// until sessions complete or expire. Transports serve it as 503 Service
// Unavailable (gRPC ResourceExhausted): the condition is transient and the
// caller should retry later.
type SessionLimitError struct {
	// Limit is the store's session cap.
	Limit int
}

// Error describes the exhausted capacity.
func (e *SessionLimitError) Error() string {
	return fmt.Sprintf("webauthn: session store is full (%d unfinished ceremonies)", e.Limit)
}

// IsSessionLimit reports whether err is, or wraps, a *SessionLimitError.
func IsSessionLimit(err error) bool {
	var limitErr *SessionLimitError
	return errors.As(err, &limitErr)
}

// WebAuthnError wraps an error with additional context.
type WebAuthnError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

// Error returns the error message.
func (e *WebAuthnError) Error() string {
	if e.Op != "" {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *WebAuthnError) Unwrap() error {
	return e.Err
}

// Is reports whether the target error matches.
func (e *WebAuthnError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewError creates a new WebAuthnError with the given operation and error.
func NewError(op string, err error) error {
	return &WebAuthnError{
		Op:  op,
		Err: err,
	}
}

// WrapError wraps an error with an operation name if it's not nil.
func WrapError(op string, err error) error {
	if err == nil {
		return nil
	}
	return NewError(op, err)
}

// IsUserNotFound returns true if the error indicates a user was not found.
func IsUserNotFound(err error) bool {
	return errors.Is(err, ErrUserNotFound)
}

// IsCredentialNotFound returns true if the error indicates a credential was not found.
func IsCredentialNotFound(err error) bool {
	return errors.Is(err, ErrCredentialNotFound)
}

// IsSessionNotFound returns true if the error indicates a session was not found.
func IsSessionNotFound(err error) bool {
	return errors.Is(err, ErrSessionNotFound)
}

// IsSessionExpired returns true if the error indicates a session has expired.
func IsSessionExpired(err error) bool {
	return errors.Is(err, ErrSessionExpired)
}

// IsVerificationFailed returns true if the error indicates verification failed.
func IsVerificationFailed(err error) bool {
	return errors.Is(err, ErrVerificationFailed)
}

// NewVerificationError wraps a credential-verification failure (a go-webauthn
// protocol error from attestation or assertion validation) so that it satisfies
// errors.Is(err, ErrVerificationFailed). Transports use this classification to
// return 401 Unauthorized for a forged or invalid credential rather than a 500.
// Errors that are NOT protocol-level verification failures (for example a
// storage fault) must not be passed here; wrap those with WrapError instead.
func NewVerificationError(op string, err error) error {
	return &WebAuthnError{
		Op:  op,
		Err: errors.Join(ErrVerificationFailed, err),
	}
}

// LoginFinishFailure classifies an error Service.FinishLogin or
// Service.FinishLoginPair returned, for a login-finish response. Every
// transport that exposes WebAuthn login finish (the browser route, gRPC, SDK
// REST) classifies its error through ClassifyLoginFinish, and this type, so
// a decoy ceremony's failure is byte-identical -- on every transport -- to a
// genuine wrong assertion against a real account (go-xkms#1296, go-xkms#1298,
// go-xkms#1310).
type LoginFinishFailure int

const (
	// LoginFinishInternal is a failure that is not a session-claim error and
	// does not satisfy errors.Is(err, ErrVerificationFailed): a genuine
	// server-side fault (for example a storage error) unrelated to the
	// caller's account or assertion. Transports serve it as their ordinary
	// internal-error response; unlike LoginFinishFailed it carries no
	// enumeration risk, since it happens identically regardless of which
	// account, real or decoy, the caller named.
	LoginFinishInternal LoginFinishFailure = iota

	// LoginFinishSessionNotFound reports that the session is missing or was
	// already consumed. It reflects the caller's own ceremony bookkeeping,
	// not a guess about an account, so it is reported distinctly rather than
	// folded into LoginFinishFailed.
	LoginFinishSessionNotFound

	// LoginFinishSessionExpired reports that the session existed but its TTL
	// elapsed before finish. Reported distinctly for the same reason as
	// LoginFinishSessionNotFound.
	LoginFinishSessionExpired

	// LoginFinishFailed is every login-finish failure that must not be
	// distinguishable from any other: a wrong assertion, an unknown or
	// refused account, an account not in standing, an unknown credential, or
	// a protocol-level parse failure of the assertion. A transport must
	// serve exactly one fixed response for this outcome, carrying no detail
	// that would tell one cause apart from another.
	LoginFinishFailed
)

// ClassifyLoginFinish classifies err, the error Service.FinishLogin or
// Service.FinishLoginPair returned (or a transport's wrapping of it that
// preserves the error chain), into a LoginFinishFailure. Every transport's
// login-finish handler must call this -- and only this -- to decide the
// client-visible outcome, so the classification lives in one place and every
// transport agrees with it.
func ClassifyLoginFinish(err error) LoginFinishFailure {
	switch {
	case errors.Is(err, ErrSessionNotFound):
		return LoginFinishSessionNotFound
	case errors.Is(err, ErrSessionExpired):
		return LoginFinishSessionExpired
	case errors.Is(err, ErrVerificationFailed):
		return LoginFinishFailed
	default:
		return LoginFinishInternal
	}
}
