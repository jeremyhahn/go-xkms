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

package token

import "time"

// NilInputError is returned when a required constructor argument is nil or
// empty.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string { return "auth/token: nil or empty input: " + e.Field }

// InvalidTokenError is returned when a presented token fails signature,
// shape, or claim validation.
type InvalidTokenError struct {
	Reason string
	Err    error
}

// Error implements the error interface.
func (e *InvalidTokenError) Error() string {
	msg := "auth/token: invalid token: " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *InvalidTokenError) Unwrap() error { return e.Err }

// RefreshReuseError is returned when a refresh token that was already rotated
// is presented again. The whole token family is revoked in response: replay
// of a rotated refresh token is the signature of token theft.
type RefreshReuseError struct {
	Family string
}

// Error implements the error interface.
func (e *RefreshReuseError) Error() string {
	return "auth/token: refresh token reuse detected; token family revoked"
}

// RefreshRevokedError is returned when the presented refresh token belongs to
// a family that was revoked (logout or reuse response) or is unknown to the
// store (expired and cleaned, or never issued by this issuer).
type RefreshRevokedError struct{}

// Error implements the error interface.
func (e *RefreshRevokedError) Error() string {
	return "auth/token: refresh token revoked or unknown"
}

// UserRecheckFailedError is returned when Refresh's UserResolver refuses a
// refresh: the account behind the token's subject is disabled, deleted, no
// longer resolves, or the resolver otherwise could not currently vouch for
// it. It wraps the resolver's own error for logging, but every transport
// maps it to the same generic 401 response as RefreshRevokedError -- a
// presented refresh token must not reveal whether it was refused because it
// was revoked or because the account behind it no longer may authenticate.
type UserRecheckFailedError struct {
	Err error
}

// Error implements the error interface.
func (e *UserRecheckFailedError) Error() string {
	return "auth/token: refresh refused: user re-check failed: " + e.Err.Error()
}

// Unwrap returns the resolver's error.
func (e *UserRecheckFailedError) Unwrap() error { return e.Err }

// RefreshRaceLostError is returned when an atomic rotation lost its race: a
// concurrent exchange of the same refresh token rotated the record first, so
// this caller must not receive a successor.
//
// It is deliberately distinct from RefreshReuseError. A lost race is two
// requests arriving inside one round trip, which is the shape of a
// double-submitted client, and it revokes nothing; a rotated token presented
// after the rotation completed is the signature of theft and still revokes the
// whole family. Either way only one successor exists.
type RefreshRaceLostError struct {
	Family string
	JTI    string
}

// Error implements the error interface.
func (e *RefreshRaceLostError) Error() string {
	return "auth/token: refresh token was already rotated by a concurrent request"
}

// FamilyRevokedError is returned when a record cannot be committed because its
// family carries a revocation tombstone. It is how a refresh that raced a
// logout is prevented from leaving a usable successor behind.
type FamilyRevokedError struct {
	Family string
}

// Error implements the error interface.
func (e *FamilyRevokedError) Error() string {
	return "auth/token: refresh token family is revoked; no successor may be issued"
}

// GuardedKVUnsupportedError is returned by NewQRDBRefreshStore when the KV
// client does not carry the atomic conditional-write verbs
// (transport.GuardedKVClient). Refresh-token rotation is decided by a
// compare-and-swap, so a transport without them cannot host the store; the
// store fails to build rather than run a read-then-write two refreshes can
// interleave inside.
type GuardedKVUnsupportedError struct {
	ClientType string
}

// Error implements the error interface.
func (e *GuardedKVUnsupportedError) Error() string {
	return "auth/token: kv client " + e.ClientType +
		" does not implement transport.GuardedKVClient; atomic refresh-token rotation is unavailable on this transport"
}

// ATJWTClientIDRequiredError is returned when Config selects at+jwt access
// tokens without a ClientID: RFC 9068 §2.2 makes client_id REQUIRED in every
// token that header declares.
type ATJWTClientIDRequiredError struct{}

// Error implements the error interface.
func (e *ATJWTClientIDRequiredError) Error() string {
	return "auth/token: at+jwt access tokens require a client ID (RFC 9068 §2.2)"
}

// RefreshTTLTooLongError is returned when a configured refresh lifetime
// outlives the family revocation tombstone that has to guard it. Allowing it
// would let a token outlive the record of its own family's revocation.
type RefreshTTLTooLongError struct {
	TTL time.Duration
	Max time.Duration
}

// Error implements the error interface.
func (e *RefreshTTLTooLongError) Error() string {
	return "auth/token: refresh TTL " + e.TTL.String() +
		" exceeds the revocation tombstone window " + e.Max.String()
}

// StoreError wraps a refresh-store failure.
type StoreError struct {
	Op  string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return "auth/token: refresh store " + e.Op + " failed: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *StoreError) Unwrap() error { return e.Err }

// SigningError wraps a token signing failure.
type SigningError struct {
	Err error
}

// Error implements the error interface.
func (e *SigningError) Error() string { return "auth/token: signing failed: " + e.Err.Error() }

// Unwrap returns the underlying error.
func (e *SigningError) Unwrap() error { return e.Err }
