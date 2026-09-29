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

package importtoken

import "fmt"

// NotFoundError reports that a token is unknown to the Store, either
// because it was never issued, it was already consumed by Take, or it
// expired and was swept. The three cases are indistinguishable by design:
// telling an attacker which one occurred would confirm whether a guessed
// token had ever been valid.
type NotFoundError struct {
	// Token is the import token that was not found.
	Token string
}

// Error implements the error interface.
func (e *NotFoundError) Error() string {
	return fmt.Sprintf("importtoken: token not found or expired: %s", e.Token)
}

// LimitExceededError reports that a Store is at capacity and refused a new
// token rather than evicting a live one to make room.
//
// A Store's entries are not interchangeable the way, say, a web session
// cache's are: each one gates a specific in-flight key-import ceremony that
// only its caller can complete, so evicting the oldest to admit a new one
// would silently take a wrapping key away from whichever caller happens to
// have been waiting longest -- who would not learn about it until their
// later UnwrapKey call inexplicably reported an invalid token. Refusing the
// new token instead fails at the point the cap was hit, with a caller who
// can retry once earlier ceremonies complete or expire.
type LimitExceededError struct {
	// Limit is the Store's configured capacity.
	Limit int
}

// Error implements the error interface.
func (e *LimitExceededError) Error() string {
	return fmt.Sprintf("importtoken: store at capacity (%d tokens)", e.Limit)
}

// UnavailableError reports that a SealedRSAKey's enclave could not be
// opened -- because it was already destroyed, or because opening the
// underlying secret failed -- so Use never reached the caller's callback.
type UnavailableError struct {
	// Err is the underlying cause, or nil when the key was already
	// destroyed before Use was called.
	Err error
}

// Error implements the error interface.
func (e *UnavailableError) Error() string {
	if e.Err == nil {
		return "importtoken: wrapping key is not available"
	}
	return "importtoken: failed to open wrapping key enclave: " + e.Err.Error()
}

// Unwrap returns the underlying cause, if any.
func (e *UnavailableError) Unwrap() error { return e.Err }

// NotRSAKeyError reports that a SealedRSAKey's enclave decoded to a
// private key that is not RSA. Every SealedRSAKey holds an RSA wrapping
// key by construction (NewSealedRSAKey only accepts an *rsa.PrivateKey),
// so this indicates the sealed payload was tampered with, corrupted, or
// (in tests) deliberately substituted.
type NotRSAKeyError struct{}

// Error implements the error interface.
func (e *NotRSAKeyError) Error() string {
	return "importtoken: wrapping key is not RSA"
}
