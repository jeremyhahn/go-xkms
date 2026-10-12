// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package fido2

import (
	"errors"
	"fmt"
	"strings"
)

// ErrLocalCeremonyUnavailable indicates the CTAP2 driver is not wired.
var ErrLocalCeremonyUnavailable = errors.New("fido2: local CTAP2 ceremony is not available in this build")

// NoHandlerReason is the operator-facing text reported by a LocalCeremony with
// no FIDO2 handler attached. It is exported because it is what the ceremony's
// preflight surfaces to the person standing at the console, and a caller may
// want to match on it.
const NoHandlerReason = "no FIDO2 handler attached — this build or host has no FIDO2 support; enroll from a console that can reach a security key"

// ErrLocalRPIDRequired indicates a local enrollment was attempted with no
// relying-party ID. A credential enrolled against the wrong RP ID verifies at
// enrollment and fails at every login, so this is refused rather than guessed.
var ErrLocalRPIDRequired = errors.New("fido2: relying-party ID is required for local enrollment")

// ErrLocalChallengeRequired indicates a local enrollment was attempted with no
// relying-party challenge. The challenge must come from the RP so the
// credential is bound to a session the server will accept.
var ErrLocalChallengeRequired = errors.New("fido2: relying-party challenge is required for local enrollment")

// ErrNoAuthenticator indicates no FIDO2 authenticator is attached.
var ErrNoAuthenticator = errors.New("fido2: no authenticator detected")

// AmbiguousAuthenticatorError indicates several authenticators matched and the
// operator did not say which to use. Enrolling onto the wrong token is not
// discoverable until first login, so the ceremony refuses to guess.
type AmbiguousAuthenticatorError struct {
	Candidates []string
}

// Error lists the candidates so the operator can pick one.
func (e *AmbiguousAuthenticatorError) Error() string {
	return "fido2: several authenticators are attached; select one with --passkey-device: " +
		strings.Join(e.Candidates, ", ")
}

// AuthenticatorNotFoundError indicates the operator's device selector matched
// nothing.
type AuthenticatorNotFoundError struct {
	Hint       string
	Candidates []string
}

// Error reports the unmatched selector alongside what is actually attached.
func (e *AuthenticatorNotFoundError) Error() string {
	if len(e.Candidates) == 0 {
		return fmt.Sprintf("fido2: no authenticator matches %q (none attached)", e.Hint)
	}
	return fmt.Sprintf("fido2: no authenticator matches %q; attached: %s",
		e.Hint, strings.Join(e.Candidates, ", "))
}

// LocalCeremonyError wraps a failure at a named stage of the local CTAP2
// enrollment. Stage distinguishes an authenticator problem (the user did not
// touch the key) from a parsing one, which are diagnosed differently.
type LocalCeremonyError struct {
	Stage string
	Err   error
}

// Error describes which stage of the local ceremony failed.
func (e *LocalCeremonyError) Error() string {
	return fmt.Sprintf("fido2: local enrollment failed at %s: %v", e.Stage, e.Err)
}

// Unwrap returns the underlying error.
func (e *LocalCeremonyError) Unwrap() error { return e.Err }
