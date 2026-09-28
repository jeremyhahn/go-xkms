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

package validation

import (
	"errors"
	"strconv"
)

// ErrNilClient is returned when a verifier is given no Client.
var ErrNilClient = errors.New("challenge validation: no validation client configured")

// Kind classifies a validation failure into a category that is safe to show
// the ACME client. The category never carries a dial error, a resolved
// address, an internal host name or a status code.
type Kind int

const (
	// KindInvalidTarget: the target is not a bare hostname or IP literal,
	// or its port is not a TCP port.
	KindInvalidTarget Kind = iota + 1

	// KindTargetRefused: the target resolved to a reserved address.
	KindTargetRefused

	// KindConnection: the target could not be reached or the response
	// could not be read.
	KindConnection

	// KindStatus: the target answered with a status other than 200 OK.
	KindStatus

	// KindResponseTooLarge: the response body exceeded the request's limit.
	KindResponseTooLarge

	// KindRedirect: the target redirected where the request may not go.
	KindRedirect
)

// kindText holds each Kind's client-safe description. KindTargetRefused
// reads the same as KindConnection on purpose: telling them apart would let
// a client probe whether a name resolves to an internal address.
var kindText = map[Kind]string{
	KindInvalidTarget:    "invalid validation target",
	KindTargetRefused:    "connection failed",
	KindConnection:       "connection failed",
	KindStatus:           "unexpected HTTP status",
	KindResponseTooLarge: "response too large",
	KindRedirect:         "redirect not permitted",
}

// String returns the client-safe description of k.
func (k Kind) String() string {
	if text, ok := kindText[k]; ok {
		return text
	}
	return "validation failed"
}

// Error is a challenge-validation failure. Kind is the client-safe
// category; Err carries the detail for server logs only.
type Error struct {
	Kind Kind
	Err  error
}

// Error returns the full, log-only description, including Err.
func (e *Error) Error() string {
	if e.Err == nil {
		return "challenge validation: " + e.Kind.String()
	}
	return "challenge validation: " + e.Kind.String() + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// IsTargetRejected reports whether err is a validation failure the client
// decided by itself, without the target having been contacted: the target
// is not a bare hostname or IP literal with a TCP port (KindInvalidTarget),
// or the dialer refused the reserved address it resolved to
// (KindTargetRefused). Such a failure is a policy decision about a
// client-chosen target, not evidence that the network or the target is
// unhealthy, so a circuit breaker guarding challenge validation must not
// count it: every ACME account can produce one at will.
//
// Every other failure, including KindConnection, reports false.
func IsTargetRejected(err error) bool {
	var verr *Error
	if !errors.As(err, &verr) {
		return false
	}
	return verr.Kind == KindInvalidTarget || verr.Kind == KindTargetRefused
}

// A refused dial target's error is *netguard.AddressNotPermittedError, and
// an oversized response body's is *netguard.ResponseTooLargeError; both
// wrap into Error.Err (KindTargetRefused, KindResponseTooLarge) rather than
// being redeclared here.

// InvalidPortError is returned when a target's port is not a TCP port.
type InvalidPortError struct {
	Port string
}

func (e *InvalidPortError) Error() string {
	return "invalid port " + strconv.Quote(e.Port)
}

// StatusError is returned when a target answers with a status other than
// 200 OK.
type StatusError struct {
	StatusCode int
}

func (e *StatusError) Error() string {
	return "HTTP status " + strconv.Itoa(e.StatusCode)
}

// RedirectError is returned when a redirect is refused.
type RedirectError struct {
	Reason string
}

func (e *RedirectError) Error() string {
	return e.Reason
}
