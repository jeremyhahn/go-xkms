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

package peer

import "strconv"

// PolicyError reports a Policy that cannot be evaluated as written. It is
// the caller's configuration that is wrong, not the peer's evidence, so
// Verify returns it as an error rather than folding it into the Verdict.
type PolicyError struct {
	// Field is the Policy field at fault.
	Field string
	// Reason says what is wrong with it.
	Reason string
}

// Error implements error.
func (e *PolicyError) Error() string {
	return "peer: invalid policy: " + e.Field + ": " + e.Reason
}

// ContextError reports that the context was done before verification ran.
type ContextError struct {
	// Cause is the context's error.
	Cause error
}

// Error implements error.
func (e *ContextError) Error() string {
	return "peer: verification aborted: " + e.Cause.Error()
}

// Unwrap returns the context error so errors.Is(err, context.Canceled) holds.
func (e *ContextError) Unwrap() error { return e.Cause }

// ChannelBindingError reports that a TLS connection state cannot yield a
// channel binding: no state was supplied, or the connection does not support
// key material export (TLS 1.2 without the extended master secret).
type ChannelBindingError struct {
	// Reason says why the binding could not be derived.
	Reason string
	// Cause is the underlying error, when the TLS stack produced one.
	Cause error
}

// Error implements error.
func (e *ChannelBindingError) Error() string {
	msg := "peer: channel binding unavailable: " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the TLS stack's error, when there is one.
func (e *ChannelBindingError) Unwrap() error { return e.Cause }

// FailureClassError reports text that does not name a FailureClass.
type FailureClassError struct {
	// Text is the value that was rejected.
	Text string
}

// Error implements error.
func (e *FailureClassError) Error() string {
	return "peer: unknown failure class " + strconv.Quote(e.Text)
}
