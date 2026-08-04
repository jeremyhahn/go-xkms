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

// Package errs provides small reusable typed error values used across
// go-xkms packages in place of ad-hoc formatted-error construction. Each
// type preserves the exact rendered message of the call it replaces
// and participates in errors.Is / errors.As chains via Unwrap.
package errs

// Message is a typed error carrying a fixed or pre-formatted message with
// no wrapped cause.
type Message struct {
	// Msg is the complete error message.
	Msg string
}

// Error implements the error interface.
func (e *Message) Error() string { return e.Msg }

// Wrapped prefixes a wrapped cause with a contextual message, rendering as
// "<msg>: <cause>". The cause participates in errors.Is / errors.As.
type Wrapped struct {
	// Msg is the contextual prefix, without the trailing ": ".
	Msg string

	// Err is the wrapped cause.
	Err error
}

// Error implements the error interface.
func (e *Wrapped) Error() string { return e.Msg + ": " + e.Err.Error() }

// Unwrap returns the wrapped cause.
func (e *Wrapped) Unwrap() error { return e.Err }

// Detail appends detail text to a wrapped (usually sentinel) error,
// rendering as "<err>: <detail>". The wrapped error participates in
// errors.Is / errors.As.
type Detail struct {
	// Err is the wrapped error, typically a package sentinel.
	Err error

	// Detail is the appended detail text, without the leading ": ".
	Detail string
}

// Error implements the error interface.
func (e *Detail) Error() string { return e.Err.Error() + ": " + e.Detail }

// Unwrap returns the wrapped error.
func (e *Detail) Unwrap() error { return e.Err }

// Affix surrounds a wrapped cause with pre-formatted prefix and suffix
// text, rendering as "<prefix><cause><suffix>". The cause participates in
// errors.Is / errors.As.
type Affix struct {
	// Prefix is the text rendered before the cause, including any
	// separator characters.
	Prefix string

	// Err is the wrapped cause.
	Err error

	// Suffix is the text rendered after the cause, including any
	// separator characters.
	Suffix string
}

// Error implements the error interface.
func (e *Affix) Error() string { return e.Prefix + e.Err.Error() + e.Suffix }

// Unwrap returns the wrapped cause.
func (e *Affix) Unwrap() error { return e.Err }

// Joined wraps two causes, rendering as "<lead>: <cause>" or
// "<lead>: <detail>: <cause>" when Detail is non-empty. Both causes
// participate in errors.Is / errors.As, matching the semantics of a
// format error that wraps two %w verbs.
type Joined struct {
	// Lead is the first wrapped error, typically a package sentinel.
	Lead error

	// Detail is optional text rendered between the two causes, without
	// separator characters.
	Detail string

	// Cause is the second wrapped error.
	Cause error
}

// Error implements the error interface.
func (e *Joined) Error() string {
	if e.Detail != "" {
		return e.Lead.Error() + ": " + e.Detail + ": " + e.Cause.Error()
	}
	return e.Lead.Error() + ": " + e.Cause.Error()
}

// Unwrap returns both wrapped causes.
func (e *Joined) Unwrap() []error { return []error{e.Lead, e.Cause} }
