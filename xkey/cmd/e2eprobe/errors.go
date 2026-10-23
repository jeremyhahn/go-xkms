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

package main

import "fmt"

// MessageError is a typed error that carries a preformatted message. It
// replaces inline formatted-error constructions that do not wrap a cause.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// NoResponseError reports a probe step that got no routable response before
// its deadline: the phone never answered, or answered with an ID or
// generation the router refuses (issue #128), which it drops rather than
// delivers. Err is the context error that ended the wait.
type NoResponseError struct {
	Method string
	Err    error
}

// Error implements the error interface.
func (e *NoResponseError) Error() string {
	return fmt.Sprintf("no routable response to %s: %v", e.Method, e.Err)
}

// Unwrap returns the context error that ended the wait.
func (e *NoResponseError) Unwrap() error {
	return e.Err
}
