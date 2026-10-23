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

package attestation

import "fmt"

// ResponseMismatchError reports a response that does not answer the request
// it was read for: its ID or its generation differs from the request's. The
// MessageRouter drops such a response (go-xkms#128); a one-shot exchange
// outside the router refuses it with this error instead.
type ResponseMismatchError struct {
	RequestID          uint64
	RequestGeneration  uint64
	ResponseID         uint64
	ResponseGeneration uint64
}

// Error implements the error interface.
func (e *ResponseMismatchError) Error() string {
	return fmt.Sprintf("response id %d generation %d does not answer request id %d generation %d",
		e.ResponseID, e.ResponseGeneration, e.RequestID, e.RequestGeneration)
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
