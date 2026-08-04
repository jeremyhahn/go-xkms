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

package api

import "errors"

// ErrInvalidRequestBody indicates the request body could not be decoded.
type ErrInvalidRequestBody struct {
	Detail string
}

// Error returns the error message.
func (e *ErrInvalidRequestBody) Error() string {
	return "gui/api: invalid request body: " + e.Detail
}

// ErrInvalidPathParam indicates a required path parameter is invalid.
type ErrInvalidPathParam struct {
	Param  string
	Detail string
}

// Error returns the error message.
func (e *ErrInvalidPathParam) Error() string {
	return "gui/api: invalid path parameter " + e.Param + ": " + e.Detail
}

// ErrSDKCall indicates the SDK client returned an error.
type ErrSDKCall struct {
	Operation string
	Detail    string
}

// Error returns the error message.
func (e *ErrSDKCall) Error() string {
	return "gui/api: " + e.Operation + " failed: " + e.Detail
}

// isErrorType checks whether err matches the target error type using errors.As.
func isErrorType[T error](err error, target *T) bool {
	return errors.As(err, target)
}
