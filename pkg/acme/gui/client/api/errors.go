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

// ErrInvalidRequestBody indicates the request body could not be decoded.
type ErrInvalidRequestBody struct {
	Detail string
}

// Error returns the error message.
func (e *ErrInvalidRequestBody) Error() string {
	return "gui/client/api: invalid request body: " + e.Detail
}

// ErrServiceCall indicates the service layer returned an error.
type ErrServiceCall struct {
	Operation string
	Detail    string
}

// Error returns the error message.
func (e *ErrServiceCall) Error() string {
	return "gui/client/api: " + e.Operation + " failed: " + e.Detail
}

// ErrMissingField indicates a required field was not provided in the request.
type ErrMissingField struct {
	Field string
}

// Error returns the error message.
func (e *ErrMissingField) Error() string {
	return "gui/client/api: missing required field: " + e.Field
}
