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

package ssh

// NilInputError is returned when a required Client constructor option
// is missing.
type NilInputError struct {
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string {
	return "sdk/ssh: nil input: " + e.Field
}

// NotImplementedError is returned by transport stubs whose concrete
// implementation is not yet available in this build.
type NotImplementedError struct {
	Transport string
	Op        string
}

// Error implements the error interface.
func (e *NotImplementedError) Error() string {
	return "sdk/ssh: not implemented: " + e.Transport + " " + e.Op
}

// InvalidAlgorithmError is returned when a DTO carries an algorithm
// string that the internal keys package rejects.
type InvalidAlgorithmError struct {
	Value string
}

// Error implements the error interface.
func (e *InvalidAlgorithmError) Error() string {
	return "sdk/ssh: invalid algorithm: " + e.Value
}

// InvalidScopeError is returned when a DTO carries an unrecognized
// scope string.
type InvalidScopeError struct {
	Value string
}

// Error implements the error interface.
func (e *InvalidScopeError) Error() string {
	return "sdk/ssh: invalid scope: " + e.Value
}

// NotFoundError is returned by REST client methods that receive a 404
// response from the server. The Resource field describes the logical
// resource ("key", "known_host", "authorized_entry").
type NotFoundError struct {
	Resource string
	Message  string
}

// Error implements the error interface.
func (e *NotFoundError) Error() string {
	if e.Message != "" {
		return "sdk/ssh: not found: " + e.Resource + ": " + e.Message
	}
	return "sdk/ssh: not found: " + e.Resource
}

// DuplicateError is returned by REST client methods that receive a 409
// response from the server for Add-style operations.
type DuplicateError struct {
	Resource string
	Message  string
}

// Error implements the error interface.
func (e *DuplicateError) Error() string {
	if e.Message != "" {
		return "sdk/ssh: duplicate: " + e.Resource + ": " + e.Message
	}
	return "sdk/ssh: duplicate: " + e.Resource
}

// MismatchError is returned by the REST client Verify methods when the
// server reports a MITM-indicating mismatch (HTTP 409 with the
// appropriate body).
type MismatchError struct {
	Host     string
	Expected string
	Received string
}

// Error implements the error interface.
func (e *MismatchError) Error() string {
	return "sdk/ssh: host key mismatch for " + e.Host +
		": expected " + e.Expected + ", got " + e.Received
}

// InvalidRequestError is returned on HTTP 400 responses.
type InvalidRequestError struct {
	Message string
}

// Error implements the error interface.
func (e *InvalidRequestError) Error() string {
	if e.Message == "" {
		return "sdk/ssh: invalid request"
	}
	return "sdk/ssh: invalid request: " + e.Message
}

// AuthError is returned on HTTP 401 / 403 responses.
type AuthError struct {
	StatusCode int
	Message    string
}

// Error implements the error interface.
func (e *AuthError) Error() string {
	if e.Message == "" {
		return "sdk/ssh: authentication/authorization failure"
	}
	return "sdk/ssh: authentication/authorization failure: " + e.Message
}

// ServerError is returned for 5xx responses the REST client cannot
// map to a more specific type.
type ServerError struct {
	StatusCode int
	Message    string
}

// Error implements the error interface.
func (e *ServerError) Error() string {
	if e.Message == "" {
		return "sdk/ssh: server error"
	}
	return "sdk/ssh: server error: " + e.Message
}

// ProtocolError is returned for REST responses the client cannot
// decode (malformed JSON, missing content-type, etc.). Message carries
// a short description and Err carries the underlying decode failure.
type ProtocolError struct {
	Message string
	Err     error
}

// Error implements the error interface.
func (e *ProtocolError) Error() string {
	if e.Err == nil {
		return "sdk/ssh: protocol error: " + e.Message
	}
	return "sdk/ssh: protocol error: " + e.Message + ": " + e.Err.Error()
}

// Unwrap returns the underlying decode failure so callers can inspect
// the specific encoding/json error type if they need to.
func (e *ProtocolError) Unwrap() error { return e.Err }
