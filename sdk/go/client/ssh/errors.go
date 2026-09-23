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

// BackendUnavailableError is returned when a GenerateRequest selects a
// crypto backend but the embedded transport was constructed without a
// BackendProvider (or a backend-backed key's signer is requested without
// one). The Backend field names the requested backend.
type BackendUnavailableError struct {
	Backend string
}

// Error implements the error interface.
func (e *BackendUnavailableError) Error() string {
	return "sdk/ssh: no backend provider configured for backend: " + e.Backend
}

// ConsoleUnsupportedError is returned by Console on transports that cannot
// carry an interactive byte stream (MCP, and the REST/QUIC SDK clients whose
// console is served by the WebSocket bridge rather than the Go client).
type ConsoleUnsupportedError struct {
	Transport string
}

// Error implements the error interface.
func (e *ConsoleUnsupportedError) Error() string {
	return "sdk/ssh: interactive console is not supported over the " + e.Transport +
		" client (use embedded/gRPC, or the WebSocket bridge for REST/QUIC)"
}

// ConsoleClosedError indicates an operation on a console session that has
// already been closed. It mirrors pkg/ssh/console.ClosedError for the
// transports whose ConsoleSession is not the in-process console.
type ConsoleClosedError struct{}

// Error implements the error interface.
func (e *ConsoleClosedError) Error() string { return "sdk/ssh: console session is closed" }

// ConsoleWriteClosedError indicates a Write after CloseWrite: the session's
// write half is shut and the remote has already seen EOF on its stdin.
type ConsoleWriteClosedError struct{}

// Error implements the error interface.
func (e *ConsoleWriteClosedError) Error() string { return "sdk/ssh: console write half is closed" }

// InvalidScopeError is returned when a DTO carries an unrecognized
// scope string.
type InvalidScopeError struct {
	Value string
}

// Error implements the error interface.
func (e *InvalidScopeError) Error() string {
	return "sdk/ssh: invalid scope: " + e.Value
}

// MissingPublicKeyError is returned by KnownHostsClient.Add when
// AddKnownHostRequest.PublicKey is empty. Every pin now requires the full
// host key; there is no fingerprint-only form.
type MissingPublicKeyError struct {
	Host string
}

// Error implements the error interface.
func (e *MissingPublicKeyError) Error() string {
	return "sdk/ssh: pin for host " + e.Host + " requires a public key"
}

// InvalidPublicKeyError is returned by KnownHostsClient.Add when
// AddKnownHostRequest.PublicKey cannot be parsed as an authorized_keys-format
// line.
type InvalidPublicKeyError struct {
	Host string
	Err  error
}

// Error implements the error interface.
func (e *InvalidPublicKeyError) Error() string {
	return "sdk/ssh: pin for host " + e.Host + " has an invalid public key: " + e.Err.Error()
}

// Unwrap returns the underlying parse failure.
func (e *InvalidPublicKeyError) Unwrap() error { return e.Err }

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

// ConnectionClosedError indicates the MCP transport's connection was
// closed by the server before a response was received, with no
// underlying scanner error to report.
type ConnectionClosedError struct{}

// Error implements the error interface.
func (e *ConnectionClosedError) Error() string { return "sdk/ssh: connection closed by server" }
