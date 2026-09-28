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

package mcp

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ErrInternal is the fixed message a client receives in place of an
// internal error's text (see ClientError). The detail is logged server-side
// by InvokeMethod instead (go-xkms#1118).
var ErrInternal = errors.New("xkms: internal error")

// KeyOpError carries a JSON-RPC error code alongside the underlying error
// returned by the xkms service layer. InvokeMethod unwraps it via errors.As
// to select the wire-level code instead of collapsing every handler failure
// to ErrCodeInternalError, so a capability boundary (a backend that cannot
// attest, or cannot export) is distinguishable from an actual server fault.
type KeyOpError struct {
	// Code is the JSON-RPC 2.0 error code to report to the caller.
	Code int

	// Err is the underlying error returned by the xkms service layer.
	Err error

	// Classified reports that Err matched a named sentinel in one of this
	// package's classification tables, so its text is a client-facing
	// message. It matters only when Code is ErrCodeInternalError: JSON-RPC
	// has no FailedPrecondition, DataLoss or ResourceExhausted member, so a
	// classified condition such as a sealed barrier shares that code with
	// the unclassified floor, and Classified is what tells them apart. The
	// zero value is unclassified, so an error nobody classified is withheld.
	Classified bool
}

// Error returns the underlying error's message. It is the server-side
// detail; the text a client may see is ClientError's.
func (e *KeyOpError) Error() string { return e.Err.Error() }

// Unwrap returns the underlying error.
func (e *KeyOpError) Unwrap() error { return e.Err }

// Internal reports whether e is an unclassified server fault, whose text is
// withheld from the client.
func (e *KeyOpError) Internal() bool {
	return e.Code == ErrCodeInternalError && !e.Classified
}

// classified returns a *KeyOpError for an err a classification table (or a
// handler's own sentinel switch) matched, marking its text client-facing
// even when code is the ErrCodeInternalError floor.
func classified(code int, err error) *KeyOpError {
	return &KeyOpError{Code: code, Err: err, Classified: true}
}

// ClientError returns the JSON-RPC code and the message a client may see for
// an error InvokeMethod returned. A *KeyOpError keeps its code; its message
// is its own text unless it is Internal, in which case the message is
// ErrInternal's fixed text. Any other error was never classified and
// reports ErrCodeInternalError with ErrInternal's text. InvokeMethod logs
// the withheld detail with the method and request ID (go-xkms#1118).
func ClientError(err error) (code int, message string) {
	var keyErr *KeyOpError
	if !errors.As(err, &keyErr) {
		return ErrCodeInternalError, ErrInternal.Error()
	}
	if keyErr.Internal() {
		return keyErr.Code, ErrInternal.Error()
	}
	return keyErr.Code, keyErr.Error()
}

// withheld reports whether ClientError withholds err's text from the
// client.
func withheld(err error) bool {
	var keyErr *KeyOpError
	return !errors.As(err, &keyErr) || keyErr.Internal()
}

// keyOpSentinelCodes maps the service-layer sentinels raised by the key and
// crypto operations onto JSON-RPC error codes. It is an ordered slice rather
// than a map because a single error can satisfy errors.Is for more than one
// entry: xkms.ErrOperationWrap deliberately exposes both its sentinel and its
// cause. The first match wins, so the most specific sentinel is listed first.
//
// This mirrors pkg/api/grpc/errors_keyops.go's keyOpSentinelCodes, translated
// onto the JSON-RPC 2.0 error vocabulary (which is far coarser than gRPC's
// codes.Code): ErrOperationNotSupported is the only sentinel with a distinct
// wire-level code (Method not found, MCP's "unimplemented" signal), and
// ErrBackendNotFound/ErrKeyNotFound -- codes.NotFound over gRPC -- carry
// sdkssh.JSONRPCCodeNotFound, the reserved-range code this package's SSH
// sub-system already defined for the identical wire.CodeNotFound outcome
// (errors_ssh.go's mapSSHError; go-xkms#814). Every other sentinel here
// reports as an internal error since JSON-RPC has no standard
// FailedPrecondition/Unavailable code.
var keyOpSentinelCodes = []struct {
	sentinel error
	code     int
}{
	{xkms.ErrOperationNotSupported, ErrCodeMethodNotFound},
	{xkms.ErrExportKeyMaterialFailed, ErrCodeInternalError},
	{xkms.ErrBackendNotFound, sdkssh.JSONRPCCodeNotFound},
	{xkms.ErrKeyNotFound, sdkssh.JSONRPCCodeNotFound},
	{xkms.ErrNotInitialized, ErrCodeInternalError},
}

// mapKeyOpError converts an error returned by the xkms service layer into a
// *KeyOpError carrying the JSON-RPC error code InvokeMethod should report.
// Validation failures become Invalid params; an unresolved role, backend, or
// key becomes Not found (sdkssh.JSONRPCCodeNotFound, matching gRPC's
// codes.NotFound for all three); a backend that lacks the requested hardware
// capability becomes Method not found, MCP's signal for "not implemented by
// this backend". Anything else is an internal fault.
func mapKeyOpError(err error) error {
	if err == nil {
		return nil
	}

	var role *xkms.ErrRoleLookup
	if errors.As(err, &role) {
		// Not found, matching pkg/api/grpc/errors_keyops.go's mapKeyOpError
		// (codes.NotFound) and go-qrdb's own MCP wire contract, which
		// classifies its own *role.RoleNotFoundError the same way its gRPC
		// transport does (go-qrdb pkg/api/mcp/status.go's classifyToolError,
		// status_test.go's "missing role" case). ErrRoleLookup reports
		// exactly that condition -- a named role, backend, or key that does
		// not resolve -- so MCP and gRPC now agree (go-xkms#912). This used
		// to report Invalid params, as if the caller's request were
		// malformed rather than the name it gave simply not resolving.
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: err}
	}

	var validation *xkms.ErrValidation
	if errors.As(err, &validation) {
		// The validation error is carried through rather than flattened into
		// a message. It used to be replaced with an errs.Message holding only
		// the Detail, which discarded the sentinel and with it every
		// errors.Is check a caller or test could make: a refused weak hash and
		// a missing required field became indistinguishable once they reached
		// this transport. ErrValidation.Error already renders as
		// "<sentinel>: <detail>", so the wire message still carries the
		// caller-facing detail.
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: validation}
	}

	for _, entry := range keyOpSentinelCodes {
		if errors.Is(err, entry.sentinel) {
			return classified(entry.code, err)
		}
	}

	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}
