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
)

// KeyOpError carries a JSON-RPC error code alongside the underlying error
// returned by the xkms service layer. handleRequest unwraps it via errors.As
// to select the wire-level code instead of collapsing every handler failure
// to ErrCodeInternalError, so a capability boundary (a backend that cannot
// attest, or cannot export) is distinguishable from an actual server fault.
type KeyOpError struct {
	// Code is the JSON-RPC 2.0 error code to report to the caller.
	Code int

	// Err is the underlying error returned by the xkms service layer.
	Err error
}

// Error returns the underlying error's message.
func (e *KeyOpError) Error() string { return e.Err.Error() }

// Unwrap returns the underlying error.
func (e *KeyOpError) Unwrap() error { return e.Err }

// keyOpSentinelCodes maps the service-layer sentinels raised by the key and
// crypto operations onto JSON-RPC error codes. It is an ordered slice rather
// than a map because a single error can satisfy errors.Is for more than one
// entry: xkms.ErrOperationWrap deliberately exposes both its sentinel and its
// cause. The first match wins, so the most specific sentinel is listed first.
//
// This mirrors pkg/api/grpc/errors_keyops.go's keyOpSentinelCodes, translated
// onto the JSON-RPC 2.0 error vocabulary (which is far coarser than gRPC's
// codes.Code): ErrOperationNotSupported is the only sentinel with a distinct
// wire-level code (Method not found, MCP's "unimplemented" signal); every
// other sentinel here reports as an internal error since JSON-RPC has no
// standard NotFound/FailedPrecondition/Unavailable codes.
var keyOpSentinelCodes = []struct {
	sentinel error
	code     int
}{
	{xkms.ErrOperationNotSupported, ErrCodeMethodNotFound},
	{xkms.ErrExportKeyMaterialFailed, ErrCodeInternalError},
	{xkms.ErrBackendNotFound, ErrCodeInternalError},
	{xkms.ErrKeyNotFound, ErrCodeInternalError},
	{xkms.ErrNotInitialized, ErrCodeInternalError},
}

// mapKeyOpError converts an error returned by the xkms service layer into a
// *KeyOpError carrying the JSON-RPC error code handleRequest should report.
// Validation failures and unresolved participants (a named backend or key
// that could not be found) become Invalid params, since JSON-RPC has no
// dedicated NotFound code; a backend that lacks the requested hardware
// capability becomes Method not found, MCP's signal for "not implemented by
// this backend". Anything else is an internal fault.
func mapKeyOpError(err error) error {
	if err == nil {
		return nil
	}

	var role *xkms.ErrRoleLookup
	if errors.As(err, &role) {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
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
			return &KeyOpError{Code: entry.code, Err: err}
		}
	}

	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}
