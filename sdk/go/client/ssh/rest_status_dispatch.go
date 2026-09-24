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

import (
	"errors"
	"net/http"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
)

// sshErrorClass is a transport-neutral classification for an error raised by
// the SSH SDK client or by one of the embedded pkg/ssh/* stores. classify is
// the single place that walks an error's Unwrap chain against the typed-error
// table; every transport-specific status mapper (HTTPStatusForError,
// GRPCCodeForError, JSONRPCCodeForError) derives its wire-level code from
// this one classification instead of re-deriving the NotFound/Duplicate/
// Mismatch semantics per transport.
type sshErrorClass int

const (
	// classInternal is the default: an error this table does not recognize.
	// Transports that classify it MUST NOT echo err.Error() verbatim to an
	// untrusted caller, since it may carry internal detail.
	classInternal sshErrorClass = iota
	// classNotFound is a missing resource (key, known-host pin, or
	// authorized_keys entry).
	classNotFound
	// classDuplicate is a resource that already exists (Add called twice
	// without an intervening Remove).
	classDuplicate
	// classMismatch is a known_hosts host-key mismatch -- a MITM indicator,
	// classified separately from classDuplicate even though REST reports
	// both as 409 Conflict, because gRPC and MCP each have room to keep the
	// two distinguishable on the wire.
	classMismatch
	// classBadRequest is a validation/input error.
	classBadRequest
	// classNotImplemented is a transport stub (e.g. Session.Dial over MCP).
	classNotImplemented
)

// classify walks err's Unwrap chain and returns the class every wire-level
// status mapper derives its transport-specific code from. Unknown error
// types classify as classInternal.
func classify(err error) sshErrorClass {
	// Not found.
	{
		var e *pkgkeys.KeyNotFoundError
		if errors.As(err, &e) {
			return classNotFound
		}
	}
	{
		var e *pkgknownhosts.NotFoundError
		if errors.As(err, &e) {
			return classNotFound
		}
	}
	{
		var e *pkgauthorized.NotFoundError
		if errors.As(err, &e) {
			return classNotFound
		}
	}

	// Duplicate / conflict.
	{
		var e *pkgknownhosts.DuplicateError
		if errors.As(err, &e) {
			return classDuplicate
		}
	}
	{
		var e *pkgauthorized.DuplicateError
		if errors.As(err, &e) {
			return classDuplicate
		}
	}
	{
		// MismatchError on host key is a MITM indicator. Classified apart
		// from classDuplicate so gRPC and MCP can each report it precisely.
		var e *pkgknownhosts.MismatchError
		if errors.As(err, &e) {
			return classMismatch
		}
	}

	// Transport stub.
	{
		var e *NotImplementedError
		if errors.As(err, &e) {
			return classNotImplemented
		}
	}

	// Validation / input errors.
	if isBadRequest(err) {
		return classBadRequest
	}

	return classInternal
}

// httpStatusDispatch walks err's Unwrap chain and returns the first
// matching status from the typed-error table. Unknown error types fall
// through to 500. Kept separate from rest_status.go so that file can
// live in a smaller import closure if future refactors split the SDK.
func httpStatusDispatch(err error) int {
	switch classify(err) {
	case classNotFound:
		return http.StatusNotFound
	case classDuplicate, classMismatch:
		// MismatchError on host key is a MITM indicator. 409 lets
		// clients distinguish it from 400 (bad request) and 404 (no
		// pin).
		return http.StatusConflict
	case classNotImplemented:
		return http.StatusNotImplemented
	case classBadRequest:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// isBadRequest returns true when err matches one of the validation-grade
// typed errors that the mapping funnels to HTTP 400.
func isBadRequest(err error) bool {
	var scopeErr *InvalidScopeError
	if errors.As(err, &scopeErr) {
		return true
	}
	var algoErr *InvalidAlgorithmError
	if errors.As(err, &algoErr) {
		return true
	}
	var nilErr *NilInputError
	if errors.As(err, &nilErr) {
		return true
	}

	var keysNil *pkgkeys.NilInputError
	if errors.As(err, &keysNil) {
		return true
	}
	var keysSize *pkgkeys.InvalidKeySizeError
	if errors.As(err, &keysSize) {
		return true
	}
	var keysAlgo *pkgkeys.UnsupportedAlgorithmError
	if errors.As(err, &keysAlgo) {
		return true
	}
	var keysPassReq *pkgkeys.PassphraseRequiredError
	if errors.As(err, &keysPassReq) {
		return true
	}
	var keysPEM *pkgkeys.PEMParseError
	if errors.As(err, &keysPEM) {
		return true
	}

	var hostsNil *pkgknownhosts.NilInputError
	if errors.As(err, &hostsNil) {
		return true
	}
	var hostsHost *pkgknownhosts.InvalidHostError
	if errors.As(err, &hostsHost) {
		return true
	}
	var hostsFP *pkgknownhosts.InvalidFingerprintError
	if errors.As(err, &hostsFP) {
		return true
	}
	var missingPub *MissingPublicKeyError
	if errors.As(err, &missingPub) {
		return true
	}
	var invalidPub *InvalidPublicKeyError
	if errors.As(err, &invalidPub) {
		return true
	}

	var authNil *pkgauthorized.NilInputError
	if errors.As(err, &authNil) {
		return true
	}
	var authName *pkgauthorized.InvalidNameError
	if errors.As(err, &authName) {
		return true
	}
	var authLine *pkgauthorized.MalformedLineError
	return errors.As(err, &authLine)
}
