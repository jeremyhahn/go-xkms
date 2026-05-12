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

// httpStatusDispatch walks err's Unwrap chain and returns the first
// matching status from the typed-error table. Unknown error types fall
// through to 500. Kept separate from rest_status.go so that file can
// live in a smaller import closure if future refactors split the SDK.
func httpStatusDispatch(err error) int {
	// 404 — resource not found.
	{
		var e *pkgkeys.KeyNotFoundError
		if errors.As(err, &e) {
			return http.StatusNotFound
		}
	}
	{
		var e *pkgknownhosts.NotFoundError
		if errors.As(err, &e) {
			return http.StatusNotFound
		}
	}
	{
		var e *pkgauthorized.NotFoundError
		if errors.As(err, &e) {
			return http.StatusNotFound
		}
	}

	// 409 — duplicate / conflict.
	{
		var e *pkgknownhosts.DuplicateError
		if errors.As(err, &e) {
			return http.StatusConflict
		}
	}
	{
		var e *pkgauthorized.DuplicateError
		if errors.As(err, &e) {
			return http.StatusConflict
		}
	}
	{
		// MismatchError on host key is a MITM indicator. 409 lets
		// clients distinguish it from 400 (bad request) and 404 (no
		// pin).
		var e *pkgknownhosts.MismatchError
		if errors.As(err, &e) {
			return http.StatusConflict
		}
	}

	// 501 — transport stub.
	{
		var e *NotImplementedError
		if errors.As(err, &e) {
			return http.StatusNotImplemented
		}
	}

	// 400 — validation / input errors.
	if isBadRequest(err) {
		return http.StatusBadRequest
	}

	return http.StatusInternalServerError
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

	var authNil *pkgauthorized.NilInputError
	if errors.As(err, &authNil) {
		return true
	}
	var authName *pkgauthorized.InvalidNameError
	if errors.As(err, &authName) {
		return true
	}
	var authLine *pkgauthorized.MalformedLineError
	if errors.As(err, &authLine) {
		return true
	}

	return false
}
