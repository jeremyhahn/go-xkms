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

import "net/http"

// HTTPStatusForError returns the canonical HTTP status code for an
// error produced by any of the go-xkms SSH packages. It is exported so
// both the REST server handlers and the REST client transport can route
// typed errors through a single table without duplicating the mapping.
//
// Mapping:
//
//	*pkg/ssh/known_hosts.NotFoundError        -> 404
//	*pkg/ssh/authorized.NotFoundError         -> 404
//	*pkg/ssh/keys.KeyNotFoundError            -> 404
//	*pkg/ssh/known_hosts.DuplicateError       -> 409
//	*pkg/ssh/authorized.DuplicateError        -> 409
//	*pkg/ssh/known_hosts.MismatchError        -> 409 (MITM)
//	*InvalidScopeError                        -> 400
//	*InvalidAlgorithmError                    -> 400
//	*pkg/ssh/keys.NilInputError               -> 400
//	*pkg/ssh/known_hosts.NilInputError        -> 400
//	*pkg/ssh/authorized.NilInputError         -> 400
//	*pkg/ssh/known_hosts.InvalidHostError     -> 400
//	*pkg/ssh/known_hosts.InvalidFingerprint.. -> 400
//	*pkg/ssh/authorized.InvalidNameError      -> 400
//	*pkg/ssh/authorized.MalformedLineError    -> 400
//	*pkg/ssh/keys.InvalidKeySizeError         -> 400
//	*pkg/ssh/keys.UnsupportedAlgorithmError   -> 400
//	*pkg/ssh/keys.PassphraseRequiredError     -> 400
//	*pkg/ssh/keys.PEMParseError               -> 400
//	*NotImplementedError                      -> 501
//	*NilInputError                            -> 400
//	anything else                             -> 500
//
// The mapping is intentionally simple; routing derives from the error's
// concrete type (or errors.As-compatible unwrap chain) via dispatch in
// httpStatusDispatch.
func HTTPStatusForError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	return httpStatusDispatch(err)
}
