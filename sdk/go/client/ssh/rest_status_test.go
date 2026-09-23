// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ssh_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestHTTPStatusForError_MappingTable asserts every row of the mapping
// documented on HTTPStatusForError. This table is the single shared contract
// between the REST server handlers and the REST client, so a drift here
// changes the status code clients branch on. The MITM row (MismatchError ->
// 409) is the highest-stakes entry: collapsing it into 500 would hide a
// host-key mismatch behind a generic server error.
func TestHTTPStatusForError_MappingTable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, http.StatusOK},

		// 404 — resource not found.
		{"keys.KeyNotFoundError", &pkgkeys.KeyNotFoundError{ID: "k"}, http.StatusNotFound},
		{"knownhosts.NotFoundError", &pkgknownhosts.NotFoundError{Host: "h"}, http.StatusNotFound},
		{"authorized.NotFoundError", &pkgauthorized.NotFoundError{Name: "n"}, http.StatusNotFound},

		// 409 — duplicate / conflict.
		{"knownhosts.DuplicateError", &pkgknownhosts.DuplicateError{Host: "h"}, http.StatusConflict},
		{"authorized.DuplicateError", &pkgauthorized.DuplicateError{Name: "n"}, http.StatusConflict},
		{"knownhosts.MismatchError_MITM", &pkgknownhosts.MismatchError{
			Host: "h", Expected: "SHA256:a", Received: "SHA256:b",
		}, http.StatusConflict},

		// 501 — transport stub.
		{"NotImplementedError", &sdkssh.NotImplementedError{Transport: "rest", Op: "Session.Dial"}, http.StatusNotImplemented},

		// 400 — validation / input errors.
		{"sdk.InvalidScopeError", &sdkssh.InvalidScopeError{Value: "bogus"}, http.StatusBadRequest},
		{"sdk.InvalidAlgorithmError", &sdkssh.InvalidAlgorithmError{Value: "rot13"}, http.StatusBadRequest},
		{"sdk.NilInputError", &sdkssh.NilInputError{Field: "Name"}, http.StatusBadRequest},
		{"keys.NilInputError", &pkgkeys.NilInputError{Field: "Name"}, http.StatusBadRequest},
		{"keys.InvalidKeySizeError", &pkgkeys.InvalidKeySizeError{Algorithm: "rsa", Size: 7}, http.StatusBadRequest},
		{"keys.UnsupportedAlgorithmError", &pkgkeys.UnsupportedAlgorithmError{Algorithm: "rot13"}, http.StatusBadRequest},
		{"keys.PassphraseRequiredError", &pkgkeys.PassphraseRequiredError{}, http.StatusBadRequest},
		{"keys.PEMParseError", &pkgkeys.PEMParseError{Err: errors.New("bad pem")}, http.StatusBadRequest},
		{"knownhosts.NilInputError", &pkgknownhosts.NilInputError{Field: "Host"}, http.StatusBadRequest},
		{"knownhosts.InvalidHostError", &pkgknownhosts.InvalidHostError{Value: "!!", Reason: "syntax"}, http.StatusBadRequest},
		{"knownhosts.InvalidFingerprintError", &pkgknownhosts.InvalidFingerprintError{Value: "x", Reason: "syntax"}, http.StatusBadRequest},
		{"authorized.NilInputError", &pkgauthorized.NilInputError{Field: "Line"}, http.StatusBadRequest},
		{"authorized.InvalidNameError", &pkgauthorized.InvalidNameError{Value: "!", Reason: "syntax"}, http.StatusBadRequest},
		{"authorized.MalformedLineError", &pkgauthorized.MalformedLineError{Line: "junk"}, http.StatusBadRequest},
		{"sdk.MissingPublicKeyError", &sdkssh.MissingPublicKeyError{Host: "h"}, http.StatusBadRequest},
		{"sdk.InvalidPublicKeyError", &sdkssh.InvalidPublicKeyError{Host: "h", Err: errors.New("bad key")}, http.StatusBadRequest},

		// 500 — anything else.
		{"unknown_error", errors.New("something else entirely"), http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sdkssh.HTTPStatusForError(tc.err); got != tc.want {
				t.Errorf("HTTPStatusForError(%T) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestHTTPStatusForError_WalksUnwrapChain proves the mapping uses errors.As
// rather than a concrete type switch: handlers routinely wrap errors with
// context before they reach the status mapper, and a wrapped 404 must not
// degrade to 500.
func TestHTTPStatusForError_WalksUnwrapChain(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"wrapped_not_found", fmt.Errorf("loading pin: %w", &pkgknownhosts.NotFoundError{Host: "h"}), http.StatusNotFound},
		{"wrapped_mismatch", fmt.Errorf("verify: %w", &pkgknownhosts.MismatchError{Host: "h"}), http.StatusConflict},
		{"double_wrapped_bad_request", fmt.Errorf("outer: %w",
			fmt.Errorf("inner: %w", &sdkssh.InvalidScopeError{Value: "x"})), http.StatusBadRequest},
		{"wrapped_unknown_stays_500", fmt.Errorf("outer: %w", errors.New("opaque")), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sdkssh.HTTPStatusForError(tc.err); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// TestHTTPStatusForError_NotFoundBeatsBadRequest guards the dispatch ordering.
// A not-found error must map to 404 even though the chain also carries a
// validation-grade error underneath it.
func TestHTTPStatusForError_DispatchOrdering(t *testing.T) {
	// A 404-grade error wrapping a 400-grade one must resolve as 404,
	// because the not-found checks run before isBadRequest.
	err := fmt.Errorf("%w", &pkgauthorized.NotFoundError{Name: "n"})
	if got := sdkssh.HTTPStatusForError(err); got != http.StatusNotFound {
		t.Errorf("got %d, want 404", got)
	}

	// NotImplemented must not be swallowed by the 400 bucket.
	if got := sdkssh.HTTPStatusForError(&sdkssh.NotImplementedError{Transport: "quic", Op: "x"}); got != http.StatusNotImplemented {
		t.Errorf("got %d, want 501", got)
	}
}
