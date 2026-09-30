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
	"testing"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestJSONRPCCodeForError_MappingTable asserts every row of the mapping
// documented on JSONRPCCodeForError. It shares the classify() dispatch
// table with HTTPStatusForError and GRPCCodeForError, so this table is the
// JSON-RPC/MCP transport's half of the same contract.
func TestJSONRPCCodeForError_MappingTable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},

		// NotFound.
		{"keys.KeyNotFoundError", &pkgkeys.KeyNotFoundError{ID: "k"}, sdkssh.JSONRPCCodeNotFound},
		{"knownhosts.NotFoundError", &pkgknownhosts.NotFoundError{Host: "h"}, sdkssh.JSONRPCCodeNotFound},
		{"authorized.NotFoundError", &pkgauthorized.NotFoundError{Name: "n"}, sdkssh.JSONRPCCodeNotFound},

		// Duplicate.
		{"knownhosts.DuplicateError", &pkgknownhosts.DuplicateError{Host: "h"}, sdkssh.JSONRPCCodeDuplicate},
		{"authorized.DuplicateError", &pkgauthorized.DuplicateError{Name: "n"}, sdkssh.JSONRPCCodeDuplicate},
		{"keys.OwnerConflictError", &pkgkeys.OwnerConflictError{ID: "tenant/o/n"}, sdkssh.JSONRPCCodeDuplicate},

		// Mismatch (MITM) — separable from Duplicate, unlike REST's shared 409.
		{"knownhosts.MismatchError_MITM", &pkgknownhosts.MismatchError{
			Host: "h", Expected: "SHA256:a", Received: "SHA256:b",
		}, sdkssh.JSONRPCCodeMismatch},

		// Method not found (transport stub).
		{"NotImplementedError", &sdkssh.NotImplementedError{Transport: "mcp", Op: "Session.Dial"}, -32601},

		// Invalid params.
		{"sdk.InvalidScopeError", &sdkssh.InvalidScopeError{Value: "bogus"}, -32602},
		{"sdk.InvalidAlgorithmError", &sdkssh.InvalidAlgorithmError{Value: "rot13"}, -32602},
		{"sdk.NilInputError", &sdkssh.NilInputError{Field: "Name"}, -32602},
		{"keys.NilInputError", &pkgkeys.NilInputError{Field: "Name"}, -32602},

		// Internal error — anything else.
		{"unknown_error", errors.New("something else entirely"), -32603},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sdkssh.JSONRPCCodeForError(tc.err); got != tc.want {
				t.Errorf("JSONRPCCodeForError(%T) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

// TestJSONRPCCodeForError_WalksUnwrapChain proves the mapping uses
// errors.As via the shared classify() dispatch rather than a concrete type
// switch, so a wrapped typed error still resolves correctly.
func TestJSONRPCCodeForError_WalksUnwrapChain(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"wrapped_not_found", fmt.Errorf("loading pin: %w", &pkgknownhosts.NotFoundError{Host: "h"}), sdkssh.JSONRPCCodeNotFound},
		{"wrapped_mismatch", fmt.Errorf("verify: %w", &pkgknownhosts.MismatchError{Host: "h"}), sdkssh.JSONRPCCodeMismatch},
		{"wrapped_unknown_stays_internal", fmt.Errorf("outer: %w", errors.New("opaque")), -32603},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sdkssh.JSONRPCCodeForError(tc.err); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// TestJSONRPCCodeForError_MismatchDistinctFromDuplicate pins the property
// JSON-RPC's reserved error-code range buys over REST: unlike REST's shared
// 409, JSONRPCCodeMismatch and JSONRPCCodeDuplicate must resolve to
// different codes so an MCP caller can distinguish "pin already exists"
// from "the presented host key does not match the pin".
func TestJSONRPCCodeForError_MismatchDistinctFromDuplicate(t *testing.T) {
	dup := sdkssh.JSONRPCCodeForError(&pkgknownhosts.DuplicateError{Host: "h"})
	mismatch := sdkssh.JSONRPCCodeForError(&pkgknownhosts.MismatchError{Host: "h"})
	if dup == mismatch {
		t.Fatalf("duplicate (%d) and mismatch (%d) must not share a code", dup, mismatch)
	}
}
