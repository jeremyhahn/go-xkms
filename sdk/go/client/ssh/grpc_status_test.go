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

	"google.golang.org/grpc/codes"

	pkgauthorized "github.com/jeremyhahn/go-xkms/pkg/ssh/authorized"
	pkgkeys "github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	pkgknownhosts "github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestGRPCCodeForError_MappingTable asserts every row of the mapping
// documented on GRPCCodeForError, including the BackendUnavailableError
// special case classified ahead of the shared classify() table. This table
// is the gRPC transport's half of the same contract HTTPStatusForError and
// JSONRPCCodeForError implement, so a drift here changes the status code
// gRPC clients branch on.
func TestGRPCCodeForError_MappingTable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"nil", nil, codes.OK},

		// NotFound.
		{"keys.KeyNotFoundError", &pkgkeys.KeyNotFoundError{ID: "k"}, codes.NotFound},
		{"knownhosts.NotFoundError", &pkgknownhosts.NotFoundError{Host: "h"}, codes.NotFound},
		{"authorized.NotFoundError", &pkgauthorized.NotFoundError{Name: "n"}, codes.NotFound},

		// AlreadyExists.
		{"knownhosts.DuplicateError", &pkgknownhosts.DuplicateError{Host: "h"}, codes.AlreadyExists},
		{"authorized.DuplicateError", &pkgauthorized.DuplicateError{Name: "n"}, codes.AlreadyExists},

		// FailedPrecondition (MITM).
		{"knownhosts.MismatchError_MITM", &pkgknownhosts.MismatchError{
			Host: "h", Expected: "SHA256:a", Received: "SHA256:b",
		}, codes.FailedPrecondition},

		// Unimplemented.
		{"NotImplementedError", &sdkssh.NotImplementedError{Transport: "grpc", Op: "Session.Dial"}, codes.Unimplemented},

		// InvalidArgument.
		{"sdk.InvalidScopeError", &sdkssh.InvalidScopeError{Value: "bogus"}, codes.InvalidArgument},
		{"sdk.InvalidAlgorithmError", &sdkssh.InvalidAlgorithmError{Value: "rot13"}, codes.InvalidArgument},
		{"sdk.NilInputError", &sdkssh.NilInputError{Field: "Name"}, codes.InvalidArgument},
		{"keys.NilInputError", &pkgkeys.NilInputError{Field: "Name"}, codes.InvalidArgument},

		// FailedPrecondition (capability gap), classified ahead of the
		// shared table.
		{"sdk.BackendUnavailableError", &sdkssh.BackendUnavailableError{Backend: "tpm2"}, codes.FailedPrecondition},

		// Internal — anything else.
		{"unknown_error", errors.New("something else entirely"), codes.Internal},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sdkssh.GRPCCodeForError(tc.err); got != tc.want {
				t.Errorf("GRPCCodeForError(%T) = %s, want %s", tc.err, got, tc.want)
			}
		})
	}
}

// TestGRPCCodeForError_WalksUnwrapChain proves the mapping uses errors.As
// (via classify() and errors.As on BackendUnavailableError) rather than a
// concrete type switch, so a wrapped typed error still resolves correctly.
func TestGRPCCodeForError_WalksUnwrapChain(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"wrapped_not_found", fmt.Errorf("loading pin: %w", &pkgknownhosts.NotFoundError{Host: "h"}), codes.NotFound},
		{"wrapped_backend_unavailable", fmt.Errorf("generate: %w", &sdkssh.BackendUnavailableError{Backend: "pkcs11"}), codes.FailedPrecondition},
		{"wrapped_unknown_stays_internal", fmt.Errorf("outer: %w", errors.New("opaque")), codes.Internal},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sdkssh.GRPCCodeForError(tc.err); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestGRPCCodeForError_BackendUnavailableBeatsSharedTable guards the
// dispatch ordering documented on GRPCCodeForError: BackendUnavailableError
// is checked before classify() runs, so it must not be reclassified as a
// generic Internal error even though it carries no entry in the shared
// classify() table.
func TestGRPCCodeForError_BackendUnavailableBeatsSharedTable(t *testing.T) {
	err := &sdkssh.BackendUnavailableError{Backend: "cloud"}
	if got := sdkssh.GRPCCodeForError(err); got != codes.FailedPrecondition {
		t.Errorf("got %s, want %s", got, codes.FailedPrecondition)
	}
}
