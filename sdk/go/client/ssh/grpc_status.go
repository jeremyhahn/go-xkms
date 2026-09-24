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

package ssh

import (
	"errors"

	"google.golang.org/grpc/codes"
)

// GRPCCodeForError returns the canonical gRPC status code for an error
// produced by any of the go-xkms SSH packages. It shares the classify()
// dispatch table with HTTPStatusForError, so the gRPC and REST transports
// report the same NotFound/Duplicate/Mismatch semantics for the same typed
// store error instead of each transport re-deriving its own table.
//
// Mapping:
//
//	classNotFound                         -> NotFound
//	classDuplicate                        -> AlreadyExists
//	classMismatch                         -> FailedPrecondition (MITM)
//	classBadRequest                       -> InvalidArgument
//	classNotImplemented                   -> Unimplemented
//	*BackendUnavailableError               -> FailedPrecondition (capability
//	                                          gap: no backend provider wired
//	                                          for the requested backend)
//	anything else                          -> Internal
//
// BackendUnavailableError is classified ahead of the shared table because it
// is specific to the gRPC/embedded transport's backend-key-generation path
// and has no REST or MCP equivalent to keep in the shared table.
func GRPCCodeForError(err error) codes.Code {
	if err == nil {
		return codes.OK
	}

	var backendErr *BackendUnavailableError
	if errors.As(err, &backendErr) {
		return codes.FailedPrecondition
	}

	switch classify(err) {
	case classNotFound:
		return codes.NotFound
	case classDuplicate:
		return codes.AlreadyExists
	case classMismatch:
		return codes.FailedPrecondition
	case classBadRequest:
		return codes.InvalidArgument
	case classNotImplemented:
		return codes.Unimplemented
	default:
		return codes.Internal
	}
}
