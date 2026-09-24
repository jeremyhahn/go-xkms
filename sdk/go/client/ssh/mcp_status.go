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

// JSON-RPC 2.0 reserves the range -32000..-32099 for implementation-defined
// server errors (the standard code set -32700..-32603 has no NotFound or
// Conflict member). pkg/api/mcp/types.go already extends that range with
// ErrCodeUnauthorized (-32002), ErrCodeForbidden (-32003), and
// ErrCodeServiceUnavailable (-32004); JSONRPCCodeNotFound continues that
// table at -32001, matching the "Not found" convention already used by
// pkg/acme/api/server's MCP surface. JSONRPCCodeDuplicate and
// JSONRPCCodeMismatch are new: unlike REST, which reports both as 409
// because HTTP has no room for a finer distinction, JSON-RPC's reserved
// range costs nothing to keep them separable so a caller can tell "the pin
// is already there" from "the presented host key does not match the pin" --
// the same distinction the ssh.knownHosts.verify handler needs to preserve.
//
// These constants intentionally duplicate the *values* (not the logic) of
// the standard JSON-RPC 2.0 codes below rather than importing pkg/api/mcp:
// this package sits under pkg/api/mcp in the dependency graph (the API layer
// consumes the SDK, never the reverse), and the values are fixed by the
// JSON-RPC 2.0 spec, not by this project.
const (
	// jsonrpcCodeInvalidParams mirrors the JSON-RPC 2.0 spec's Invalid
	// params and pkg/api/mcp.ErrCodeInvalidParams.
	jsonrpcCodeInvalidParams = -32602
	// jsonrpcCodeMethodNotFound mirrors the JSON-RPC 2.0 spec's Method not
	// found and pkg/api/mcp.ErrCodeMethodNotFound.
	jsonrpcCodeMethodNotFound = -32601
	// jsonrpcCodeInternalError mirrors the JSON-RPC 2.0 spec's Internal
	// error and pkg/api/mcp.ErrCodeInternalError.
	jsonrpcCodeInternalError = -32603

	// JSONRPCCodeNotFound reports a missing key, known-host pin, or
	// authorized_keys entry -- the REST 404 and gRPC NotFound.
	JSONRPCCodeNotFound = -32001

	// JSONRPCCodeDuplicate reports a resource that already exists (Add
	// called twice without an intervening Remove) -- the REST 409 and gRPC
	// AlreadyExists.
	JSONRPCCodeDuplicate = -32005

	// JSONRPCCodeMismatch reports a known_hosts host-key mismatch, a
	// MITM-indicating condition -- the REST 409 and gRPC FailedPrecondition.
	JSONRPCCodeMismatch = -32006
)

// JSONRPCCodeForError returns the canonical JSON-RPC 2.0 error code for an
// error produced by any of the go-xkms SSH packages, sharing the classify()
// dispatch table with HTTPStatusForError and GRPCCodeForError so all three
// transports report the same NotFound/Duplicate/Mismatch semantics for the
// same typed store error.
func JSONRPCCodeForError(err error) int {
	if err == nil {
		return 0
	}
	switch classify(err) {
	case classNotFound:
		return JSONRPCCodeNotFound
	case classDuplicate:
		return JSONRPCCodeDuplicate
	case classMismatch:
		return JSONRPCCodeMismatch
	case classBadRequest:
		return jsonrpcCodeInvalidParams
	case classNotImplemented:
		return jsonrpcCodeMethodNotFound
	default:
		return jsonrpcCodeInternalError
	}
}
