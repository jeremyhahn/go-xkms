// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// mapSSHError converts an error returned by the sdkssh.Client SSH
// sub-system (key, known_hosts, or authorized_keys stores, or a handler's
// own params/parsing checks) into a *KeyOpError carrying the JSON-RPC error
// code InvokeMethod/mcpToolHandler should report -- the same role
// mapKeyOpError (errors_keyops.go) plays for the xkms.* key/crypto methods.
// Before this function existed, ssh.* handlers returned these errors
// unwrapped, so mcpToolHandler's `errors.As(err, &keyErr)` never matched and
// EVERY ssh.* failure -- not-found, duplicate, mismatch, bad input,
// whatever -- reached the caller as the same generic "xkms: internal error"
// (wire.CodeInternal), with the actual detail discarded (go-xkms#792).
//
// It reuses sdkssh.JSONRPCCodeForError -- the single table shared with the
// gRPC transport (pkg/api/grpc's sshStatus, via sdkssh.GRPCCodeForError) and
// the SSH SDK's own MCP client (sdk/go/client/ssh/mcp.go) -- rather than
// re-deriving the store's NotFound/Duplicate/Mismatch semantics here, so a
// missing key, a re-pinned host, and a known_hosts mismatch report the same
// class of failure this MCP surface's REST and gRPC siblings already report
// (#769). Unlike the xkms.* method family, whose eight-code vocabulary has
// no dedicated NotFound/AlreadyExists member, the SSH-specific codes
// (JSONRPCCodeNotFound/Duplicate/Mismatch, sdk/go/client/ssh/mcp_status.go)
// give the unified server's pkg/apimodule.keyOpCodeToWire (module_mcp_
// errors.go) enough to classify NotFound onto wire.CodeNotFound, Duplicate
// onto wire.CodeAlreadyExists, and Mismatch onto wire.CodeFailedPrecondition
// -- distinct codes, not the single ErrCodeInvalidParams bucket an earlier
// version of this function used.
func mapSSHError(err error) error {
	if err == nil {
		return nil
	}

	// Already classified by a lower layer (checkSSHClient, or a future
	// handler that wants a specific code) -- pass through unchanged so a
	// double-map never happens.
	var existing *KeyOpError
	if errors.As(err, &existing) {
		return existing
	}

	if errors.Is(err, ErrSSHNotConfigured) {
		// The whole sub-system is absent from this deployment, not merely
		// one operation on it -- distinct from the per-capability
		// ErrCodeMethodNotFound mapKeyOpError uses for
		// xkms.ErrOperationNotSupported, and from anything
		// JSONRPCCodeForError's table recognizes (ErrSSHNotConfigured is a
		// bare sentinel, not one of the typed store errors that table
		// walks).
		return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: err}
	}

	// *SSHNotFoundError and *SSHInvalidParamsError are this package's own
	// types (the former returned by ssh.authorizedKeys.verify when no
	// entry's fingerprint matches; the latter by every handler's own
	// params/parsing checks): neither carries a pkg/ssh/* or sdk/go/client/
	// ssh sentinel for sdkssh.JSONRPCCodeForError's table to recognize, so
	// both are classified here instead of being silently demoted to
	// Internal.
	var notFound *SSHNotFoundError
	if errors.As(err, &notFound) {
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: err}
	}
	var invalidParams *SSHInvalidParamsError
	if errors.As(err, &invalidParams) {
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	return &KeyOpError{Code: sdkssh.JSONRPCCodeForError(err), Err: err}
}
