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
// sub-system (key, known_hosts, or authorized_keys stores) into a
// *KeyOpError carrying the JSON-RPC error code InvokeMethod should report.
// It reuses sdkssh.JSONRPCCodeForError -- the single table shared with the
// gRPC transport (pkg/api/grpc's sshStatus, via sdkssh.GRPCCodeForError) and
// the SSH SDK's own MCP client (sdk/go/client/ssh/mcp.go) -- rather than
// re-deriving the store's NotFound/Duplicate/Mismatch semantics here, so a
// missing key, a re-pinned host, and a known_hosts mismatch report the same
// class of failure this MCP surface's REST and gRPC siblings already report
// (#769).
func mapSSHError(err error) error {
	if err == nil {
		return nil
	}

	// *SSHNotFoundError is this package's own type (returned by
	// ssh.authorizedKeys.verify when no entry's fingerprint matches): it
	// carries no pkg/ssh/* sentinel for sdkssh.JSONRPCCodeForError's table
	// to recognize, so it is classified here instead of being silently
	// demoted to Internal.
	var notFound *SSHNotFoundError
	if errors.As(err, &notFound) {
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: err}
	}

	return &KeyOpError{Code: sdkssh.JSONRPCCodeForError(err), Err: err}
}
