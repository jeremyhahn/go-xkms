// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import "fmt"

// ErrNoPeerInfo is returned when peer information is not available in the gRPC context.
type ErrNoPeerInfo struct{}

func (e ErrNoPeerInfo) Error() string {
	return "no peer information in context"
}

// ErrNotUnixConnection is returned when peer credentials are requested for a non-Unix connection.
type ErrNotUnixConnection struct{}

func (e ErrNotUnixConnection) Error() string {
	return "connection is not a Unix socket"
}

// ErrPeerCredentialsFailed is returned when SO_PEERCRED extraction fails.
type ErrPeerCredentialsFailed struct {
	Reason string
}

func (e ErrPeerCredentialsFailed) Error() string {
	return fmt.Sprintf("failed to get peer credentials: %s", e.Reason)
}

// ErrPermissionDenied is returned when authorization check fails.
type ErrPermissionDenied struct {
	UID      uint32
	GID      uint32
	Role     Role
	Method   string
	Required Role
}

func (e ErrPermissionDenied) Error() string {
	return fmt.Sprintf("permission denied for uid=%d gid=%d role=%s: method %s requires role %s",
		e.UID, e.GID, e.Role, e.Method, e.Required)
}
