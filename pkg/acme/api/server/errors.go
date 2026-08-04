// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package server

import (
	"fmt"
	"strconv"
)

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

// ErrInvalidUserID is returned when a wire-format user id (a decimal
// string carried over the proto/transport boundary) cannot be parsed
// into qrdb's canonical uint64 user identifier.
type ErrInvalidUserID struct {
	// Value is the offending wire-format id.
	Value string
}

func (e ErrInvalidUserID) Error() string {
	return fmt.Sprintf("invalid user id: %q is not a uint64", e.Value)
}

// parseUserID converts a wire-format (decimal string) user id into
// qrdb's uint64 user identifier. An empty string yields 0 (no id),
// matching the qrdb convention where a zero id is unset.
func parseUserID(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, ErrInvalidUserID{Value: s}
	}
	return id, nil
}

// formatUserID renders qrdb's uint64 user identifier as the decimal
// wire-format string used across the proto/transport boundary.
func formatUserID(id uint64) string {
	return strconv.FormatUint(id, 10)
}
