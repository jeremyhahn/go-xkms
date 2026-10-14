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

// Package peercred reads the kernel-verified UID/GID/PID of a Unix domain
// socket peer. The value comes from the kernel's record of the connecting
// process and cannot be forged by the peer, unlike an application-layer
// credential the peer supplies itself.
//
// This is the one implementation of that mechanism in the tree; every Unix
// socket listener that needs to authenticate its peer at the kernel level
// (the ACME admin gRPC listener in pkg/acme/api/server, the keystore gRPC
// listener in pkg/api/unix) imports this package rather than carrying its
// own copy of the platform syscalls.
package peercred

import (
	"fmt"
	"net"
)

// Credentials holds the kernel-verified identity of a Unix domain socket
// peer.
type Credentials struct {
	// PID is the process ID of the peer.
	PID int32
	// UID is the user ID of the peer.
	UID uint32
	// GID is the primary group ID of the peer.
	GID uint32
}

// UnsupportedError is returned when the running platform has no kernel
// peer-credential mechanism this package implements. It is returned before
// any socket is opened, so a deployment on an unsupported platform never
// starts a listener it cannot authenticate.
type UnsupportedError struct {
	// GOOS is the runtime.GOOS value extraction was attempted on.
	GOOS string
}

// Error implements the error interface.
func (e UnsupportedError) Error() string {
	return fmt.Sprintf("peer credential extraction is not implemented for GOOS=%s", e.GOOS)
}

// ExtractionFailedError is returned when the kernel peer-credential syscall
// itself fails.
type ExtractionFailedError struct {
	// Reason describes the underlying syscall failure.
	Reason string
}

// Error implements the error interface.
func (e ExtractionFailedError) Error() string {
	return fmt.Sprintf("failed to get peer credentials: %s", e.Reason)
}

// CheckSupport reports whether this platform implements a kernel
// peer-credential mechanism. It returns UnsupportedError on every platform
// other than the ones peercred_linux.go and peercred_darwin.go implement.
func CheckSupport() error {
	return checkSupport()
}

// FromConn reads the kernel-verified UID/GID/PID of conn's peer.
func FromConn(conn *net.UnixConn) (*Credentials, error) {
	// A nil *net.UnixConn passes a caller's conn.(*net.UnixConn) assertion
	// when the interface holds a typed nil, and its methods dereference it.
	if conn == nil {
		return nil, ExtractionFailedError{Reason: "nil connection"}
	}
	return fromConn(conn)
}
