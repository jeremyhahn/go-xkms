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

//go:build !linux && !darwin

package peercred

import (
	"net"
	"runtime"
)

// checkSupport refuses construction on every platform other than Linux and
// Darwin, the two this package implements a kernel peer-credential mechanism
// for (SO_PEERCRED and LOCAL_PEERCRED/LOCAL_PEEREPID respectively -- see
// peercred_linux.go and peercred_darwin.go).
//
// This covers Windows, which has no equivalent of SO_PEERCRED at all, and
// FreeBSD, OpenBSD, and NetBSD, each of which exposes its own kernel
// mechanism (LOCAL_PEERCRED, SO_PEERCRED, and LOCAL_PEEREID respectively),
// but none of which is a build target this project ships, tests, or has
// verified golang.org/x/sys/unix wrappers for. Guessing at an unverified
// syscall layout would be exactly the silent degradation this package must
// not ship: a caller refused here can escalate the gap; a caller admitted on
// a credential nobody verified could not be told apart from a bug.
func checkSupport() error {
	return UnsupportedError{GOOS: runtime.GOOS}
}

// fromConn is unreachable: every caller of FromConn must first construct
// through a path that calls CheckSupport, which refuses before any socket
// that could reach here is created.
func fromConn(*net.UnixConn) (*Credentials, error) {
	return nil, UnsupportedError{GOOS: runtime.GOOS}
}
