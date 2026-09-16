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

//go:build !linux && !darwin

package server

import (
	"net"
	"runtime"
)

// checkPeerCredentialSupport refuses construction on every platform other
// than Linux and Darwin, the two this package implements a kernel
// peer-credential mechanism for (SO_PEERCRED and LOCAL_PEERCRED/
// LOCAL_PEEREPID, respectively — see peercred_linux.go and
// peercred_darwin.go).
//
// This covers Windows, which has no equivalent of SO_PEERCRED at all — the
// same reasoning ownership_other.go in pkg/ssh/agent applies to ACL-based
// ownership applies here to peer identity: a check that cannot see the
// credential it is asked for has no business returning one. It also covers
// FreeBSD, OpenBSD, and NetBSD, each of which exposes its own kernel
// mechanism (LOCAL_PEERCRED, SO_PEERCRED, and LOCAL_PEEREID respectively),
// but none of which is a build target this project ships, tests, or has
// verified golang.org/x/sys/unix wrappers for. Guessing at an unverified
// syscall layout would be exactly the silent degradation this package must
// not ship: a caller refused here can escalate the gap; a caller admitted on
// a credential nobody verified could not be told apart from a bug.
func checkPeerCredentialSupport() error {
	return ErrPeerCredentialsUnsupported{GOOS: runtime.GOOS}
}

// peerCredentialsFromConn is unreachable: NewUnixPeerCredentials refuses
// construction via checkPeerCredentialSupport before any listener that could
// call this function is created.
func peerCredentialsFromConn(*net.UnixConn) (*PeerCredentials, error) {
	return nil, ErrPeerCredentialsUnsupported{GOOS: runtime.GOOS}
}
