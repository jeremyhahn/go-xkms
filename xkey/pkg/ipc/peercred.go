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

package ipc

import (
	"fmt"
	"net"
	"slices"
)

// verifyPeer checks the kernel-reported uid of the process at the other end
// of conn against trusted and returns that uid. The uid comes from the
// kernel's record of the socket (SO_PEERCRED on Linux, LOCAL_PEERCRED on
// macOS and FreeBSD), so the peer cannot forge it.
//
// The client calls it on the connection to the listener before sending
// anything, and the server calls it on every accepted connection before
// reading anything (see Server.handleConnection). On a refused peer
// (ErrPeerUntrusted) the returned uid is the peer's, so the caller can log
// who was turned away; when the credentials cannot be read at all
// (ErrPeerCredentials, ErrPeerCredentialsUnsupported) there is no uid and
// the returned value is meaningless.
func verifyPeer(conn net.Conn, trusted []int) (int, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, &DetailError{Err: ErrPeerCredentials, Detail: fmt.Sprintf(": %T is not a unix socket", conn)}
	}
	uid, err := peerUID(unixConn)
	if err != nil {
		return 0, err
	}
	if !slices.Contains(trusted, uid) {
		return uid, &DetailError{Err: ErrPeerUntrusted, Detail: fmt.Sprintf(": peer uid %d", uid)}
	}
	return uid, nil
}
