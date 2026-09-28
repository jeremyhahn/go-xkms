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
// of conn against trusted. The uid comes from the kernel's record of the
// socket (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS and FreeBSD), so the
// peer cannot forge it.
func verifyPeer(conn net.Conn, trusted []int) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return &DetailError{Err: ErrPeerCredentials, Detail: fmt.Sprintf(": %T is not a unix socket", conn)}
	}
	uid, err := peerUID(unixConn)
	if err != nil {
		return err
	}
	if !slices.Contains(trusted, uid) {
		return &DetailError{Err: ErrPeerUntrusted, Detail: fmt.Sprintf(": peer uid %d", uid)}
	}
	return nil
}
