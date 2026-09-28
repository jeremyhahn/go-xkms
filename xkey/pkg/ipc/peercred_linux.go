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

//go:build linux

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the peer's uid from SO_PEERCRED, which records the
// credentials of the process that called connect(2) or listen(2).
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, &SentinelCauseError{Sentinel: ErrPeerCredentials, Cause: err}
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, &SentinelCauseError{Sentinel: ErrPeerCredentials, Cause: err}
	}
	if credErr != nil {
		return 0, &SentinelCauseError{Sentinel: ErrPeerCredentials, Cause: credErr}
	}
	return int(cred.Uid), nil
}
