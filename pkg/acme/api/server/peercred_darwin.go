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

//go:build darwin

package server

import (
	"net"

	"golang.org/x/sys/unix"
)

// checkPeerCredentialSupport reports that Darwin implements LOCAL_PEERCRED
// and LOCAL_PEEREPID.
func checkPeerCredentialSupport() error {
	return nil
}

// peerCredentialsFromConn reads the kernel-verified UID/GID/PID of the peer
// of a Unix domain socket connection using LOCAL_PEERCRED (UID and primary
// GID) and LOCAL_PEEREPID (the peer's effective process ID). Both values
// come from the kernel's record of the socket's connecting process and
// cannot be forged by the peer.
func peerCredentialsFromConn(conn *net.UnixConn) (*PeerCredentials, error) {
	sysConn, err := conn.SyscallConn()
	if err != nil {
		return nil, ErrPeerCredentialsFailed{Reason: err.Error()}
	}

	var xucred *unix.Xucred
	var pid int
	var credErr, pidErr error
	if ctrlErr := sysConn.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return
		}
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEEREPID)
	}); ctrlErr != nil {
		return nil, ErrPeerCredentialsFailed{Reason: ctrlErr.Error()}
	}
	if credErr != nil {
		return nil, ErrPeerCredentialsFailed{Reason: credErr.Error()}
	}
	if pidErr != nil {
		return nil, ErrPeerCredentialsFailed{Reason: pidErr.Error()}
	}
	if xucred.Ngroups < 1 {
		return nil, ErrPeerCredentialsFailed{Reason: "kernel reported no peer group"}
	}

	return &PeerCredentials{
		PID: int32(pid),
		UID: xucred.Uid,
		GID: xucred.Groups[0],
	}, nil
}
