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

package server

import (
	"net"

	"golang.org/x/sys/unix"
)

// checkPeerCredentialSupport reports that Linux implements SO_PEERCRED.
func checkPeerCredentialSupport() error {
	return nil
}

// peerCredentialsFromConn reads the kernel-verified UID/GID/PID of the peer
// of a Unix domain socket connection using SO_PEERCRED. The value comes from
// the kernel's record of the socket's creating process and cannot be forged
// by the peer.
func peerCredentialsFromConn(conn *net.UnixConn) (*PeerCredentials, error) {
	sysConn, err := conn.SyscallConn()
	if err != nil {
		return nil, ErrPeerCredentialsFailed{Reason: err.Error()}
	}

	var ucred *unix.Ucred
	var sockErr error
	if ctrlErr := sysConn.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return nil, ErrPeerCredentialsFailed{Reason: ctrlErr.Error()}
	}
	if sockErr != nil {
		return nil, ErrPeerCredentialsFailed{Reason: sockErr.Error()}
	}

	return &PeerCredentials{
		PID: ucred.Pid,
		UID: ucred.Uid,
		GID: ucred.Gid,
	}, nil
}
