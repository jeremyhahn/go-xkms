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

	"github.com/jeremyhahn/go-xkms/pkg/peercred"
)

// checkPeerCredentialSupport reports that Darwin implements LOCAL_PEERCRED
// and LOCAL_PEEREPID.
func checkPeerCredentialSupport() error {
	return peercred.CheckSupport()
}

// peerCredentialsFromConn reads the kernel-verified UID/GID/PID of the peer
// of a Unix domain socket connection using LOCAL_PEERCRED (UID and primary
// GID) and LOCAL_PEEREPID (the peer's effective process ID), via the shared
// pkg/peercred implementation. Both values come from the kernel's record of
// the socket's connecting process and cannot be forged by the peer.
func peerCredentialsFromConn(conn *net.UnixConn) (*PeerCredentials, error) {
	creds, err := peercred.FromConn(conn)
	if err != nil {
		return nil, ErrPeerCredentialsFailed{Reason: err.Error()}
	}
	return &PeerCredentials{PID: creds.PID, UID: creds.UID, GID: creds.GID}, nil
}
