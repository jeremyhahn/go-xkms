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

//go:build !linux && !darwin && !freebsd

package ipc

import "net"

// peerUID refuses on platforms where xkey reads no peer credentials (the
// other BSDs, illumos, Windows), so both ends fail closed: to a client an
// unverified peer might be another user's listener about to receive a PIN,
// and to the server it might be another user's process about to ask for a
// signature or a stored password.
func peerUID(_ *net.UnixConn) (int, error) {
	return 0, ErrPeerCredentialsUnsupported
}
