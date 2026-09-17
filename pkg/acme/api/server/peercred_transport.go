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

package server

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
)

// unixPeerCredentials is a server-only grpc credentials.TransportCredentials
// that extracts the kernel-verified UID/GID/PID of a Unix domain socket peer
// during the transport handshake, via the platform's SO_PEERCRED equivalent
// (see peerCredentialsFromConn implementations). A connection that is not a
// Unix domain socket, or for which the kernel credential mechanism fails, is
// refused at the handshake — it never reaches a gRPC handler, and no identity
// is ever assumed.
type unixPeerCredentials struct{}

// NewUnixPeerCredentials returns transport credentials for a Unix domain
// socket gRPC listener. It fails at construction, before any socket is
// opened, on a platform with no kernel peer-credential mechanism this
// package implements.
func NewUnixPeerCredentials() (credentials.TransportCredentials, error) {
	if err := checkPeerCredentialSupport(); err != nil {
		return nil, err
	}
	return unixPeerCredentials{}, nil
}

// ClientHandshake always fails: xkmsd never dials this transport as a
// client, so there is no client-side identity to establish.
func (unixPeerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, ErrClientHandshakeUnsupported{}
}

// ServerHandshake refuses any connection that is not a Unix domain socket,
// and any Unix domain socket connection whose kernel peer credentials cannot
// be read, so the caller is never admitted without a verified identity.
func (unixPeerCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, ErrNotUnixConnection{}
	}

	creds, err := peerCredentialsFromConn(unixConn)
	if err != nil {
		return nil, nil, err
	}

	return conn, &PeerCredentialsAuthInfo{Credentials: creds}, nil
}

// Info describes the security properties of this transport credential.
func (unixPeerCredentials) Info() credentials.ProtocolInfo {
	// SecurityVersion is omitted: gRPC deprecated it in favour of
	// Peer.AuthInfo, and nothing in this tree read it.
	return credentials.ProtocolInfo{
		SecurityProtocol: "so_peercred",
	}
}

// Clone returns a copy of the credentials. unixPeerCredentials is stateless,
// so the receiver is returned directly.
func (c unixPeerCredentials) Clone() credentials.TransportCredentials {
	return c
}

// OverrideServerName is part of the credentials.TransportCredentials
// interface. It has no meaning for a Unix domain socket peer-credential
// transport and is a deliberate no-op.
func (unixPeerCredentials) OverrideServerName(string) error {
	return nil
}
