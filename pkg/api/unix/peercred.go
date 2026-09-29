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

package unix

import (
	"context"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc/credentials"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/peercred"
)

// PeerCredentialPolicy decides which Unix-socket peers GRPCServer admits at
// accept time, independent of and prior to any RBAC decision -- this
// listener registers its keystore service with grpcinternal.WithLocalTrust
// (RBAC off, see GRPCServer.Start), so the kernel-verified peer identity is
// the only gate a connection passes through. The default policy admits only
// the daemon's own uid and root (uid 0); GRPCConfig.AllowedUIDs /
// GRPCConfig.AllowedGIDs extend it for a deployment that runs a companion
// process under a different uid that must also reach this socket.
type PeerCredentialPolicy struct {
	daemonUID   uint32
	allowedUIDs map[uint32]struct{}
	allowedGIDs map[uint32]struct{}
}

// NewPeerCredentialPolicy builds a policy admitting the calling process's
// own effective uid, root (uid 0), and the given allowlists.
func NewPeerCredentialPolicy(allowedUIDs, allowedGIDs []uint32) *PeerCredentialPolicy {
	p := &PeerCredentialPolicy{
		daemonUID:   uint32(os.Geteuid()),
		allowedUIDs: make(map[uint32]struct{}, len(allowedUIDs)),
		allowedGIDs: make(map[uint32]struct{}, len(allowedGIDs)),
	}
	for _, uid := range allowedUIDs {
		p.allowedUIDs[uid] = struct{}{}
	}
	for _, gid := range allowedGIDs {
		p.allowedGIDs[gid] = struct{}{}
	}
	return p
}

// Allowed reports whether creds may connect: the daemon's own uid, root, or
// an explicitly configured uid/gid. A nil creds (never produced by
// peercred.FromConn on success) is refused.
func (p *PeerCredentialPolicy) Allowed(creds *peercred.Credentials) bool {
	if creds == nil {
		return false
	}
	if creds.UID == 0 || creds.UID == p.daemonUID {
		return true
	}
	if _, ok := p.allowedUIDs[creds.UID]; ok {
		return true
	}
	if _, ok := p.allowedGIDs[creds.GID]; ok {
		return true
	}
	return false
}

// PeerCredentialDeniedError reports a Unix-socket peer refused at accept
// time because its kernel-verified uid/gid matched neither the daemon's own
// identity, root, nor the configured allowlist.
type PeerCredentialDeniedError struct {
	UID uint32
	GID uint32
}

// Error implements the error interface.
func (e *PeerCredentialDeniedError) Error() string {
	return fmt.Sprintf(
		"peer credential denied: uid=%d gid=%d is not the daemon uid, root, or an allowlisted uid/gid",
		e.UID, e.GID)
}

// peerCredentialTransport is a server-only grpc credentials.TransportCredentials
// that refuses any connection whose kernel-verified Unix peer credentials
// (see pkg/peercred) do not satisfy policy. It runs during the transport
// handshake -- before any RPC reaches a handler or interceptor -- so a
// refused connection never enters the stream pipeline.
type peerCredentialTransport struct {
	policy *PeerCredentialPolicy
}

// newPeerCredentialTransport returns transport credentials enforcing policy
// on every connection accepted by this listener.
func newPeerCredentialTransport(policy *PeerCredentialPolicy) credentials.TransportCredentials {
	return &peerCredentialTransport{policy: policy}
}

// ClientHandshake always fails: this listener never dials out as a gRPC
// client, so there is no client-side identity to establish.
func (t *peerCredentialTransport) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, &errs.Message{Msg: "peer credential transport does not support client-side handshakes"}
}

// ServerHandshake refuses any connection that is not a Unix domain socket,
// any connection whose kernel peer credentials cannot be read, and any
// connection policy does not admit.
func (t *peerCredentialTransport) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, &errs.Message{Msg: "connection is not a Unix socket"}
	}

	creds, err := peercred.FromConn(unixConn)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "failed to read peer credentials", Err: err}
	}

	if !t.policy.Allowed(creds) {
		return nil, nil, &PeerCredentialDeniedError{UID: creds.UID, GID: creds.GID}
	}

	return conn, peerCredentialAuthInfo{credentials: creds}, nil
}

// Info describes the security properties of this transport credential.
func (t *peerCredentialTransport) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "so_peercred"}
}

// Clone returns a copy of the credentials, sharing the same policy.
func (t *peerCredentialTransport) Clone() credentials.TransportCredentials {
	return &peerCredentialTransport{policy: t.policy}
}

// OverrideServerName is part of the credentials.TransportCredentials
// interface. It has no meaning for a Unix domain socket peer-credential
// transport and is a deliberate no-op.
func (t *peerCredentialTransport) OverrideServerName(string) error {
	return nil
}

// peerCredentialAuthInfo implements credentials.AuthInfo, carrying the
// kernel-verified identity of the connecting peer.
type peerCredentialAuthInfo struct {
	credentials *peercred.Credentials
}

// AuthType returns the type of authentication.
func (peerCredentialAuthInfo) AuthType() string {
	return "peer_credentials"
}
