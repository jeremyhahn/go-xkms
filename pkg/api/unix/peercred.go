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
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
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

	// exclusive drops the implicit admission of the daemon's own uid and
	// root: only the configured allowlists are admitted.
	exclusive bool
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

// NewExclusivePeerCredentialPolicy builds a policy admitting only the given
// allowlists. Unlike NewPeerCredentialPolicy it does not admit the daemon's
// own uid or root implicitly: a socket that exists to serve one named
// consumer (an IKE daemon reaching a sign-only slot, say) refuses every other
// process on the host, including privileged ones that were not named.
func NewExclusivePeerCredentialPolicy(allowedUIDs, allowedGIDs []uint32) *PeerCredentialPolicy {
	p := NewPeerCredentialPolicy(allowedUIDs, allowedGIDs)
	p.exclusive = true
	return p
}

// Allowed reports whether creds may connect: the daemon's own uid, root, or
// an explicitly configured uid/gid, or under an exclusive policy only the
// configured uid/gid. A nil creds (never produced by peercred.FromConn on
// success) is refused.
func (p *PeerCredentialPolicy) Allowed(creds *peercred.Credentials) bool {
	if creds == nil {
		return false
	}
	if !p.exclusive && (creds.UID == 0 || creds.UID == p.daemonUID) {
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

// ErrNoAdmittedPeers is returned by GRPCServer.Start for an exclusive peer
// policy with no allowlisted uid or gid: such a listener could admit no
// process, so it is a configuration error rather than a socket to bind.
var ErrNoAdmittedPeers = errors.New("unix listener: exclusive peer policy names no uid or gid")

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

// PeerAuthMethod is the auth_method metadata of the identity the listener
// attaches to an admitted peer.
const PeerAuthMethod = "unix-peer"

// identity returns the explicit identity of an admitted peer: subject
// "uid:<uid>" in the system tenant. The peer policy admits only the daemon's
// own uid, root and the configured uids/gids -- operators of this host -- so
// the peer acts in the system tenant, confined to it like every other
// system-tenant caller (pkg/scope).
func (a peerCredentialAuthInfo) identity() *auth.Identity {
	creds := a.credentials
	uid := strconv.FormatUint(uint64(creds.UID), 10)
	return &auth.Identity{
		Subject:  "uid:" + uid,
		TenantID: qrdbsdk.SystemTenantID,
		Metadata: map[string]string{
			"auth_method": PeerAuthMethod,
			"uid":         uid,
			"gid":         strconv.FormatUint(uint64(creds.GID), 10),
			"pid":         strconv.FormatInt(int64(creds.PID), 10),
		},
	}
}

// withPeerIdentity returns ctx carrying the identity of the request's peer
// when the peer passed the peer-credential policy. Any other context is
// returned unchanged and reaches the handlers with no identity, which every
// identity-scoped operation refuses.
func withPeerIdentity(ctx context.Context) context.Context {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ctx
	}
	info, ok := p.AuthInfo.(peerCredentialAuthInfo)
	if !ok || info.credentials == nil {
		return ctx
	}
	return auth.WithIdentity(ctx, info.identity())
}

// peerIdentityUnaryInterceptor attaches the admitted peer's identity to every
// unary request.
func peerIdentityUnaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return handler(withPeerIdentity(ctx), req)
}

// peerIdentityStreamInterceptor attaches the admitted peer's identity to
// every stream.
func peerIdentityStreamInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &peerIdentityStream{ServerStream: ss, ctx: withPeerIdentity(ss.Context())})
}

// peerIdentityStream is a grpc.ServerStream whose context carries the peer's
// identity.
type peerIdentityStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the stream context carrying the peer's identity.
func (s *peerIdentityStream) Context() context.Context {
	return s.ctx
}
