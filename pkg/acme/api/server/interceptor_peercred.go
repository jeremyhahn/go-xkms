// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux || darwin || freebsd || openbsd || netbsd

package server

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// peerCredentialsKey is the context key for storing peer credentials.
type peerCredentialsKey struct{}

// PeerCredentials contains the credentials of the peer process obtained
// from a Unix domain socket connection via SO_PEERCRED.
type PeerCredentials struct {
	// PID is the process ID of the peer
	PID int32
	// UID is the user ID of the peer
	UID uint32
	// GID is the group ID of the peer
	GID uint32
}

// UnaryPeerCredentialsInterceptor returns a gRPC unary server interceptor that
// extracts peer credentials from Unix domain socket connections and stores them
// in the request context.
//
// For TCP connections, the interceptor passes through without adding credentials.
// The credentials are obtained using the SO_PEERCRED socket option, which is
// provided by the kernel and cannot be forged by the peer process.
func UnaryPeerCredentialsInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Try to extract peer credentials from the connection
		creds, err := extractPeerCredentials(ctx)
		if err == nil && creds != nil {
			// Store credentials in context for downstream handlers
			ctx = context.WithValue(ctx, peerCredentialsKey{}, creds)
		}
		// For TCP connections or if extraction fails, continue without credentials
		// The authorization interceptor will handle access control appropriately

		return handler(ctx, req)
	}
}

// GetPeerCredentials retrieves peer credentials from the context.
// Returns nil if no credentials are present (e.g., TCP connection).
func GetPeerCredentials(ctx context.Context) *PeerCredentials {
	if creds, ok := ctx.Value(peerCredentialsKey{}).(*PeerCredentials); ok {
		return creds
	}
	return nil
}

// extractPeerCredentials extracts SO_PEERCRED from a Unix socket connection.
func extractPeerCredentials(ctx context.Context) (*PeerCredentials, error) {
	// Get peer information from gRPC context
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, ErrNoPeerInfo{}
	}

	// Check if this is a Unix socket connection
	unixAddr, ok := p.Addr.(*net.UnixAddr)
	if !ok {
		// Not a Unix socket (probably TCP), return nil without error
		return nil, nil
	}

	// Get the underlying connection
	// For Unix sockets in gRPC, we need to get credentials through the transport
	// The peer.Peer struct doesn't directly expose the connection, so we use
	// a different approach: store credentials during connection setup

	// Note: In gRPC, accessing the raw connection from an interceptor is complex.
	// The recommended approach is to use a custom credentials implementation
	// or transport credentials that extract SO_PEERCRED during the handshake.
	// For now, we provide a simpler implementation that works with the local
	// context and connection information available.

	_ = unixAddr // Acknowledge we detected a Unix socket

	// Since gRPC doesn't provide direct access to the underlying Unix connection
	// in interceptors, we need to use an alternative approach. The credentials
	// can be extracted at the transport level using a custom TransportCredentials
	// implementation. However, for simplicity and compatibility, we'll check if
	// the AuthInfo contains peer credentials (which can be set by transport creds).

	if p.AuthInfo != nil {
		if pc, ok := p.AuthInfo.(*PeerCredentialsAuthInfo); ok {
			return pc.Credentials, nil
		}
	}

	return nil, nil
}

// PeerCredentialsAuthInfo implements credentials.AuthInfo for Unix socket peer credentials.
type PeerCredentialsAuthInfo struct {
	Credentials *PeerCredentials
}

// AuthType returns the type of authentication.
func (p *PeerCredentialsAuthInfo) AuthType() string {
	return "peer_credentials"
}
