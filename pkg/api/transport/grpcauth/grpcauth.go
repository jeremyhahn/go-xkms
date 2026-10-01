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


// Package grpcauth holds the client-side gRPC call authentication shared by
// the network gRPC transport and the Unix-socket transport: the configured
// login JWT presented as "authorization: Bearer" metadata on every RPC.
package grpcauth

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Bearer presents a JWT on every RPC as "authorization: Bearer <token>"
// metadata. It requires a secure channel: TLS on the network, or local
// credentials on a Unix socket.
type Bearer struct{ token string }

// GetRequestMetadata implements credentials.PerRPCCredentials.
func (b Bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials: a
// bearer token never crosses a plaintext connection.
func (Bearer) RequireTransportSecurity() bool { return true }

// Compile-time check that Bearer is a credentials.PerRPCCredentials.
var _ credentials.PerRPCCredentials = Bearer{}

// DialOptions returns the dial options that authenticate every RPC with
// token. It returns nil when token is empty, so no authorization metadata
// is invented.
func DialOptions(token string) []grpc.DialOption {
	if token == "" {
		return nil
	}
	return []grpc.DialOption{grpc.WithPerRPCCredentials(Bearer{token: token})}
}
