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
	"crypto/x509"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// UnaryMTLSIdentityInterceptor returns a gRPC unary server interceptor that
// authenticates TCP callers from their verified TLS client certificate and
// publishes the canonical auth.Identity on the request context. It is the
// authentication layer the ACME admin gRPC TCP listener previously lacked: the
// authorization interceptor assumed such a layer existed and passed every
// credential-less call straight to the handler.
//
// Authentication is delegated to certAuth, the ACME admin surface's one
// certificate-to-identity rule (admin.MTLSAuthHandler) the REST admin listener
// applies too: the caller's tenant is the one qrdbsdk.TenantFromClientCert
// names, and its roles are those of the go-qrdb user the certificate binds to
// in that tenant. Nothing in the certificate, its OU least of all, grants a
// role. The resolved tenant is bound on the request context as well as on the
// identity.
//
// The interceptor never denies on its own: a call with no usable client
// certificate, or one certAuth cannot resolve (including a nil certAuth),
// simply carries no identity, and the authorization interceptor that runs
// after it denies with Unauthenticated. Keeping the denial in one place means
// there is exactly one gate to reason about.
func UnaryMTLSIdentityInterceptor(certAuth *admin.MTLSAuthHandler, logger *slog.Logger) grpc.UnaryServerInterceptor {
	if logger == nil {
		logger = slog.Default()
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if auth.GetIdentity(ctx) != nil {
			return handler(ctx, req)
		}

		cert := peerCertificate(ctx)
		if cert == nil {
			logger.DebugContext(ctx, "ACME admin gRPC call carries no client certificate",
				slog.String("method", info.FullMethod))
			return handler(ctx, req)
		}

		md, _ := metadata.FromIncomingContext(ctx)
		identity, err := certAuth.AuthenticateGRPC(ctx, cert, md)
		if err != nil {
			logger.DebugContext(ctx, "ACME admin gRPC mTLS authentication produced no identity",
				slog.String("method", info.FullMethod),
				slog.String("error", err.Error()))
			return handler(ctx, req)
		}

		ctx = qrdbsdk.ContextWithTenant(ctx, identity.TenantID)
		return handler(auth.WithIdentity(ctx, identity), req)
	}
}

// peerCertificate returns the verified TLS client certificate on the gRPC
// peer, or nil when the connection carries none (plaintext, Unix socket, or a
// TLS handshake without client authentication).
func peerCertificate(ctx context.Context) *x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil
	}
	return tlsInfo.State.PeerCertificates[0]
}
