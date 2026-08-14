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

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// UnaryMTLSIdentityInterceptor returns a gRPC unary server interceptor that
// authenticates TCP callers from their verified TLS client certificate and
// publishes the canonical auth.Identity on the request context. It is the
// authentication layer the ACME admin gRPC TCP listener previously lacked: the
// authorization interceptor assumed such a layer existed and passed every
// credential-less call straight to the handler.
//
// Authentication itself is delegated to the canonical xkms mTLS authenticator
// (auth.MTLSAuthenticator), so certificate-to-identity resolution — including
// SPKI-thumbprint user lookup when a UserStore is configured — is identical to
// the main xkms transports.
//
// The interceptor never denies on its own: a call with no usable client
// certificate simply carries no identity, and the authorization interceptor
// that runs after it denies with Unauthenticated. Keeping the denial in one
// place means there is exactly one gate to reason about.
func UnaryMTLSIdentityInterceptor(authenticator *auth.MTLSAuthenticator, roleExtractor func(*x509.Certificate) []string, logger *slog.Logger) grpc.UnaryServerInterceptor {
	if authenticator == nil {
		authenticator = auth.NewMTLSAuthenticator(nil)
	}
	if roleExtractor == nil {
		roleExtractor = certificateRoles
	}
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
		identity, err := authenticator.AuthenticateGRPC(ctx, md)
		if err != nil {
			logger.DebugContext(ctx, "ACME admin gRPC mTLS authentication produced no identity",
				slog.String("method", info.FullMethod),
				slog.String("error", err.Error()))
			return handler(ctx, req)
		}

		// The authenticator resolves roles only when a UserStore matched the
		// certificate. Otherwise fall back to the certificate's own role
		// claim, mirroring the ACME admin REST mTLS middleware.
		if len(identity.Roles) == 0 {
			identity.Roles = roleExtractor(cert)
		}

		return handler(auth.WithIdentity(ctx, identity), req)
	}
}

// certificateRoles reads role names from the certificate's Organizational Unit
// values. It mints no fallback role: a certificate naming no role yields no
// grants and every privileged method is denied.
func certificateRoles(cert *x509.Certificate) []string {
	if cert == nil || len(cert.Subject.OrganizationalUnit) == 0 {
		return nil
	}
	roles := make([]string, 0, len(cert.Subject.OrganizationalUnit))
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == "" {
			continue
		}
		roles = append(roles, ou)
	}
	if len(roles) == 0 {
		return nil
	}
	return roles
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
