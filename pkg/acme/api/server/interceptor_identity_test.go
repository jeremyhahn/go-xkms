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

//go:build !integration

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// certWithSubject builds an unsigned *x509.Certificate carrying only the
// Subject fields the functions under test read (CommonName,
// OrganizationalUnit). It is never parsed from DER or verified, which is
// fine here: peerCertificate, certificateRoles and the authenticator's
// default subject/metadata extraction only read struct fields, never
// signatures.
func certWithSubject(commonName string, organizationalUnit ...string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: organizationalUnit,
		},
	}
}

// peerContextWithCert returns a context carrying a gRPC peer whose AuthInfo
// is credentials.TLSInfo with cert as the sole verified peer certificate,
// mirroring how a real TLS handshake publishes the client cert.
func peerContextWithCert(cert *x509.Certificate) context.Context {
	p := &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	}
	return peer.NewContext(context.Background(), p)
}

func TestCertificateRoles_NilCertificate(t *testing.T) {
	assert.Nil(t, certificateRoles(nil))
}

func TestCertificateRoles_NoOrganizationalUnit(t *testing.T) {
	cert := certWithSubject("no-ou-client")
	assert.Nil(t, certificateRoles(cert))
}

func TestCertificateRoles_ReturnsOrganizationalUnits(t *testing.T) {
	cert := certWithSubject("client", "admin", "operator")
	assert.Equal(t, []string{"admin", "operator"}, certificateRoles(cert))
}

// TestCertificateRoles_SkipsEmptyEntries proves a blank OU value (which a
// misconfigured issuer could produce) never becomes a blank role that would
// otherwise match an unintended RBAC grant.
func TestCertificateRoles_SkipsEmptyEntries(t *testing.T) {
	cert := certWithSubject("client", "admin", "", "operator")
	assert.Equal(t, []string{"admin", "operator"}, certificateRoles(cert))
}

// TestCertificateRoles_AllEmptyEntriesYieldsNil proves an OU slice made up
// entirely of blank values mints no role, not a slice of empty strings.
func TestCertificateRoles_AllEmptyEntriesYieldsNil(t *testing.T) {
	cert := certWithSubject("client", "", "")
	assert.Nil(t, certificateRoles(cert))
}

func TestPeerCertificate_NoPeerInContext(t *testing.T) {
	assert.Nil(t, peerCertificate(context.Background()))
}

func TestPeerCertificate_NoTLSInfo(t *testing.T) {
	p := &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, AuthInfo: nil}
	ctx := peer.NewContext(context.Background(), p)
	assert.Nil(t, peerCertificate(ctx))
}

func TestPeerCertificate_NoPeerCertificates(t *testing.T) {
	p := &peer.Peer{
		Addr:     &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1},
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}},
	}
	ctx := peer.NewContext(context.Background(), p)
	assert.Nil(t, peerCertificate(ctx))
}

func TestPeerCertificate_ReturnsLeafCertificate(t *testing.T) {
	cert := certWithSubject("grpc-peer")
	ctx := peerContextWithCert(cert)
	assert.Same(t, cert, peerCertificate(ctx))
}

// TestUnaryMTLSIdentityInterceptor_ExistingIdentityPassesThrough proves the
// interceptor does not re-authenticate or override an identity a preceding
// interceptor already published (e.g. the Unix peer-credential path).
func TestUnaryMTLSIdentityInterceptor_ExistingIdentityPassesThrough(t *testing.T) {
	interceptor := UnaryMTLSIdentityInterceptor(nil, nil, testLogger())

	existing := &auth.Identity{Subject: "uid:1000"}
	ctx := auth.WithIdentity(context.Background(), existing)

	var ran bool
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		assert.Same(t, existing, auth.GetIdentity(ctx))
		return "ok", nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
}

// TestUnaryMTLSIdentityInterceptor_NoClientCertificate proves a call with no
// client certificate (plaintext, Unix socket, or TLS with no client auth)
// reaches the handler with no identity attached, leaving the denial to the
// authorization interceptor that runs after it.
func TestUnaryMTLSIdentityInterceptor_NoClientCertificate(t *testing.T) {
	interceptor := UnaryMTLSIdentityInterceptor(nil, nil, testLogger())

	var ran bool
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		assert.Nil(t, auth.GetIdentity(ctx))
		return "ok", nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
}

// TestUnaryMTLSIdentityInterceptor_AuthenticatesFromCertificate proves a call
// carrying a verified client certificate is authenticated and the resulting
// identity, with roles filled in from the certificate's OrganizationalUnit
// (the authenticator resolves no roles with a nil UserStore), is published
// on the context the handler sees.
func TestUnaryMTLSIdentityInterceptor_AuthenticatesFromCertificate(t *testing.T) {
	authenticator := auth.NewMTLSAuthenticator(nil)
	interceptor := UnaryMTLSIdentityInterceptor(authenticator, nil, testLogger())

	cert := certWithSubject("grpc-admin", "admin")
	ctx := peerContextWithCert(cert)

	var ran bool
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		id := auth.GetIdentity(ctx)
		require.NotNil(t, id)
		assert.Equal(t, "grpc-admin", id.Subject)
		assert.Equal(t, []string{"admin"}, id.Roles)
		return "ok", nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
}

// TestUnaryMTLSIdentityInterceptor_CustomRoleExtractor proves a caller-supplied
// roleExtractor, not just the package default certificateRoles, is honored
// when the authenticator resolves no roles of its own.
func TestUnaryMTLSIdentityInterceptor_CustomRoleExtractor(t *testing.T) {
	authenticator := auth.NewMTLSAuthenticator(nil)
	custom := func(cert *x509.Certificate) []string { return []string{"custom-role"} }
	interceptor := UnaryMTLSIdentityInterceptor(authenticator, custom, testLogger())

	cert := certWithSubject("grpc-client")
	ctx := peerContextWithCert(cert)

	var ran bool
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		id := auth.GetIdentity(ctx)
		require.NotNil(t, id)
		assert.Equal(t, []string{"custom-role"}, id.Roles)
		return "ok", nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
}

// TestUnaryMTLSIdentityInterceptor_DefaultsWhenNilArgsGiven proves the
// constructor's nil-fallback wiring (default authenticator, default role
// extractor, default logger) produces a working interceptor rather than a
// nil-pointer panic.
func TestUnaryMTLSIdentityInterceptor_DefaultsWhenNilArgsGiven(t *testing.T) {
	interceptor := UnaryMTLSIdentityInterceptor(nil, nil, nil)
	require.NotNil(t, interceptor)

	cert := certWithSubject("default-wiring-client", "operator")
	ctx := peerContextWithCert(cert)

	var ran bool
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/x/Y"}, func(ctx context.Context, req interface{}) (interface{}, error) {
		ran = true
		id := auth.GetIdentity(ctx)
		require.NotNil(t, id)
		assert.Equal(t, []string{"operator"}, id.Roles)
		return "ok", nil
	})

	require.NoError(t, err)
	assert.True(t, ran)
}
