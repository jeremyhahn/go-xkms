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

//go:build (linux || darwin) && !integration

package server

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// realUnixConnPair returns a connected pair of *net.UnixConn backed by a real
// kernel AF_UNIX socketpair, so SO_PEERCRED (or its platform equivalent)
// reflects this test process's own genuine credentials — not a fake stand-in.
// Both ends must be closed by the caller.
func realUnixConnPair(t *testing.T) (client, server *net.UnixConn) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err, "unix.Socketpair")

	clientFile := os.NewFile(uintptr(fds[0]), "peercred-client")
	serverFile := os.NewFile(uintptr(fds[1]), "peercred-server")
	t.Cleanup(func() {
		_ = clientFile.Close()
		_ = serverFile.Close()
	})

	clientConn, err := net.FileConn(clientFile)
	require.NoError(t, err, "net.FileConn(client)")
	serverConn, err := net.FileConn(serverFile)
	require.NoError(t, err, "net.FileConn(server)")

	clientUnix, ok := clientConn.(*net.UnixConn)
	require.True(t, ok, "client end must be a *net.UnixConn")
	serverUnix, ok := serverConn.(*net.UnixConn)
	require.True(t, ok, "server end must be a *net.UnixConn")

	return clientUnix, serverUnix
}

// TestPeerCredentialsFromConn_MatchesRunningProcess verifies the kernel
// peer-credential extraction reports this test process's own real PID, UID,
// and GID -- not a value computed or assumed by this package.
func TestPeerCredentialsFromConn_MatchesRunningProcess(t *testing.T) {
	client, server := realUnixConnPair(t)
	defer client.Close()
	defer server.Close()

	creds, err := peerCredentialsFromConn(server)
	require.NoError(t, err)
	require.NotNil(t, creds)

	assert.Equal(t, uint32(os.Getuid()), creds.UID)
	assert.Equal(t, uint32(os.Getgid()), creds.GID)
	assert.Equal(t, int32(os.Getpid()), creds.PID)
}

// TestUnixPeerCredentials_ServerHandshake_RealSocket verifies the transport
// credential populates PeerCredentialsAuthInfo with the real, kernel-verified
// identity of the connecting process during ServerHandshake.
func TestUnixPeerCredentials_ServerHandshake_RealSocket(t *testing.T) {
	client, server := realUnixConnPair(t)
	defer client.Close()
	defer server.Close()

	creds, err := NewUnixPeerCredentials()
	require.NoError(t, err)

	conn, authInfo, err := creds.ServerHandshake(server)
	require.NoError(t, err)
	assert.Equal(t, server, conn)

	peerAuth, ok := authInfo.(*PeerCredentialsAuthInfo)
	require.True(t, ok, "AuthInfo must be *PeerCredentialsAuthInfo")
	require.NotNil(t, peerAuth.Credentials)
	assert.Equal(t, uint32(os.Getuid()), peerAuth.Credentials.UID)
	assert.Equal(t, uint32(os.Getgid()), peerAuth.Credentials.GID)
	assert.Equal(t, int32(os.Getpid()), peerAuth.Credentials.PID)
}

// TestUnixPeerCredentials_ServerHandshake_RefusesTCP verifies a non-Unix-socket
// connection is refused at the handshake with the typed error, never admitted
// with an empty or assumed identity.
func TestUnixPeerCredentials_ServerHandshake_RefusesTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			acceptedCh <- conn
		}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer clientConn.Close()

	serverConn := <-acceptedCh
	defer serverConn.Close()

	creds, err := NewUnixPeerCredentials()
	require.NoError(t, err)

	conn, authInfo, err := creds.ServerHandshake(serverConn)
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Nil(t, authInfo)
	_, ok := err.(ErrNotUnixConnection)
	assert.True(t, ok, "TCP connections must be refused with ErrNotUnixConnection, got %T: %v", err, err)
}

// TestNewUnixPeerCredentials_ConstructsOnSupportedPlatform verifies
// construction succeeds on Linux and Darwin, the platforms this package
// implements kernel peer-credential extraction for.
func TestNewUnixPeerCredentials_ConstructsOnSupportedPlatform(t *testing.T) {
	creds, err := NewUnixPeerCredentials()
	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, "so_peercred", creds.Info().SecurityProtocol)
}

// TestUnixPeerCredentials_ClientHandshakeUnsupported verifies the credential
// refuses client-side use rather than silently succeeding with no identity.
func TestUnixPeerCredentials_ClientHandshakeUnsupported(t *testing.T) {
	creds, err := NewUnixPeerCredentials()
	require.NoError(t, err)

	conn, authInfo, err := creds.ClientHandshake(context.Background(), "", nil)
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Nil(t, authInfo)
	_, ok := err.(ErrClientHandshakeUnsupported)
	assert.True(t, ok, "expected ErrClientHandshakeUnsupported, got %T: %v", err, err)
}

// TestUnixPeerCredentials_Clone verifies Clone returns a working, equivalent
// credential rather than a zero value or nil: unixPeerCredentials is
// stateless, so the clone must behave identically to the original.
func TestUnixPeerCredentials_Clone(t *testing.T) {
	creds, err := NewUnixPeerCredentials()
	require.NoError(t, err)

	clone := creds.Clone()
	require.NotNil(t, clone)
	assert.Equal(t, creds.Info(), clone.Info())
}

// TestUnaryAuthorizationInterceptor_RealPeerCredentials_MapsConfiguredUID
// exercises the full authentication path this interceptor is installed for:
// real kernel-extracted credentials from an AF_UNIX socketpair, mapped by a
// RoleMapping configured for this test process's real UID, reaching the
// authorizer as the expected role.
func TestUnaryAuthorizationInterceptor_RealPeerCredentials_MapsConfiguredUID(t *testing.T) {
	client, server := realUnixConnPair(t)
	defer client.Close()
	defer server.Close()

	realCreds, err := peerCredentialsFromConn(server)
	require.NoError(t, err)

	roleMapping := &RoleMapping{AdminUIDs: []uint32{realCreds.UID}}
	gate, rbac := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(roleMapping, gate, testLogger())

	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, realCreds)

	ran := false
	_, err = interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_RevokeCertificate_FullMethodName},
		func(ctx context.Context, _ interface{}) (interface{}, error) {
			ran = true
			id := auth.GetIdentity(ctx)
			require.NotNil(t, id)
			assert.Equal(t, []string{RoleAdmin}, id.Roles)
			return "ok", nil
		})

	require.NoError(t, err)
	assert.True(t, ran)
	assert.Equal(t, []string{"certs:revoke"}, rbac.requested)
}

// TestUnaryAuthorizationInterceptor_RealPeerCredentials_UnmappedUIDDenied
// verifies a real peer that matches no configured mapping entry is denied,
// never granted an implicit role.
func TestUnaryAuthorizationInterceptor_RealPeerCredentials_UnmappedUIDDenied(t *testing.T) {
	client, server := realUnixConnPair(t)
	defer client.Close()
	defer server.Close()

	realCreds, err := peerCredentialsFromConn(server)
	require.NoError(t, err)

	// An empty RoleMapping matches no UID or GID, including this test
	// process's real one.
	roleMapping := &RoleMapping{}
	gate, rbac := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(roleMapping, gate, testLogger())

	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, realCreds)

	ran := false
	_, err = interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_ListCertificates_FullMethodName},
		func(ctx context.Context, _ interface{}) (interface{}, error) {
			ran = true
			return "ok", nil
		})

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, ran)
	assert.Equal(t, []string{"certs:list"}, rbac.requested,
		"an unmapped identity reaches the authorizer with no roles and is denied there, not admitted implicitly")
}
