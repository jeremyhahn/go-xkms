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

//go:build (linux || darwin || freebsd || openbsd || netbsd) && !integration

package server

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

func TestGetPeerCredentials_NotInContext(t *testing.T) {
	ctx := context.Background()
	creds := GetPeerCredentials(ctx)
	assert.Nil(t, creds, "GetPeerCredentials should return nil when not in context")
}

func TestGetPeerCredentials_InContext(t *testing.T) {
	expected := &PeerCredentials{
		PID: 12345,
		UID: 1000,
		GID: 1000,
	}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, expected)

	creds := GetPeerCredentials(ctx)

	require.NotNil(t, creds)
	assert.Equal(t, int32(12345), creds.PID)
	assert.Equal(t, uint32(1000), creds.UID)
	assert.Equal(t, uint32(1000), creds.GID)
}

func TestGetPeerCredentials_WrongType(t *testing.T) {
	// Wrong type in context should return nil
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, "not PeerCredentials")
	creds := GetPeerCredentials(ctx)
	assert.Nil(t, creds, "GetPeerCredentials should return nil for wrong type")
}

func TestUnaryPeerCredentialsInterceptor_NoGRPCPeer(t *testing.T) {
	// Context without gRPC peer information
	interceptor := UnaryPeerCredentialsInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		// Should not have peer credentials
		creds := GetPeerCredentials(ctx)
		assert.Nil(t, creds, "No peer credentials expected for non-gRPC context")
		return "success", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	resp, err := interceptor(context.Background(), "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

func TestUnaryPeerCredentialsInterceptor_TCPConnection(t *testing.T) {
	// TCP connection should not have peer credentials
	interceptor := UnaryPeerCredentialsInterceptor()

	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8080,
	}
	peerInfo := &peer.Peer{
		Addr: tcpAddr,
	}
	ctx := peer.NewContext(context.Background(), peerInfo)

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "success", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)

	// TCP connections should not have peer credentials
	creds := GetPeerCredentials(capturedCtx)
	assert.Nil(t, creds, "TCP connections should not have peer credentials")
}

func TestUnaryPeerCredentialsInterceptor_UnixSocket_NoAuthInfo(t *testing.T) {
	// Unix socket without AuthInfo should not inject credentials
	interceptor := UnaryPeerCredentialsInterceptor()

	unixAddr := &net.UnixAddr{
		Name: "/run/test.sock",
		Net:  "unix",
	}
	peerInfo := &peer.Peer{
		Addr: unixAddr,
	}
	ctx := peer.NewContext(context.Background(), peerInfo)

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "success", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)

	// Without AuthInfo, no credentials should be extracted
	creds := GetPeerCredentials(capturedCtx)
	assert.Nil(t, creds, "Unix socket without AuthInfo should not have credentials")
}

func TestUnaryPeerCredentialsInterceptor_UnixSocket_WithAuthInfo(t *testing.T) {
	// Unix socket with PeerCredentialsAuthInfo should inject credentials
	interceptor := UnaryPeerCredentialsInterceptor()

	unixAddr := &net.UnixAddr{
		Name: "/run/test.sock",
		Net:  "unix",
	}
	expectedCreds := &PeerCredentials{
		PID: 9999,
		UID: 1001,
		GID: 1001,
	}
	peerInfo := &peer.Peer{
		Addr:     unixAddr,
		AuthInfo: &PeerCredentialsAuthInfo{Credentials: expectedCreds},
	}
	ctx := peer.NewContext(context.Background(), peerInfo)

	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "success", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)

	// Credentials should be extracted from AuthInfo
	creds := GetPeerCredentials(capturedCtx)
	require.NotNil(t, creds)
	assert.Equal(t, int32(9999), creds.PID)
	assert.Equal(t, uint32(1001), creds.UID)
	assert.Equal(t, uint32(1001), creds.GID)
}

func TestUnaryPeerCredentialsInterceptor_HandlerError(t *testing.T) {
	// Interceptor should propagate handler errors
	interceptor := UnaryPeerCredentialsInterceptor()

	expectedErr := assert.AnError
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, expectedErr
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	resp, err := interceptor(context.Background(), "request", info, handler)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, resp)
}

func TestPeerCredentialsAuthInfo_AuthType(t *testing.T) {
	authInfo := &PeerCredentialsAuthInfo{
		Credentials: &PeerCredentials{
			PID: 1234,
			UID: 1000,
			GID: 1000,
		},
	}

	assert.Equal(t, "peer_credentials", authInfo.AuthType())
}

func TestPeerCredentialsAuthInfo_NilCredentials(t *testing.T) {
	authInfo := &PeerCredentialsAuthInfo{
		Credentials: nil,
	}

	assert.Equal(t, "peer_credentials", authInfo.AuthType())
	assert.Nil(t, authInfo.Credentials)
}

func TestPeerCredentials_Fields(t *testing.T) {
	creds := &PeerCredentials{
		PID: 12345,
		UID: 1000,
		GID: 2000,
	}

	assert.Equal(t, int32(12345), creds.PID)
	assert.Equal(t, uint32(1000), creds.UID)
	assert.Equal(t, uint32(2000), creds.GID)
}

func TestExtractPeerCredentials_NoPeer(t *testing.T) {
	ctx := context.Background()
	creds, err := extractPeerCredentials(ctx)

	assert.Error(t, err)
	assert.Nil(t, creds)
	_, ok := err.(ErrNoPeerInfo)
	assert.True(t, ok, "Error should be ErrNoPeerInfo")
}

func TestExtractPeerCredentials_TCPAddr(t *testing.T) {
	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 443,
	}
	peerInfo := &peer.Peer{Addr: tcpAddr}
	ctx := peer.NewContext(context.Background(), peerInfo)

	creds, err := extractPeerCredentials(ctx)

	// TCP returns nil without error (not a Unix socket)
	assert.NoError(t, err)
	assert.Nil(t, creds)
}

func TestExtractPeerCredentials_UnixAddr_NoAuthInfo(t *testing.T) {
	unixAddr := &net.UnixAddr{
		Name: "/var/run/app.sock",
		Net:  "unix",
	}
	peerInfo := &peer.Peer{Addr: unixAddr}
	ctx := peer.NewContext(context.Background(), peerInfo)

	creds, err := extractPeerCredentials(ctx)

	// Unix socket without AuthInfo returns nil
	assert.NoError(t, err)
	assert.Nil(t, creds)
}

func TestExtractPeerCredentials_UnixAddr_WrongAuthInfoType(t *testing.T) {
	unixAddr := &net.UnixAddr{
		Name: "/var/run/app.sock",
		Net:  "unix",
	}
	// Use a different AuthInfo type
	peerInfo := &peer.Peer{
		Addr:     unixAddr,
		AuthInfo: &mockAuthInfo{},
	}
	ctx := peer.NewContext(context.Background(), peerInfo)

	creds, err := extractPeerCredentials(ctx)

	// Wrong AuthInfo type returns nil
	assert.NoError(t, err)
	assert.Nil(t, creds)
}

func TestExtractPeerCredentials_UnixAddr_WithPeerCredentialsAuthInfo(t *testing.T) {
	unixAddr := &net.UnixAddr{
		Name: "/var/run/app.sock",
		Net:  "unix",
	}
	expectedCreds := &PeerCredentials{
		PID: 5678,
		UID: 500,
		GID: 500,
	}
	peerInfo := &peer.Peer{
		Addr:     unixAddr,
		AuthInfo: &PeerCredentialsAuthInfo{Credentials: expectedCreds},
	}
	ctx := peer.NewContext(context.Background(), peerInfo)

	creds, err := extractPeerCredentials(ctx)

	assert.NoError(t, err)
	require.NotNil(t, creds)
	assert.Equal(t, expectedCreds.PID, creds.PID)
	assert.Equal(t, expectedCreds.UID, creds.UID)
	assert.Equal(t, expectedCreds.GID, creds.GID)
}

// mockAuthInfo is a mock AuthInfo that is not PeerCredentialsAuthInfo
type mockAuthInfo struct{}

func (m *mockAuthInfo) AuthType() string {
	return "mock"
}

func TestPeerCredentialsKey_Uniqueness(t *testing.T) {
	// Verify that the key type is unique
	key1 := peerCredentialsKey{}
	key2 := peerCredentialsKey{}

	// Same type should be equal
	assert.Equal(t, key1, key2)

	// Context with the key should be retrievable
	creds := &PeerCredentials{PID: 1, UID: 2, GID: 3}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	retrieved := ctx.Value(peerCredentialsKey{})
	assert.NotNil(t, retrieved)
	assert.Equal(t, creds, retrieved)
}

func TestUnaryPeerCredentialsInterceptor_ContextPropagation(t *testing.T) {
	// Verify that the original context is preserved when credentials are added
	interceptor := UnaryPeerCredentialsInterceptor()

	type customKey struct{}
	originalCtx := context.WithValue(context.Background(), customKey{}, "original-value")

	unixAddr := &net.UnixAddr{Name: "/test.sock", Net: "unix"}
	expectedCreds := &PeerCredentials{PID: 100, UID: 200, GID: 300}
	peerInfo := &peer.Peer{
		Addr:     unixAddr,
		AuthInfo: &PeerCredentialsAuthInfo{Credentials: expectedCreds},
	}
	ctx := peer.NewContext(originalCtx, peerInfo)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		// Original context value should still be accessible
		val := ctx.Value(customKey{})
		assert.Equal(t, "original-value", val, "Original context value should be preserved")

		// New peer credentials should be accessible
		creds := GetPeerCredentials(ctx)
		assert.NotNil(t, creds)
		assert.Equal(t, expectedCreds.UID, creds.UID)

		return "success", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	resp, err := interceptor(ctx, "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

func TestUnaryPeerCredentialsInterceptor_MultipleInvocations(t *testing.T) {
	// Each invocation should get fresh context handling
	interceptor := UnaryPeerCredentialsInterceptor()

	unixAddr := &net.UnixAddr{Name: "/test.sock", Net: "unix"}

	for i := 0; i < 3; i++ {
		expectedCreds := &PeerCredentials{
			PID: int32(i * 100),
			UID: uint32(i * 10),
			GID: uint32(i * 10),
		}
		peerInfo := &peer.Peer{
			Addr:     unixAddr,
			AuthInfo: &PeerCredentialsAuthInfo{Credentials: expectedCreds},
		}
		ctx := peer.NewContext(context.Background(), peerInfo)

		iteration := i
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			creds := GetPeerCredentials(ctx)
			require.NotNil(t, creds)
			assert.Equal(t, int32(iteration*100), creds.PID)
			assert.Equal(t, uint32(iteration*10), creds.UID)
			return "success", nil
		}

		info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
		resp, err := interceptor(ctx, "request", info, handler)

		assert.NoError(t, err)
		assert.Equal(t, "success", resp)
	}
}

func TestErrorTypes(t *testing.T) {
	t.Run("ErrNoPeerInfo", func(t *testing.T) {
		err := ErrNoPeerInfo{}
		assert.Equal(t, "no peer information in context", err.Error())
	})

	t.Run("ErrNotUnixConnection", func(t *testing.T) {
		err := ErrNotUnixConnection{}
		assert.Equal(t, "connection is not a Unix socket", err.Error())
	})

	t.Run("ErrPeerCredentialsFailed", func(t *testing.T) {
		err := ErrPeerCredentialsFailed{Reason: "test reason"}
		assert.Equal(t, "failed to get peer credentials: test reason", err.Error())
	})

	t.Run("ErrPermissionDenied", func(t *testing.T) {
		err := ErrPermissionDenied{
			Subject:  "uid:1000",
			Method:   "/test/Method",
			Resource: "certs",
			Action:   "revoke",
		}
		expected := "permission denied for uid:1000: method /test/Method requires certs:revoke"
		assert.Equal(t, expected, err.Error())
	})
}
