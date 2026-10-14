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
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/peercred"
)

// privateSocketDir returns a fresh t.TempDir() explicitly chmod'd to 0700.
// t.TempDir()'s per-call leaf directory is created with mode 0o777 (see
// testing.(*common).makeTempDir), so its effective mode after the process
// umask is applied can be group- or world-writable in environments whose
// umask is not the conservative 022 default (e.g. umask 002 for
// group-collaborative accounts) -- exactly the shape validateSocketDir
// refuses. Tests that only care about socket behaviour, not directory
// security, use this instead of a bare t.TempDir() so they exercise the
// same private-directory shape a real daemon's runtime directory has.
func privateSocketDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0700))
	return dir
}

// TestPeerCredentialPolicy_Allowed verifies the accept-time policy admits
// the daemon's own uid, root, and configured allowlist entries, and refuses
// everything else.
func TestPeerCredentialPolicy_Allowed(t *testing.T) {
	daemonUID := uint32(os.Geteuid())

	tests := []struct {
		name    string
		policy  *PeerCredentialPolicy
		creds   *peercred.Credentials
		allowed bool
	}{
		{
			name:    "nil credentials refused",
			policy:  NewPeerCredentialPolicy(nil, nil),
			creds:   nil,
			allowed: false,
		},
		{
			name:    "daemon uid admitted",
			policy:  NewPeerCredentialPolicy(nil, nil),
			creds:   &peercred.Credentials{UID: daemonUID, GID: 4242},
			allowed: true,
		},
		{
			name:    "root admitted",
			policy:  NewPeerCredentialPolicy(nil, nil),
			creds:   &peercred.Credentials{UID: 0, GID: 0},
			allowed: true,
		},
		{
			name:    "unrelated uid refused",
			policy:  NewPeerCredentialPolicy(nil, nil),
			creds:   &peercred.Credentials{UID: 65534, GID: 65534},
			allowed: false,
		},
		{
			name:    "allowlisted uid admitted",
			policy:  NewPeerCredentialPolicy([]uint32{4242}, nil),
			creds:   &peercred.Credentials{UID: 4242, GID: 4242},
			allowed: true,
		},
		{
			name:    "allowlisted gid admitted",
			policy:  NewPeerCredentialPolicy(nil, []uint32{4242}),
			creds:   &peercred.Credentials{UID: 65534, GID: 4242},
			allowed: true,
		},
		{
			name:    "uid not in either allowlist refused",
			policy:  NewPeerCredentialPolicy([]uint32{4242}, []uint32{4343}),
			creds:   &peercred.Credentials{UID: 65534, GID: 65534},
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.allowed, tt.policy.Allowed(tt.creds))
		})
	}
}

// TestGRPCServer_PeerCredential_SameUIDAccepted verifies a connection from
// this test process's own uid -- the default case for every existing client
// in this test suite -- is accepted by the accept-time peer-credential
// check.
func TestGRPCServer_PeerCredential_SameUIDAccepted(t *testing.T) {
	socketPath := filepath.Join(privateSocketDir(t), "peercred-same-uid.sock")

	server, err := NewGRPCServer(&GRPCConfig{SocketPath: socketPath})
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()
	waitForGRPCServerReady(t, server, socketPath)
	defer func() { _ = server.Stop(context.Background()) }()

	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	client := pb.NewKeystoreServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Health(ctx, &pb.HealthRequest{})
	require.NoError(t, err, "a same-uid peer must be accepted by the peer-credential check")
	assert.Equal(t, "healthy", resp.Status)
}

// TestValidateSocketDir_RefusesGroupWritableDir verifies a preexisting
// socket directory writable by group or other is refused before Start ever
// binds a listener inside it.
func TestValidateSocketDir_RefusesGroupWritableDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0775))

	err := validateSocketDir(dir)
	require.Error(t, err)
	var insecureErr *InsecureSocketDirError
	require.ErrorAs(t, err, &insecureErr)
	assert.Equal(t, dir, insecureErr.Path)
}

// TestValidateSocketDir_AcceptsPrivateDir verifies a preexisting socket
// directory that is privately owned and not group/world writable passes.
func TestValidateSocketDir_AcceptsPrivateDir(t *testing.T) {
	dir := privateSocketDir(t)
	assert.NoError(t, validateSocketDir(dir))
}

// TestValidateSocketDir_MissingDirOK verifies a socket directory that does
// not exist yet is not treated as insecure: Start creates it fresh.
func TestValidateSocketDir_MissingDirOK(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist-yet")
	assert.NoError(t, validateSocketDir(dir))
}

// TestPeerCredentialTransport_TypedNilConnRefused is the regression test for
// a typed-nil *net.UnixConn inside a net.Conn: it passes the handshake's
// type assertion, and used to panic in peercred.FromConn instead of
// refusing the connection with the typed extraction error.
func TestPeerCredentialTransport_TypedNilConnRefused(t *testing.T) {
	transport := newPeerCredentialTransport(&PeerCredentialPolicy{})
	var unixConn *net.UnixConn

	conn, authInfo, err := transport.ServerHandshake(unixConn)
	assert.Nil(t, conn)
	assert.Nil(t, authInfo)
	var extractionErr peercred.ExtractionFailedError
	assert.ErrorAs(t, err, &extractionErr)
}

// TestGRPCServer_Start_RefusesGroupWritableSocketDir is the end-to-end
// regression test for go-xkms#1299: Start refuses to bind a listener inside
// a preexisting socket directory that is writable by group or other.
func TestGRPCServer_Start_RefusesGroupWritableSocketDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0775))
	socketPath := filepath.Join(dir, "insecure.sock")

	server, err := NewGRPCServer(&GRPCConfig{SocketPath: socketPath})
	require.NoError(t, err)

	err = server.Start()
	require.Error(t, err)
	var insecureErr *InsecureSocketDirError
	assert.ErrorAs(t, err, &insecureErr)
}
