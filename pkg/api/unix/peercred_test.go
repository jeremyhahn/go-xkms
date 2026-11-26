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
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.ErrorAs(t, err, &insecureErr)
	assert.Equal(t, dir, insecureErr.Path)
}
