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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPeerCredentialTransport_Properties proves the transport describes
// itself as SO_PEERCRED and clones share its policy.
func TestPeerCredentialTransport_Properties(t *testing.T) {
	policy := NewPeerCredentialPolicy(nil, nil)
	creds := newPeerCredentialTransport(policy)

	assert.Equal(t, "so_peercred", creds.Info().SecurityProtocol)

	clone, ok := creds.Clone().(*peerCredentialTransport)
	require.True(t, ok)
	assert.NotSame(t, creds, clone)
	assert.Same(t, policy, clone.policy)

	assert.Equal(t, "peer_credentials", peerCredentialAuthInfo{}.AuthType())
}

// TestPeerCredentialTransport_ClientHandshakeRefused proves the server-only
// transport never establishes a client-side identity.
func TestPeerCredentialTransport_ClientHandshakeRefused(t *testing.T) {
	creds := newPeerCredentialTransport(NewPeerCredentialPolicy(nil, nil))

	conn, info, err := creds.ClientHandshake(context.Background(), "unix", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not support client-side handshakes")
	assert.Nil(t, conn)
	assert.Nil(t, info)
}

// TestPeerCredentialTransport_ServerHandshakeUnreadableCredentials proves a
// Unix connection whose peer credentials cannot be read is refused.
func TestPeerCredentialTransport_ServerHandshakeUnreadableCredentials(t *testing.T) {
	socketPath := filepath.Join(privateSocketDir(t), "closed.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	conn, err := net.Dial("unix", socketPath)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	creds := newPeerCredentialTransport(NewPeerCredentialPolicy(nil, nil))
	got, info, err := creds.ServerHandshake(conn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read peer credentials")
	assert.Nil(t, got)
	assert.Nil(t, info)
}

// TestValidateSocketDir_RefusesSymlink proves a socket directory reached
// through a symlink is refused: the link could be repointed at a directory
// another user controls.
func TestValidateSocketDir_RefusesSymlink(t *testing.T) {
	target := privateSocketDir(t)
	link := filepath.Join(privateSocketDir(t), "link")
	require.NoError(t, os.Symlink(target, link))

	err := validateSocketDir(link)
	var insecureErr *InsecureSocketDirError
	require.ErrorAs(t, err, &insecureErr)
	assert.Equal(t, link, insecureErr.Path)
	assert.Equal(t, "is a symlink", insecureErr.Reason)
	assert.Equal(t, `insecure socket directory "`+link+`": is a symlink`, err.Error())
}

// TestGRPCServer_Start_ListenFailure proves Start reports a socket path the
// kernel cannot bind instead of serving nothing.
func TestGRPCServer_Start_ListenFailure(t *testing.T) {
	// sun_path holds at most 108 bytes on Linux.
	socketPath := filepath.Join(privateSocketDir(t), strings.Repeat("s", 120)+".sock")
	server, err := NewGRPCServer(&GRPCConfig{SocketPath: socketPath})
	require.NoError(t, err)

	err = server.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create Unix socket listener")
}
