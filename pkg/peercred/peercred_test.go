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

//go:build linux || darwin

package peercred

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realUnixConnPair returns a connected pair of *net.UnixConn backed by a
// real kernel Unix domain socket, so the kernel peer-credential mechanism
// reflects this test process's own genuine credentials.
func realUnixConnPair(t *testing.T) (client, server *net.UnixConn) {
	t.Helper()

	conns, err := net.ListenUnix("unix", &net.UnixAddr{Name: "@peercred-test", Net: "unix"})
	if err != nil {
		// Fall back to a named socket in a temp directory: not every
		// platform in this build set supports the abstract namespace
		// "@name" address (Linux does; Darwin does not).
		sockPath := t.TempDir() + "/peercred-test.sock"
		conns, err = net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
		require.NoError(t, err)
	}
	t.Cleanup(func() { _ = conns.Close() })

	acceptedCh := make(chan *net.UnixConn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, acceptErr := conns.AcceptUnix()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		acceptedCh <- c
	}()

	clientConn, err := net.DialUnix("unix", nil, conns.Addr().(*net.UnixAddr))
	require.NoError(t, err)

	select {
	case c := <-acceptedCh:
		return clientConn, c
	case err := <-errCh:
		t.Fatalf("accept failed: %v", err)
	}
	return nil, nil
}

// TestFromConn_MatchesRunningProcess verifies the kernel peer-credential
// extraction reports this test process's own real PID, UID, and GID -- not
// a value computed or assumed by this package.
func TestFromConn_MatchesRunningProcess(t *testing.T) {
	client, server := realUnixConnPair(t)
	defer client.Close()
	defer server.Close()

	creds, err := FromConn(server)
	require.NoError(t, err)
	require.NotNil(t, creds)

	assert.Equal(t, uint32(os.Getuid()), creds.UID)
	assert.Equal(t, uint32(os.Getgid()), creds.GID)
	assert.Equal(t, int32(os.Getpid()), creds.PID)
}

// TestCheckSupport_SupportedPlatform verifies CheckSupport succeeds on
// Linux and Darwin, the platforms this package implements kernel
// peer-credential extraction for.
func TestCheckSupport_SupportedPlatform(t *testing.T) {
	assert.NoError(t, CheckSupport())
}

// TestFromConn_RefusesNonUnixConnCaller documents that FromConn's contract
// is scoped to *net.UnixConn: the compiler enforces this at the call site,
// so there is no runtime type-assertion failure to exercise here. This test
// instead pins that a nil peer produces the typed extraction error rather
// than a panic.
func TestFromConn_ClosedConnReturnsExtractionFailedError(t *testing.T) {
	client, server := realUnixConnPair(t)
	require.NoError(t, client.Close())
	require.NoError(t, server.Close())

	_, err := FromConn(server)
	require.Error(t, err)
	var extractionErr ExtractionFailedError
	assert.ErrorAs(t, err, &extractionErr)
}
