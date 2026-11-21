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

package cmd

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startStalledXKMSd listens on a unix socket, accepts every connection and
// never answers it: a server whose connect stalls. It returns its URL.
func startStalledXKMSd(t *testing.T) string {
	t.Helper()
	socketPath := filepath.Join(privateTempDir(t), "stalled.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	return "unix://" + socketPath
}

// TestTrustBootstrapXKMSd_StalledConnectEndsAtTheDeadline: the client
// connect runs under the bootstrap --timeout context, so a stalled server
// ends the bootstrap at its deadline, not after the 30 s connect default.
func TestTrustBootstrapXKMSd_StalledConnectEndsAtTheDeadline(t *testing.T) {
	isolateXKMSdEndpoint(t)
	xkmsdURL = startStalledXKMSd(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var buf bytes.Buffer
	start := time.Now()
	err := runTrustBootstrapXKMSd(ctx, newTrustBootstrapTestCommand(t, &buf),
		newTestCertificatePEM(t, "stalled bootstrap CA"), "stalled.example")
	elapsed := time.Since(start)

	require.Error(t, err, "a stalled server never answers the bootstrap")
	require.Less(t, elapsed, 5*time.Second, "the connect outlived the bootstrap deadline")
}
