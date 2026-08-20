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

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	grpcinternal "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestNoiseBootstrapKeySurvivesStart is the regression test for a
// use-after-free that shipped into this branch on a false premise.
//
// startNoiseBootstrap destroyed the protected static key on the way out,
// documented as safe because "Start blocks until the server has stopped".
// noiseboot.Server.Start does not block: it binds the listener, launches its
// accept loop in a goroutine, and returns nil. So the key was freed while the
// published server and every future handshake still aliased its DHKey, and
// any client connecting afterwards would read freed protected pages.
//
// The tell was in this package's own tests all along — the existing
// TestStartNoiseBootstrap_WithBundler comments that startNoiseBootstrap
// "should return after noiseboot.NewServer.Start() returns (non-blocking
// listen+accept goroutine)". Nobody connected that to the destroy.
func TestNoiseBootstrapKeySurvivesStart(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	grpcinternal.SetCABundler(&mockCABundlerForNoise{cert: selfSignedCert(t)})
	defer grpcinternal.SetCABundler(nil)

	cfg := createMinimalConfig(t)
	cfg.Protocols.Noise = false // drive startNoiseBootstrap directly
	cfg.Server.NoisePort = 0
	cfg.Server.Host = "127.0.0.1"

	srv, err := New(cfg)
	require.NoError(t, err)

	srv.wg.Add(1)
	done := make(chan struct{})
	go func() {
		srv.startNoiseBootstrap()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startNoiseBootstrap did not return")
	}

	// The accept loop is live at this point. Assert on the key the server
	// published, not on a local: ownership is the thing under test.
	srv.mu.RLock()
	key := srv.noiseBootstrapKey
	published := srv.noiseBootstrapServer
	srv.mu.RUnlock()

	require.NotNil(t, published, "the bootstrap server was never published")
	require.NotNil(t, key, "the server published no static key to own")
	require.NotEmpty(t, key.Private,
		"the static key was destroyed while the accept loop was still running")

	require.NoError(t, srv.Shutdown())

	// And Shutdown is where it gets released, once Stop has drained.
	require.Empty(t, key.Private,
		"Shutdown left the static key resident after a clean stop")

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	require.Nil(t, srv.noiseBootstrapKey, "Shutdown left the key reachable")
	require.Nil(t, srv.noiseBootstrapServer, "Shutdown left the server reachable")
}
