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

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"

	grpcinternal "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
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

	// The accept loop is live at this point. Assert on the keys the server
	// published, not on locals: ownership is the thing under test.
	srv.mu.RLock()
	noiseKey := srv.noiseBootstrapKey
	p256Key := srv.p256BootstrapKey
	published := srv.noiseBootstrapServer
	srv.mu.RUnlock()

	// The listener starts in every build. Under -tags fips it offers only the
	// approved suite, and before go-xkms#269 it was never published there at
	// all, because loading its only key failed.
	require.NotNil(t, published, "the bootstrap server was never published")

	// Which key is published follows the build, so the ownership rule is
	// checked against whichever suite this binary can actually run.
	noiseRunnable := bootstrap.EnsureSuiteAvailable(bootstrap.SuiteNoiseNK) == nil
	require.Equal(t, noiseRunnable, noiseKey != nil,
		"a Noise key must be published exactly when this build can run Noise")
	require.NotNil(t, p256Key, "the approved suite is available in every build")

	if noiseRunnable {
		require.NotEmpty(t, noiseKey.Private,
			"the Noise static key was destroyed while the accept loop was still running")
	}
	// NewResponder refuses a destroyed key, which is the only exported way to
	// observe the P-256 private half: PublicBytes deliberately survives Destroy
	// so a destroyed key can still name its identity.
	_, err = p256proto.NewResponder(p256Key)
	require.NoError(t, err,
		"the P-256 static key was destroyed while the accept loop was still running")

	require.NoError(t, srv.Shutdown())

	// And Shutdown is where they get released, once Stop has drained.
	if noiseRunnable {
		require.Empty(t, noiseKey.Private,
			"Shutdown left the Noise static key resident after a clean stop")
	}
	_, err = p256proto.NewResponder(p256Key)
	require.Error(t, err,
		"Shutdown left the P-256 static key usable after a clean stop")

	srv.mu.RLock()
	defer srv.mu.RUnlock()
	require.Nil(t, srv.noiseBootstrapKey, "Shutdown left the Noise key reachable")
	require.Nil(t, srv.p256BootstrapKey, "Shutdown left the P-256 key reachable")
	require.Nil(t, srv.noiseBootstrapServer, "Shutdown left the server reachable")
}
