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

//go:build !fips

// bootstrap_key_report_nofips_test.go proves startNoiseBootstrap publishes the
// listener's public keys into the XKMSService (go-xkms#632), that the
// reported hex round-trips through the client's own NoiseConfig validation
// and completes a real handshake, and that Shutdown withdraws the report
// again. It needs Noise_NK, so it builds without the fips tag only;
// bootstrap_key_report_fips_test.go is its FIPS counterpart.
package server

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestStartNoiseBootstrap_PublishesAndWithdrawsListenerKeys drives a real
// startNoiseBootstrap/Shutdown cycle and checks BootstrapListenerKeys through
// the XKMSService the whole time: not enabled before Start, published with
// the exact hex the listener's live key holds once Start succeeds, and not
// enabled again once Shutdown has claimed the listener.
func TestStartNoiseBootstrap_PublishesAndWithdrawsListenerKeys(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Noise = false // call startNoiseBootstrap manually
	cfg.Server.NoisePort = 0    // bind on any available port
	cfg.Server.Host = "127.0.0.1"

	srv, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv.xkmsService, "server construction must wire the XKMSService singleton")

	srv.grpcCABundler = &mockCABundlerForNoise{cert: selfSignedCert(t)}

	ctx := context.Background()

	// Before the listener starts, the service must report "not enabled".
	_, err = srv.xkmsService.BootstrapListenerKeys(ctx)
	require.ErrorIs(t, err, xkms.ErrBootstrapListenerNotEnabled)

	srv.wg.Add(1)
	done := make(chan struct{})
	go func() {
		srv.startNoiseBootstrap()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startNoiseBootstrap did not return in time")
	}

	srv.mu.Lock()
	liveKey := srv.noiseBootstrapKey
	listenerAddr := srv.noiseBootstrapServer.Addr().String()
	srv.mu.Unlock()
	require.NotNil(t, liveKey, "Noise_NK must be offered in a non-FIPS test build")

	resp, err := srv.xkmsService.BootstrapListenerKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(liveKey.Public), resp.NoisePublicKey)

	// The reported hex must be exactly what a first-contact client pastes
	// into NoiseConfig.ServerStaticKey: pin the discovered key and complete
	// a real handshake against the running listener, the same round trip
	// test/integration/bootstrap performs against a real server.
	bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
		Mode: bootstrap.ModeNoise,
		Noise: &bootstrap.NoiseConfig{
			ServerAddr:      listenerAddr,
			ServerStaticKey: resp.NoisePublicKey,
		},
	})
	require.NoError(t, err, "the reported public key must decode and pin a working Noise_NK handshake")
	assert.NotNil(t, bundle)

	// Shutdown claims and destroys the listener's keys; the report must be
	// withdrawn in the same act, not left stale.
	require.NoError(t, srv.Shutdown())

	_, err = srv.xkmsService.BootstrapListenerKeys(ctx)
	assert.ErrorIs(t, err, xkms.ErrBootstrapListenerNotEnabled)
}
