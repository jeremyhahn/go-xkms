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

//go:build fips

// bootstrap_key_report_fips_test.go is the FIPS counterpart of
// bootstrap_key_report_nofips_test.go: with Noise_NK compiled out, the
// listener must offer the approved P-256 suite alone, report only its key,
// complete a real handshake pinned to that key, and withdraw the report on
// Shutdown.
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

// TestStartNoiseBootstrap_FIPSPublishesP256KeyOnly drives a real
// startNoiseBootstrap/Shutdown cycle in a FIPS build and checks that the
// report carries the P-256 key and no Noise_NK key.
func TestStartNoiseBootstrap_FIPSPublishesP256KeyOnly(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Protocols.Noise = false // call startNoiseBootstrap manually
	cfg.Server.NoisePort = 0    // bind on any available port
	cfg.Server.Host = "127.0.0.1"

	srv, err := newServerWithCleanup(t, cfg)
	require.NoError(t, err)
	require.NotNil(t, srv.xkmsService, "server construction must wire the XKMSService singleton")

	srv.grpcCABundler = &mockCABundlerForNoise{cert: selfSignedCert(t)}

	ctx := context.Background()

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
	noiseKey := srv.noiseBootstrapKey
	p256Key := srv.p256BootstrapKey
	listenerAddr := srv.noiseBootstrapServer.Addr().String()
	srv.mu.Unlock()
	require.Nil(t, noiseKey, "a FIPS build must not offer Noise_NK")
	require.NotNil(t, p256Key, "a FIPS build must offer the approved P-256 suite")

	resp, err := srv.xkmsService.BootstrapListenerKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, resp.NoisePublicKey, "no Noise_NK key may be reported in a FIPS build")
	assert.Equal(t, hex.EncodeToString(p256Key.PublicBytes()), resp.P256PublicKey)

	bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
		Mode: bootstrap.ModeNoise,
		Noise: &bootstrap.NoiseConfig{
			ServerAddr:          listenerAddr,
			ServerP256StaticKey: resp.P256PublicKey,
		},
	})
	require.NoError(t, err, "the reported P-256 key must pin a working approved-suite handshake")
	assert.NotNil(t, bundle)

	require.NoError(t, srv.Shutdown())

	_, err = srv.xkmsService.BootstrapListenerKeys(ctx)
	assert.ErrorIs(t, err, xkms.ErrBootstrapListenerNotEnabled)
}
