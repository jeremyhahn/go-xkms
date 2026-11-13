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
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplyHardenedTimeouts proves the helper sets every one of the four
// timeouts, not just the ReadHeaderTimeout the metrics server used to carry
// alone (go-xkms#1262).
func TestApplyHardenedTimeouts(t *testing.T) {
	srv := &http.Server{}
	ApplyHardenedTimeouts(srv)

	assert.Equal(t, HardenedReadHeaderTimeout, srv.ReadHeaderTimeout)
	assert.Equal(t, HardenedReadTimeout, srv.ReadTimeout)
	assert.Equal(t, HardenedWriteTimeout, srv.WriteTimeout)
	assert.Equal(t, HardenedIdleTimeout, srv.IdleTimeout)
}

// TestServer_StartMetrics_HasHardenedTimeouts proves the metrics server
// startMetrics builds carries the full hardened timeout set, not only
// ReadHeaderTimeout: an unbounded ReadTimeout, WriteTimeout or IdleTimeout
// left a slow-body or idle-connection Slowloris variant unmitigated even
// though the header-only variant was covered (go-xkms#1262).
func TestServer_StartMetrics_HasHardenedTimeouts(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "/metrics"

	srv, err := newServerWithCleanup(t, cfg)
	require.NoError(t, err)
	srv.SetMetricsListener(newTestMetricsListener(t))

	require.NoError(t, srv.Start())
	defer func() {
		require.NoError(t, srv.Shutdown())
	}()

	// Wait for startMetrics's goroutine to set the metrics server field
	// instead of sleeping a fixed duration.
	require.Eventually(t, func() bool {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		return srv.metricsServer != nil
	}, 10*time.Second, 10*time.Millisecond, "metrics server was not set")

	srv.mu.RLock()
	metricsServer := srv.metricsServer
	srv.mu.RUnlock()

	assert.Equal(t, HardenedReadHeaderTimeout, metricsServer.ReadHeaderTimeout)
	assert.Equal(t, HardenedReadTimeout, metricsServer.ReadTimeout)
	assert.Equal(t, HardenedWriteTimeout, metricsServer.WriteTimeout)
	assert.Equal(t, HardenedIdleTimeout, metricsServer.IdleTimeout)
}
