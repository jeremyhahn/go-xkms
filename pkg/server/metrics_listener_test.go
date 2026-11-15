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
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestServer_SetMetricsListener_ServesOnInjectedListener proves the
// go-xkms#1142 seam end-to-end: a listener injected via SetMetricsListener
// is the one startMetrics actually serves, in preference to binding the
// configured Metrics.Port, and MetricsAddr reports exactly that listener's
// address afterward -- so a caller (a test, in particular) never has to
// name a literal port to reach it.
func TestServer_SetMetricsListener_ServesOnInjectedListener(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "/metrics"

	srv, err := newServerWithCleanup(t, cfg)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	require.Nil(t, srv.MetricsAddr(), "MetricsAddr before injection must be nil: there is nothing to report yet")

	srv.SetMetricsListener(ln)
	require.NoError(t, srv.Start())
	defer func() { _ = srv.Shutdown() }()

	addr := srv.MetricsAddr()
	require.NotNil(t, addr, "MetricsAddr must report the injected listener's address once Start has run")
	assert.Equal(t, ln.Addr().String(), addr.String())

	resp, err := http.Get("http://" + addr.String() + "/metrics")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, body)
}

// TestServer_StartMetrics_WithoutInjectedListener_BindsConfiguredPort proves
// the SetMetricsListener seam is strictly additive: a server that never
// calls it keeps startMetrics's original behavior of binding the port named
// in Metrics.Port, and MetricsAddr stays nil throughout since there is no
// listener to report.
//
// Metrics.Port itself has no read-back seam -- closing that gap for
// listener-consuming callers is exactly what SetMetricsListener is for --
// so this test reserves a loopback port, releases it, and configures
// Metrics.Port with the freed number, the same pattern already used
// elsewhere in this repo (cmd/xkmsd, the enroll-01 challenge tests) for the
// "no listener injection available" case. That is not a gap this test
// introduces: it is exercising the fallback bind-by-port path itself, which
// by definition has no listener for the test to hold onto instead.
func TestServer_StartMetrics_WithoutInjectedListener_BindsConfiguredPort(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := reserved.Addr().(*net.TCPAddr).Port
	require.NoError(t, reserved.Close())

	cfg := createMinimalConfig(t)
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "/metrics"
	cfg.Metrics.Port = port

	srv, err := newServerWithCleanup(t, cfg)
	require.NoError(t, err)
	require.Nil(t, srv.MetricsAddr(), "no listener was injected, so there is nothing to report")

	require.NoError(t, srv.Start())
	defer func() { _ = srv.Shutdown() }()

	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	require.Eventually(t, func() bool {
		resp, err := http.Get(url)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond, "metrics server did not bind the configured port")

	assert.Nil(t, srv.MetricsAddr(), "MetricsAddr stays nil for the bind-by-port path even after Start")
}
