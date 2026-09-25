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

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestServer_MetricsGatherer_IncludesRegisteredGatherer exercises exactly
// what startMetrics wires into /metrics: promhttp.HandlerFor(serverGatherer{s},
// ...). It stands a private registry in for the real
// pkg/acme/server/metrics.Registry (the ACME subsystem's collectors live
// there, never in prometheus.DefaultRegisterer, so they are otherwise
// invisible to this server's /metrics) and asserts a metric registered
// through it is present in the scrape - without opening a real listener,
// per RegisterMetricsGatherer.
func TestServer_MetricsGatherer_IncludesRegisteredGatherer(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	srv, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv)

	acmeRegistry := prometheus.NewRegistry()
	acmeCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "acme",
		Name:      "test_metrics_wiring_total",
		Help:      "proves RegisterMetricsGatherer's registry reaches /metrics",
	})
	acmeRegistry.MustRegister(acmeCounter)
	acmeCounter.Inc()

	srv.RegisterMetricsGatherer(acmeRegistry)

	handler := promhttp.HandlerFor(serverGatherer{s: srv}, promhttp.HandlerOpts{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "acme_test_metrics_wiring_total 1")
}

// TestServer_MetricsGatherer_NoExtraGatherers verifies /metrics still
// serves the default registry's metrics when no gatherer has been
// registered (e.g. ACME disabled), rather than erroring or serving nothing.
func TestServer_MetricsGatherer_NoExtraGatherers(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	srv, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, srv)

	handler := promhttp.HandlerFor(serverGatherer{s: srv}, promhttp.HandlerOpts{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Body.String())
}
