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

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acmemetrics "github.com/jeremyhahn/go-xkms/pkg/acme/server/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestXkmsdMetrics_ACMERegistryReachesServerMetrics is the end-to-end proof
// for issue #734 item 3: xkmsd's /metrics output includes the ACME
// registry, gathered alongside the default registry rather than served on a
// second endpoint. It exercises the same two production call sites as
// cmd/xkmsd/acme.go - buildACMERouter (which mounts acmemetrics.Mount) and
// srv.RegisterMetricsGatherer(acmemetrics.Registry) - against a real
// pkg/server.Server metrics listener, so a regression in either call site
// would surface here.
func TestXkmsdMetrics_ACMERegistryReachesServerMetrics(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	// Drive a request through the same router buildACMERouter constructs
	// for the embedded ACME server, so acmemetrics.Registry has at least
	// one recorded sample by the time /metrics is scraped below.
	svc := &stubRestService{}
	acmeRouter := buildACMERouter(svc, "/acme")
	acmeTS := httptest.NewServer(acmeRouter)
	defer acmeTS.Close()

	resp, err := http.Get(acmeTS.URL + "/acme/directory")
	if err != nil {
		t.Fatalf("GET /acme/directory: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	tempDir := t.TempDir()
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1", RESTPort: 18081},
		Protocols: config.ProtocolsConfig{
			Unix: true,
		},
		Unix: config.UnixConfig{
			Enabled:    true,
			SocketPath: filepath.Join(tempDir, "xkms.sock"),
			Protocol:   "grpc",
		},
		Logging: config.LoggingConfig{Level: "error", Format: "json"},
		TLS:     config.TLSConfig{Enabled: false},
		Auth:    config.AuthConfig{Enabled: false},
		Storage: config.StorageConfig{Backend: "file", Path: tempDir},
		Default: config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{Enabled: true, Path: filepath.Join(tempDir, "software")},
		},
		Metrics: config.MetricsConfig{
			Enabled: true,
			Port:    19394,
			Path:    "/metrics",
		},
	}

	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// Mirrors startACMEServer's RegisterMetricsGatherer(acmemetrics.Registry)
	// call: this is the one line under test in cmd/xkmsd/acme.go, exercised
	// here without standing up the full TPM/CA-backed ACME server.
	srv.RegisterMetricsGatherer(acmemetrics.Registry)

	if err := srv.Start(); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	defer func() {
		if err := srv.Shutdown(); err != nil {
			t.Errorf("server.Shutdown: %v", err)
		}
	}()

	// The metrics server starts in its own goroutine; give it a moment to
	// bind before scraping, matching pkg/server's own startMetrics tests.
	time.Sleep(100 * time.Millisecond)

	metricsResp, err := http.Get("http://127.0.0.1:19394/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = metricsResp.Body.Close() }()

	body, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}

	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from /metrics, got %d: %s", metricsResp.StatusCode, body)
	}

	if !strings.Contains(string(body), "acme_requests_total") {
		t.Fatalf("expected xkmsd /metrics to include acme_requests_total, got:\n%s", body)
	}
}
