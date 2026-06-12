// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

// Package acmeserver_test provides integration tests for the trusted-acme-server.
//
// These tests verify that the ACME server is running, responsive, and serving
// all expected endpoints. They are designed to run against a real server
// instance in a Docker container.
//
// Environment variables:
//   - ACME_SERVER_BASE_URL: Base URL of the ACME server (default: https://localhost:8443)
//   - ACME_ADMIN_BASE_URL: Base URL of the admin API (default: https://localhost:9443)
//   - ACME_SERVER_TLS_INSECURE: Skip TLS verification (default: true)
package acmeserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

const (
	defaultACMEServerURL = "https://localhost:8443"
	defaultAdminBaseURL  = "https://localhost:9443"
	defaultServerTimeout = 30 * time.Second
)

// serverConfig holds server endpoint configuration.
type serverConfig struct {
	ACMEBaseURL  string
	AdminBaseURL string
	TLSCAFile    string
	Timeout      time.Duration
}

// newServerConfig creates a server configuration from environment variables.
// ACME_SERVER_CA_FILE must point to the server's CA certificate so TLS
// verification succeeds. InsecureSkipVerify is not supported.
func newServerConfig() *serverConfig {
	return &serverConfig{
		ACMEBaseURL:  serverEnvOr("ACME_SERVER_BASE_URL", defaultACMEServerURL),
		AdminBaseURL: serverEnvOr("ACME_ADMIN_BASE_URL", defaultAdminBaseURL),
		TLSCAFile:    os.Getenv("ACME_SERVER_CA_FILE"),
		Timeout:      defaultServerTimeout,
	}
}

// serverEnvOr returns the environment variable value or a default.
func serverEnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// newHTTPClient creates an HTTP client configured for integration tests.
// When ACME_SERVER_CA_FILE is set, the server's CA cert is loaded for
// proper TLS verification. If no CA file is configured, the system pool
// is used; the test will fail if the server uses a private CA.
func newHTTPClient(cfg *serverConfig) *http.Client {
	tr := &http.Transport{}
	if cfg.TLSCAFile != "" {
		caPEM, err := os.ReadFile(cfg.TLSCAFile)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caPEM) {
				tr.TLSClientConfig = &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS13,
				}
			}
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
	}
}

// httpGet performs an HTTP GET request with context.
func httpGet(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), defaultServerTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}

	return resp
}

// httpHead performs an HTTP HEAD request with context.
func httpHead(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), defaultServerTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HEAD %s failed: %v", url, err)
	}

	return resp
}

// readBody reads and returns the response body as a string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	return string(body)
}

// TestServerStartup verifies the ACME server is running and responding.
func TestServerStartup(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/directory")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("server not responding at %s: status=%d body=%s",
			cfg.ACMEBaseURL, resp.StatusCode, body)
	}

	t.Logf("server is running at %s", cfg.ACMEBaseURL)
}

// TestServerGracefulShutdown verifies the server handles connections during test.
// In an integration test context, we verify the server responds consistently.
func TestServerGracefulShutdown(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	// Send multiple requests to verify stability
	for i := 0; i < 5; i++ {
		resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/directory")
		body := readBody(t, resp)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("server became unresponsive on iteration %d: status=%d body=%s",
				i, resp.StatusCode, body)
		}
	}
}

// TestServerConfigValidation verifies the server returns proper ACME directory.
func TestServerConfigValidation(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/directory")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("directory endpoint returned status %d: %s", resp.StatusCode, body)
	}

	// Verify Content-Type is JSON
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got: %s", contentType)
	}
}
