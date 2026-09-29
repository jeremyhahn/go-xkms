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

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newResilienceTestClient builds an HTTPS client trusting tca's own CA
// certificate, the same TLS-verification setup TestTrustedCA_Serve_HealthEndpoints
// uses, so these tests can hit the real ACME HTTPS listener instead of
// calling handler methods directly.
func newResilienceTestClient(t *testing.T, tca *TrustedCA) *http.Client {
	t.Helper()

	caConfig, err := tca.CA().TLSConfig(context.Background(), nil)
	require.NoError(t, err)
	certPool := x509.NewCertPool()
	for _, cert := range caConfig.Certificates {
		for _, certDER := range cert.Certificate {
			x509Cert, parseErr := x509.ParseCertificate(certDER)
			if parseErr == nil {
				certPool.AddCert(x509Cert)
			}
		}
	}

	return &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}
}

// TestTrustedCA_Serve_HealthReportsRealBreakers verifies that Serve wires
// tca.config.ACME.Resilience and a caller-supplied challenge map into the
// same breaker Manager and wrapping xkmsd's embedded ACME listener uses
// (#820): GET /health reports a "storage" breaker (created unconditionally,
// same as cmd/xkmsd/acme.go) and an "http01" per-target breaker group
// (registered because the challenge map below has an http-01 entry for
// WrapChallengeVerifiers to wrap -- see go-xkms#1189/#1190), the storage
// breaker closed, the http01 group empty (no target has been validated
// yet), and the router healthy.
func TestTrustedCA_Serve_HealthReportsRealBreakers(t *testing.T) {
	acmePort := getAvailablePort(t)

	mockCA := newMockCA()
	mockCA.On("CABundleFiltered", mock.Anything, mock.Anything).Return([]byte("mock-bundle"), nil).Maybe()

	cfg := validConfig()
	cfg.ACME.HTTPSAddr = fmt.Sprintf("127.0.0.1:%d", acmePort)

	noopHTTP01 := acmecommon.ChallengeVerifierFunc(func(
		*net.Resolver, acmecommon.CertificateAuthority, string, string, string, string) error {
		return nil
	})

	tca, err := New(
		WithCA(mockCA),
		WithStorageFactory(newMockStorageFactory()),
		WithConfig(cfg),
		WithChallengeMap(map[string]acmecommon.ChallengeVerifierFunc{
			acmecommon.ChallengeTypeHTTP01: noopHTTP01,
		}),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tca.Serve(ctx) }()

	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", acmePort))
	client := newResilienceTestClient(t, tca)

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", acmePort))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var status handlers.HealthStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&status))

	assert.True(t, status.Healthy)
	require.Contains(t, status.Breakers, "storage", "the storage breaker must always be registered, matching xkmsd's unconditional wiring")
	assert.Equal(t, "closed", status.Breakers["storage"].State)
	require.Contains(t, status.TargetGroups, "http01", "the http-01 challenge verifier supplied via WithChallengeMap must be wrapped and its per-target breaker group registered")
	assert.Zero(t, status.TargetGroups["http01"].Open, "no target has been validated yet")
	assert.Zero(t, status.TargetGroups["http01"].Tracked, "no target has been validated yet")

	// Close the client's idle connections before cancelling. http.Server's
	// Shutdown treats a handshaken connection that has not sent a request
	// yet (StateNew) as active for up to five seconds, so a spare
	// connection the transport opened would otherwise hold Serve past the
	// deadline below.
	client.CloseIdleConnections()
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

// TestTrustedCA_Serve_StorageBreakerOpen_DegradesDirectory verifies that,
// once the storage breaker trips on a real CA-bundle failure, GET /directory
// serves its last cached response marked degraded and GET /health reports
// the router unhealthy -- the same degradation behavior
// pkg/acme/server/handlers.TestDirectoryHandler_DegradesToCache_WhenStorageBreakerOpen
// exercises directly on RestService, driven here through TrustedCA's actual
// wiring end to end (#820).
func TestTrustedCA_Serve_StorageBreakerOpen_DegradesDirectory(t *testing.T) {
	acmePort := getAvailablePort(t)

	mockCA := newMockCA()
	// CA-bundle storage access always fails, so the single GET /acme/ca-bundle
	// below trips the storage breaker deterministically (MaxFailures 1). This
	// test is about the directory endpoint's degraded-serving path, not
	// CA-bundle's own (see TestCABundleHandler_DegradesToCache_WhenStorageBreakerOpen
	// in pkg/acme/server/handlers for that).
	mockCA.On("CABundleFiltered", mock.Anything, mock.Anything).
		Return(nil, errors.New("ca-bundle storage unavailable")).Maybe()

	cfg := validConfig()
	cfg.ACME.HTTPSAddr = fmt.Sprintf("127.0.0.1:%d", acmePort)
	// MaxFailures 1 so the single failing call below trips the breaker
	// deterministically, and a long reset timeout so the breaker stays open
	// for the rest of the test instead of racing a half-open probe.
	cfg.ACME.Resilience.Storage = config.ACMECircuitBreakerConfig{
		MaxFailures:         1,
		ResetTimeoutSeconds: 3600,
	}

	tca, err := New(
		WithCA(mockCA),
		WithStorageFactory(newMockStorageFactory()),
		WithConfig(cfg),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tca.Serve(ctx) }()

	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", acmePort))
	client := newResilienceTestClient(t, tca)
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", acmePort)

	// First request populates the directory degradation cache with a fresh,
	// non-degraded response.
	resp, err := client.Get(baseURL + "/acme/directory")
	require.NoError(t, err)
	fresh, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Warning"), "the first directory response must not be degraded")

	// The CA-bundle call fails, tripping the storage breaker (MaxFailures 1).
	resp, err = client.Get(baseURL + "/acme/ca-bundle")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// The storage breaker is open: /health must report it open and the
	// router unhealthy.
	resp, err = client.Get(baseURL + "/health")
	require.NoError(t, err)
	var status handlers.HealthStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&status))
	_ = resp.Body.Close()

	assert.False(t, status.Healthy)
	require.Contains(t, status.Breakers, "storage")
	assert.Equal(t, "open", status.Breakers["storage"].State)
	assert.True(t, status.Degradation.Active)

	// The directory endpoint now serves the cached response, marked
	// degraded, instead of failing or silently serving unmarked content.
	resp, err = client.Get(baseURL + "/acme/directory")
	require.NoError(t, err)
	degraded, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Warning"), "a cache-served directory response must be marked degraded")
	assert.Equal(t, fresh, degraded, "the degraded response must be exactly the cached one")

	// Close the client's idle connections before cancelling. http.Server's
	// Shutdown treats a handshaken connection that has not sent a request
	// yet (StateNew) as active for up to five seconds, so a spare
	// connection the transport opened would otherwise hold Serve past the
	// deadline below.
	client.CloseIdleConnections()
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}
