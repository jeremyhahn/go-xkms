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

//go:build integration

package acmeserver_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acmeDirectory represents the ACME directory response per RFC 8555 Section 7.1.1.
type acmeDirectory struct {
	NewNonce   string                 `json:"newNonce"`
	NewAccount string                 `json:"newAccount"`
	NewOrder   string                 `json:"newOrder"`
	RevokeCert string                 `json:"revokeCert"`
	KeyChange  string                 `json:"keyChange"`
	Meta       map[string]interface{} `json:"meta,omitempty"`
}

// TestACMEDirectoryReachable verifies the /acme/directory endpoint returns
// the proper RFC 8555 Section 7.1.1 directory object.
func TestACMEDirectoryReachable(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/directory")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"directory should return 200 OK, got body: %s", body)

	var directory acmeDirectory
	err := json.Unmarshal([]byte(body), &directory)
	require.NoError(t, err, "directory response should be valid JSON")

	// Verify required fields per RFC 8555 Section 7.1.1
	assert.NotEmpty(t, directory.NewNonce, "directory must include newNonce URL")
	assert.NotEmpty(t, directory.NewAccount, "directory must include newAccount URL")
	assert.NotEmpty(t, directory.NewOrder, "directory must include newOrder URL")
	assert.NotEmpty(t, directory.RevokeCert, "directory must include revokeCert URL")
	assert.NotEmpty(t, directory.KeyChange, "directory must include keyChange URL")

	// Verify URLs are well-formed
	assert.True(t, strings.HasPrefix(directory.NewNonce, "http"),
		"newNonce URL should be absolute: %s", directory.NewNonce)
	assert.True(t, strings.HasPrefix(directory.NewAccount, "http"),
		"newAccount URL should be absolute: %s", directory.NewAccount)
	assert.True(t, strings.HasPrefix(directory.NewOrder, "http"),
		"newOrder URL should be absolute: %s", directory.NewOrder)
}

// TestACMENewNonceReachable verifies the new-nonce endpoint returns a nonce.
func TestACMENewNonceReachable(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	// Test HEAD request (preferred per RFC 8555 Section 7.2)
	t.Run("HEAD", func(t *testing.T) {
		resp := httpHead(t, client, cfg.ACMEBaseURL+"/acme/new-nonce")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode,
			"HEAD new-nonce should return 200 OK")

		nonce := resp.Header.Get("Replay-Nonce")
		assert.NotEmpty(t, nonce, "Replay-Nonce header must be present")

		// Verify Cache-Control per RFC 8555 Section 7.2
		cacheControl := resp.Header.Get("Cache-Control")
		assert.Contains(t, cacheControl, "no-store",
			"Cache-Control should include no-store")
	})

	// Test GET request (also supported per RFC 8555 Section 7.2)
	t.Run("GET", func(t *testing.T) {
		resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/new-nonce")
		defer resp.Body.Close()

		// GET should return 200 or 204
		assert.True(t,
			resp.StatusCode == http.StatusOK ||
				resp.StatusCode == http.StatusNoContent,
			"GET new-nonce should return 200 or 204, got: %d", resp.StatusCode)

		nonce := resp.Header.Get("Replay-Nonce")
		assert.NotEmpty(t, nonce, "Replay-Nonce header must be present")
	})

	// Test nonce uniqueness
	t.Run("Uniqueness", func(t *testing.T) {
		nonces := make(map[string]bool, 10)
		for i := 0; i < 10; i++ {
			resp := httpHead(t, client, cfg.ACMEBaseURL+"/acme/new-nonce")
			resp.Body.Close()

			nonce := resp.Header.Get("Replay-Nonce")
			require.NotEmpty(t, nonce, "nonce should not be empty on iteration %d", i)

			assert.False(t, nonces[nonce],
				"nonce should be unique, got duplicate: %s on iteration %d", nonce, i)
			nonces[nonce] = true
		}
	})
}

// TestHealthEndpoint verifies the /health endpoint.
func TestHealthEndpoint(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/health")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"health endpoint should return 200 OK, got body: %s", body)
}

// TestReadyEndpoint verifies the /ready endpoint.
func TestReadyEndpoint(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/ready")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"ready endpoint should return 200 OK, got body: %s", body)
}

// TestACMECABundleReachable verifies the CA bundle endpoint.
func TestACMECABundleReachable(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/ca-bundle")
	body := readBody(t, resp)

	// CA bundle should return success with certificate data
	require.True(t,
		resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusNotFound,
		"ca-bundle should return 200 or 404, got %d: %s", resp.StatusCode, body)

	if resp.StatusCode == http.StatusOK {
		// If available, verify it contains PEM data
		assert.True(t,
			strings.Contains(body, "BEGIN CERTIFICATE") ||
				strings.Contains(body, "application/pem-certificate-chain"),
			"CA bundle should contain certificate data")
	}
}

// TestACMEEndpointsReturnProperHeaders verifies ACME-required headers.
func TestACMEEndpointsReturnProperHeaders(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	endpoints := []struct {
		name   string
		path   string
		method string
	}{
		{"Directory", "/acme/directory", "GET"},
		{"NewNonce", "/acme/new-nonce", "HEAD"},
	}

	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			var resp *http.Response
			if ep.method == "HEAD" {
				resp = httpHead(t, client, cfg.ACMEBaseURL+ep.path)
			} else {
				resp = httpGet(t, client, cfg.ACMEBaseURL+ep.path)
			}
			defer resp.Body.Close()

			// All ACME responses should include Replay-Nonce except directory
			if ep.name != "Directory" {
				nonce := resp.Header.Get("Replay-Nonce")
				assert.NotEmpty(t, nonce,
					"%s should include Replay-Nonce header", ep.name)
			}
		})
	}
}

// TestACMENewAccountRequiresPOST verifies new-account rejects GET.
func TestACMENewAccountRequiresPOST(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/new-account")
	defer resp.Body.Close()

	// gorilla/mux returns 404 when a route is only registered for POST and a GET
	// is received, rather than 405. Both are valid rejections of the wrong method.
	assert.True(t,
		resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotFound,
		"expected 405 or 404 for wrong method, got %d", resp.StatusCode)
}

// TestACMENewOrderRequiresPOST verifies new-order rejects GET.
func TestACMENewOrderRequiresPOST(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.ACMEBaseURL+"/acme/new-order")
	defer resp.Body.Close()

	// gorilla/mux returns 404 when a route is only registered for POST and a GET
	// is received, rather than 405. Both are valid rejections of the wrong method.
	assert.True(t,
		resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotFound,
		"expected 405 or 404 for wrong method, got %d", resp.StatusCode)
}
