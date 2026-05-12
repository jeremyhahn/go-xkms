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

package acmeserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/jeremyhahn/go-xkms/test/integration/acme-multiprotocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listResponse is used for paginated list endpoint responses.
type listResponse struct {
	Items   json.RawMessage `json:"items"`
	Total   int             `json:"total"`
	Page    int             `json:"page"`
	PerPage int             `json:"per_page"`
}

// TestAdminAPIStatusREST verifies the admin status endpoint via REST.
func TestAdminAPIStatusREST(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.AdminBaseURL+"/admin/status")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"admin status should return 200 OK, got body: %s", body)

	var status admin.CAStatus
	err := json.Unmarshal([]byte(body), &status)
	require.NoError(t, err, "response body should unmarshal into CAStatus")

	assert.NotEmpty(t, status.Identity, "status should have identity")
	assert.NotEmpty(t, status.Version, "status should have version")
}

// TestAdminAPIStatsREST verifies the admin stats endpoint via REST.
func TestAdminAPIStatsREST(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.AdminBaseURL+"/admin/stats")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"admin stats should return 200 OK, got body: %s", body)

	var stats admin.CAStats
	err := json.Unmarshal([]byte(body), &stats)
	require.NoError(t, err, "response body should unmarshal into CAStats")

	assert.GreaterOrEqual(t, stats.TotalCertificates, 0, "total certificates >= 0")
	assert.GreaterOrEqual(t, stats.TotalAccounts, 0, "total accounts >= 0")
}

// TestAdminAPIMultiProtocol verifies admin API is reachable on all protocols.
func TestAdminAPIMultiProtocol(t *testing.T) {
	tc := multiprotocol.NewTestContext(t)
	defer tc.Cleanup()

	tc.ForEachProtocol(t, func(t *testing.T, adapter api.AdminAdapter) {
		protocol := adapter.Protocol()

		t.Run("Status", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultServerTimeout)
			defer cancel()

			status, err := adapter.GetStatus(ctx)
			require.NoError(t, err, "GetStatus should succeed via %s", protocol)
			require.NotNil(t, status, "status should not be nil via %s", protocol)
			assert.NotEmpty(t, status.Identity, "should have identity via %s", protocol)
		})

		t.Run("Stats", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultServerTimeout)
			defer cancel()

			stats, err := adapter.GetStats(ctx)
			require.NoError(t, err, "GetStats should succeed via %s", protocol)
			require.NotNil(t, stats, "stats should not be nil via %s", protocol)
		})

		t.Run("ListTenants", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultServerTimeout)
			defer cancel()

			tenants, _, err := adapter.ListTenants(ctx, &admin.ListTenantsRequest{
				Page:    1,
				PerPage: 10,
			})
			require.NoError(t, err, "ListTenants should succeed via %s", protocol)
			assert.NotNil(t, tenants, "tenants should not be nil via %s", protocol)
		})

		t.Run("ListCertificates", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultServerTimeout)
			defer cancel()

			certs, _, err := adapter.ListCertificates(ctx, &admin.ListCertificatesRequest{
				Page:    1,
				PerPage: 10,
			})
			require.NoError(t, err, "ListCertificates should succeed via %s", protocol)
			assert.NotNil(t, certs, "certificates should not be nil via %s", protocol)
		})

		t.Run("ListAccounts", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultServerTimeout)
			defer cancel()

			accounts, _, err := adapter.ListAccounts(ctx, &admin.ListAccountsRequest{
				Page:    1,
				PerPage: 10,
			})
			require.NoError(t, err, "ListAccounts should succeed via %s", protocol)
			assert.NotNil(t, accounts, "accounts should not be nil via %s", protocol)
		})
	})
}

// TestAdminAPITenantsEndpoint verifies the admin tenants REST endpoint.
func TestAdminAPITenantsEndpoint(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.AdminBaseURL+"/api/v1/tenants?page=1&per_page=10")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"admin tenants should return 200 OK, got body: %s", body)

	var list listResponse
	err := json.Unmarshal([]byte(body), &list)
	require.NoError(t, err, "response body should unmarshal into listResponse")

	// Items should be a JSON array of tenants
	var tenants []interface{}
	err = json.Unmarshal(list.Items, &tenants)
	require.NoError(t, err, "items should be a JSON array")
}

// TestAdminAPICertificatesEndpoint verifies the admin certificates REST endpoint.
func TestAdminAPICertificatesEndpoint(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.AdminBaseURL+"/admin/certificates?page=1&per_page=10")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"admin certificates should return 200 OK, got body: %s", body)

	var list listResponse
	err := json.Unmarshal([]byte(body), &list)
	require.NoError(t, err, "response body should unmarshal into listResponse")

	var certs []interface{}
	err = json.Unmarshal(list.Items, &certs)
	require.NoError(t, err, "items should be a JSON array")
}

// TestAdminAPIAccountsEndpoint verifies the admin accounts REST endpoint.
func TestAdminAPIAccountsEndpoint(t *testing.T) {
	cfg := newServerConfig()
	client := newHTTPClient(cfg)

	resp := httpGet(t, client, cfg.AdminBaseURL+"/admin/accounts?page=1&per_page=10")
	body := readBody(t, resp)

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"admin accounts should return 200 OK, got body: %s", body)

	var list listResponse
	err := json.Unmarshal([]byte(body), &list)
	require.NoError(t, err, "response body should unmarshal into listResponse")

	var accounts []interface{}
	err = json.Unmarshal(list.Items, &accounts)
	require.NoError(t, err, "items should be a JSON array")
}
