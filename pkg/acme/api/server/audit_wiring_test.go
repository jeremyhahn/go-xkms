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

//go:build !integration

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAuditTrail records one event through a real FileAuditLogger and returns
// a querier over the file it wrote, mirroring how a deployment builds both ends
// of the trail from one audit configuration.
func writeAuditTrail(t *testing.T) (*audit.FileQuerier, *audit.AuditEvent) {
	t.Helper()

	cfg := &audit.Config{
		Enabled:              true,
		LogPath:              filepath.Join(t.TempDir(), "audit.log"),
		Format:               "json",
		BufferSize:           16,
		FlushIntervalSeconds: 1,
	}

	logger, err := audit.NewFileAuditLogger(cfg)
	require.NoError(t, err)
	require.True(t, logger.Enabled())

	event := &audit.AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: audit.EventCertificateIssued,
		Actor:     "account:1234",
		Resource:  "order:5678",
		Action:    "issue",
		Result:    audit.ResultSuccess,
		Details:   map[string]interface{}{"common_name": "example.com"},
	}
	require.NoError(t, logger.Log(context.Background(), event))

	// Close rather than Flush: the writer goroutine is joined, so the record is
	// unambiguously durable before the querier reads it back.
	require.NoError(t, logger.Close())

	querier, err := audit.NewFileQuerier(cfg)
	require.NoError(t, err)

	return querier, event
}

// serveAdminAudit issues GET /admin/audit against a server built from cfg.
func serveAdminAudit(t *testing.T, cfg *ServerConfig) *httptest.ResponseRecorder {
	t.Helper()

	srv, err := NewMultiProtocolServer(cfg, &mockAdminService{}, nil, nil)
	require.NoError(t, err)

	resp := httptest.NewRecorder()
	srv.router.ServeHTTP(resp, mcpAuthenticatedRequest(
		httptest.NewRequest(http.MethodGet, "/admin/audit", nil)))

	return resp
}

// TestServerConfig_AuditQuerierServesAuditEndpoint verifies that a querier
// supplied through ServerConfig actually reaches GET /admin/audit, which is the
// wiring that makes the audit trail readable in a running deployment.
func TestServerConfig_AuditQuerierServesAuditEndpoint(t *testing.T) {
	querier, want := writeAuditTrail(t)

	cfg := DefaultConfig()
	cfg.AuditQuerier = querier

	resp := serveAdminAudit(t, cfg)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	var page struct {
		Items   []*audit.AuditEvent `json:"items"`
		Total   int                 `json:"total"`
		Page    int                 `json:"page"`
		PerPage int                 `json:"per_page"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &page))

	require.Equal(t, 1, page.Total)
	require.Len(t, page.Items, 1)
	assert.Equal(t, want.EventType, page.Items[0].EventType)
	assert.Equal(t, want.Actor, page.Items[0].Actor)
	assert.Equal(t, want.Resource, page.Items[0].Resource)
	assert.Equal(t, want.Action, page.Items[0].Action)
	assert.Equal(t, want.Result, page.Items[0].Result)
}

// TestServerConfig_WithoutAuditQuerierReportsUnavailable verifies the honest
// answer when no trail is configured: the endpoint says so rather than
// returning an empty page that would look like a CA which issued nothing.
func TestServerConfig_WithoutAuditQuerierReportsUnavailable(t *testing.T) {
	resp := serveAdminAudit(t, DefaultConfig())

	assert.Equal(t, http.StatusNotImplemented, resp.Code)
	assert.Contains(t, resp.Body.String(), "no audit trail configured")
}

// TestNewFileQuerier_RejectsDisabledTrail verifies that a deployment cannot
// accidentally build a querier over a trail that is not being written, which is
// what keeps the endpoint's "unavailable" answer truthful.
func TestNewFileQuerier_RejectsDisabledTrail(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")

	querier, err := audit.NewFileQuerier(&audit.Config{Enabled: false, LogPath: logPath})
	require.ErrorIs(t, err, audit.ErrQueryUnavailable)
	assert.Nil(t, querier)

	_, err = os.Stat(logPath)
	assert.True(t, os.IsNotExist(err))
}
