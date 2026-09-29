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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/correlation"
)

// scrubMarker is a distinctive string standing in for internal detail (a
// database path, a library message) that must never reach a client.
const scrubMarker = "SCRUB-MARKER-/var/lib/acme/db-1118"

// newScrubMCPServer builds a MultiProtocolServer over adminSvc logging into
// the returned buffer.
func newScrubMCPServer(t *testing.T, adminSvc admin.Service) (*MultiProtocolServer, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	server, err := NewMultiProtocolServer(
		&ServerConfig{
			RESTAddr: ":0",
			GRPCAddr: ":0",
			QUICAddr: ":0",
			MCPAddr:  ":0",
			Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
		},
		adminSvc,
		nil,
		&mockAuthHandler{},
	)
	require.NoError(t, err)
	return server, &logs
}

// postMCP drives one JSON-RPC request through handleMCP.
func postMCP(t *testing.T, server *MultiProtocolServer, method string, params any, authenticated bool) (*httptest.ResponseRecorder, MCPResponse) {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	body, err := json.Marshal(MCPRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
	req = req.WithContext(correlation.WithCorrelationID(req.Context(), "req-acme-1118"))
	if authenticated {
		req = mcpAuthenticatedRequest(req)
	}
	rec := httptest.NewRecorder()
	server.handleMCP(rec, req)

	var resp MCPResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return rec, resp
}

// TestHandleMCP_InternalErrorWithheld verifies an unclassified service
// error reaches the client as a bare Internal error with no data, while the
// server log carries the marker with the method, path and request ID.
func TestHandleMCP_InternalErrorWithheld(t *testing.T) {
	server, logs := newScrubMCPServer(t, &mockAdminService{
		getStatusErr: errors.New("status query failed at " + scrubMarker),
	})

	rec, resp := postMCP(t, server, "admin.getStatus", map[string]any{}, true)

	require.NotNil(t, resp.Error)
	assert.Equal(t, -32603, resp.Error.Code)
	assert.Equal(t, "Internal error", resp.Error.Message)
	assert.Nil(t, resp.Error.Data)
	assert.NotContains(t, rec.Body.String(), scrubMarker)

	assert.Contains(t, logs.String(), scrubMarker)
	assert.Contains(t, logs.String(), "method=admin.getStatus")
	assert.Contains(t, logs.String(), "path=/mcp")
	assert.Contains(t, logs.String(), "request_id=req-acme-1118")
}

// TestHandleMCP_DenialReasonWithheld verifies an authorization failure
// reports only its fixed code and message; the reason is logged.
func TestHandleMCP_DenialReasonWithheld(t *testing.T) {
	server, logs := newScrubMCPServer(t, &mockAdminService{})

	rec, resp := postMCP(t, server, "admin.getStatus", map[string]any{}, false)

	require.NotNil(t, resp.Error)
	assert.Equal(t, -32002, resp.Error.Code)
	assert.Equal(t, "Unauthorized", resp.Error.Message)
	assert.Nil(t, resp.Error.Data)
	assert.NotContains(t, rec.Body.String(), "unauthenticated")
	assert.Contains(t, logs.String(), "ACME admin MCP request denied")
}

// TestHandleMCP_ClientFaultKeepsData verifies a classified not-found error
// still carries its text in the data field.
func TestHandleMCP_ClientFaultKeepsData(t *testing.T) {
	notFound := fmt.Errorf("account 123: %w", admin.ErrAccountNotFound)
	server, logs := newScrubMCPServer(t, &mockAdminService{getAccountErr: notFound})

	_, resp := postMCP(t, server, "admin.getAccount", map[string]any{"account_id": 123}, true)

	require.NotNil(t, resp.Error)
	assert.Equal(t, -32001, resp.Error.Code)
	assert.Equal(t, "Not found", resp.Error.Message)
	assert.Equal(t, notFound.Error(), resp.Error.Data)
	assert.NotContains(t, logs.String(), "withheld")
}
