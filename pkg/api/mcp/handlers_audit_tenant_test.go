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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// mcpFilterRecordingAuditClient records the filter that reaches the qrdb audit
// chain, which is the filter that decides whose events are returned.
type mcpFilterRecordingAuditClient struct {
	got qrdbtransport.AuditFilter
}

func (c *mcpFilterRecordingAuditClient) EmitAudit(context.Context, qrdbtransport.AuditEvent) error {
	return nil
}

func (c *mcpFilterRecordingAuditClient) QueryAudit(_ context.Context, f qrdbtransport.AuditFilter) (*qrdbtransport.AuditPage, error) {
	c.got = f
	return &qrdbtransport.AuditPage{}, nil
}

// TestHandleQueryAudit_TenantCallerIsClampedToItsOwnTenant drives #1115 over
// MCP: a tenant caller's absent or foreign tenant_id reaches the audit chain as
// its own tenant.
func TestHandleQueryAudit_TenantCallerIsClampedToItsOwnTenant(t *testing.T) {
	server := createTestServer(t)
	client := &mcpFilterRecordingAuditClient{}
	server.xkmsService.SetAuditClient(client)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "tenant-a"})

	foreign, err := json.Marshal(transport.AuditFilter{TenantID: "tenant-b"})
	require.NoError(t, err)

	for _, params := range []json.RawMessage{nil, foreign} {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.queryAudit", Params: params, ID: 1}
		_, err := server.handleQueryAudit(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", client.got.TenantID, "params %s", params)
	}
}
