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

// handlers_audit_test.go covers the MCP xkms.queryAudit method: dispatch
// registration and the wire code it reports when no go-qrdb node backs the
// audit chain (go-xkms#930).
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestAuditMethod_Dispatchable proves xkms.queryAudit is reachable through
// the dispatch table.
func TestAuditMethod_Dispatchable(t *testing.T) {
	_, ok := rpcMethodHandlers["xkms.queryAudit"]
	assert.True(t, ok, "xkms.queryAudit must be dispatchable")
}

// TestMapAuditOperationError pins auditOperationError's classification: it
// is unconditionally ErrCodeInternalError, mirroring
// pkg/api/grpc/service_audit.go's QueryAudit, which reports codes.Internal
// for any failure of the call unconditionally.
func TestMapAuditOperationError(t *testing.T) {
	err := auditOperationError("failed to query audit", errors.New("boom"))
	assertKeyOpCode(t, err, ErrCodeInternalError)
}

// TestHandleQueryAudit_NoParams_NotConfigured proves an absent-params
// xkms.queryAudit call against a service with no go-qrdb node reaches
// dispatch as a *KeyOpError, not the bare *errs.Wrapped this handler
// returned before go-xkms#930.
func TestHandleQueryAudit_NoParams_NotConfigured(t *testing.T) {
	server := createTestServer(t)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.queryAudit", ID: 1}
	_, err := server.handleQueryAudit(context.Background(), req)

	require.Error(t, err, "a service with no go-qrdb node must report failure, not panic")
	assertKeyOpCode(t, err, ErrCodeInternalError)
}

// TestHandleQueryAudit_WithFilter_NotConfigured pins the same classification
// when the caller supplies an explicit filter.
func TestHandleQueryAudit_WithFilter_NotConfigured(t *testing.T) {
	server := createTestServer(t)

	raw, err := json.Marshal(transport.AuditFilter{Actor: "alice", Limit: 10})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.queryAudit", Params: raw, ID: 1}
	_, err = server.handleQueryAudit(context.Background(), req)

	require.Error(t, err)
	assertKeyOpCode(t, err, ErrCodeInternalError)
}

// TestHandleQueryAudit_InvalidParams proves a malformed filter is reported
// as Invalid params, exercising decodeParams's own gate ahead of
// auditOperationError.
func TestHandleQueryAudit_InvalidParams(t *testing.T) {
	server := createTestServer(t)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.queryAudit", Params: json.RawMessage(`{`), ID: 1}
	_, err := server.handleQueryAudit(context.Background(), req)

	require.Error(t, err)
	assertKeyOpCode(t, err, ErrCodeInvalidParams)
}

// TestAuditMethod_WireCodeThroughInvokeMethod drives xkms.queryAudit through
// Server.InvokeMethod, the production dispatch path, and pins the code a
// caller actually sees for the not-configured condition (go-xkms#930).
func TestAuditMethod_WireCodeThroughInvokeMethod(t *testing.T) {
	server := createTestServer(t)

	resp := invokeRequest(server, context.Background(), &JSONRPCRequest{
		JSONRPC: "2.0", Method: "xkms.queryAudit", ID: 1,
	})

	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
}
