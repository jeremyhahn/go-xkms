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

// This file covers pkg/api/transport/mcp client methods (go-xkms #705, batch
// A) that shipped without a test: Algorithms, GetShare/DeleteShare/
// shareParams, QueryAudit, TenantBarrierStatus, UpdateTenantEntitlements/
// Quotas, BarrierEnableEncryption, ClaimShareComplete, and
// WrappingPublicKeyError.

// --- WrappingPublicKeyError ---

func TestWrappingPublicKeyError(t *testing.T) {
	cause := errors.New("asn1: syntax error")
	err := &WrappingPublicKeyError{Err: cause}
	assert.Contains(t, err.Error(), ErrWrappingPublicKeyNotPEM.Error())
	assert.Contains(t, err.Error(), "asn1: syntax error")
	assert.Equal(t, cause, errors.Unwrap(err))
	assert.ErrorIs(t, err, ErrWrappingPublicKeyNotPEM)
}

// --- shareParams ---

func TestShareParams(t *testing.T) {
	got := shareParams("https://a.example", "g1", 3)
	assert.Equal(t, "https://a.example", got["server_url"])
	assert.Equal(t, "g1", got["group_id"])
	assert.Equal(t, 3, got["share_index"])
}

// --- Algorithms ---

func TestAlgorithms_Connected(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "xkms.algorithms" {
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
		d, _ := json.Marshal(transport.AlgorithmsResponse{
			Signing: []transport.AlgorithmInfo{{Algorithm: "ECDSA", KeySizes: []int{256}}},
		})
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.Algorithms(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Signing, 1)
	assert.Equal(t, "ECDSA", resp.Signing[0].Algorithm)
}

// --- GetShare / DeleteShare ---

func TestGetShare_Connected(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "xkms.getShare" {
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
		var params map[string]any
		_ = json.Unmarshal(req.Params, &params)
		d, _ := json.Marshal(transport.ShareInfo{
			ServerURL: params["server_url"].(string), GroupID: params["group_id"].(string),
		})
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.GetShare(context.Background(), "https://a.example", "group-1", 2)
	require.NoError(t, err)
	assert.Equal(t, "https://a.example", resp.ServerURL)
	assert.Equal(t, "group-1", resp.GroupID)
}

func TestDeleteShare_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	require.NoError(t, tr.DeleteShare(context.Background(), "https://a.example", "group-1", 2))
}

// --- QueryAudit ---

func TestQueryAudit_Connected(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "xkms.queryAudit" {
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
		d, _ := json.Marshal(transport.AuditPage{
			Events: []transport.AuditEvent{{Actor: "alice", Action: "sign"}}, Total: 1,
		})
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	page, err := tr.QueryAudit(context.Background(), &transport.AuditFilter{Actor: "alice"})
	require.NoError(t, err)
	assert.Equal(t, 1, page.Total)
	require.Len(t, page.Events, 1)
	assert.Equal(t, "alice", page.Events[0].Actor)
}

func TestQueryAudit_NilFilter(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	_, err := tr.QueryAudit(context.Background(), nil)
	assert.ErrorIs(t, err, transport.ErrInvalidRequest)
}

// --- TenantBarrierStatus / UpdateTenantEntitlements / UpdateTenantQuotas ---

func TestTenantBarrierStatus_Connected(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "xkms.tenantBarrierStatus" {
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
		d, _ := json.Marshal(transport.TenantBarrierStatusResponse{TenantID: "acme", Initialized: true})
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.TenantBarrierStatus(context.Background(), "acme")
	require.NoError(t, err)
	assert.True(t, resp.Initialized)
}

func TestUpdateTenantEntitlements_Connected(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "xkms.updateTenantEntitlements" {
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
		d, _ := json.Marshal(transport.UpdateTenantEntitlementsResponse{Tenant: transport.TenantInfo{ID: "acme"}})
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.Tenant.ID)
}

func TestUpdateTenantQuotas_Connected(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "xkms.updateTenantQuotas" {
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
		d, _ := json.Marshal(transport.UpdateTenantQuotasResponse{Tenant: transport.TenantInfo{ID: "acme"}})
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.Tenant.ID)
}

// --- BarrierEnableEncryption ---

func TestBarrierEnableEncryption_Connected(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method != "barrier.enableEncryption" {
			return jsonrpcResponse{Result: json.RawMessage(`{}`)}
		}
		d, _ := json.Marshal(transport.BarrierEnableEncryptionResponse{Status: "started", Scope: "system"})
		return jsonrpcResponse{Result: d}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	resp, err := tr.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{Strategy: "passphrase"})
	require.NoError(t, err)
	assert.Equal(t, "started", resp.Status)
}

func TestBarrierEnableEncryption_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	_, err := tr.BarrierEnableEncryption(context.Background(), &transport.BarrierEnableEncryptionRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- ClaimShareComplete ---

func TestClaimShareComplete_Connected(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	_, err := tr.ClaimShareComplete(context.Background(), &transport.ClaimShareCompleteRequest{})
	require.NoError(t, err)
}
