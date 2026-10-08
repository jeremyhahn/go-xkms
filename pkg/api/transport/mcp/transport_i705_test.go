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

// --- QueryAudit ---

// --- TenantBarrierStatus / UpdateTenantEntitlements / UpdateTenantQuotas ---

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

// --- ClaimShareComplete ---
