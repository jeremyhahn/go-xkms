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
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// verdictCalls returns one call per verdict method of svc.
func verdictCalls(ctx context.Context, svc transport.AttestationVerdictService) map[string]func() error {
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	return map[string]func() error{
		"list":     func() error { _, err := svc.ListAttestationVerdicts(ctx, req); return err },
		"latest":   func() error { _, err := svc.GetLatestAttestationVerdict(ctx, req); return err },
		"reattest": func() error { _, err := svc.ReattestDevice(ctx, req); return err },
	}
}

// TestAttestationVerdicts_CallsTheTool proves every verdict method reaches
// its attestation.verdict.* tool.
func TestAttestationVerdicts_CallsTheTool(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for name, call := range verdictCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.NoError(t, call()) })
	}
}

// TestAttestationVerdicts_ServerRefusal proves a tool error reaches the
// caller.
func TestAttestationVerdicts_ServerRefusal(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			return jsonrpcResponse{Result: []byte(`{"status":"ok"}`)}
		}
		return jsonrpcResponse{ErrorText: "validation failed: device_id is required", Envelope: qrdbsdk.MCPCodeInvalidArgument}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for name, call := range verdictCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorContains(t, call(), "device_id is required") })
	}
}

// TestAttestationVerdicts_NotConnected proves every verdict method refuses
// before the transport is connected.
func TestAttestationVerdicts_NotConnected(t *testing.T) {
	for name, call := range verdictCalls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
