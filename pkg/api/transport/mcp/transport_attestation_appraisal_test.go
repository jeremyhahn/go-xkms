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

	"github.com/jeremyhahn/go-xkms/pkg/testutil/appraisaltest"
)

// TestAttestationAppraisal_CallsTheTool proves every Verifier method reaches
// its tool.
func TestAttestationAppraisal_CallsTheTool(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for name, call := range appraisaltest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.NoError(t, call()) })
	}
}

// TestAttestationAppraisal_ServerRefusal proves a tool error reaches the
// caller: a server that refuses every Verifier call fails each method.
func TestAttestationAppraisal_ServerRefusal(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			return jsonrpcResponse{Result: []byte(`{"status":"ok"}`)}
		}
		return jsonrpcResponse{ErrorText: "validation failed: invalid name", Envelope: qrdbsdk.MCPCodeInvalidArgument}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for name, call := range appraisaltest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorContains(t, call(), "invalid name") })
	}
}

// TestAttestationAppraisal_NotConnected proves every Verifier method refuses
// before the transport is connected.
func TestAttestationAppraisal_NotConnected(t *testing.T) {
	for name, call := range appraisaltest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
