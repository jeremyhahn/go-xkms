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

	"github.com/jeremyhahn/go-xkms/pkg/testutil/signingkeytest"
)

// TestSigningKey_CallsTheTool proves every signing-key method reaches its
// attestation.signing_key.* tool.
func TestSigningKey_CallsTheTool(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for name, call := range signingkeytest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.NoError(t, call()) })
	}
}

// TestSigningKey_ServerRefusal proves a tool error reaches the caller: a
// server that refuses every signing-key call fails each method, with no
// binding or resolution decoded.
func TestSigningKey_ServerRefusal(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			return jsonrpcResponse{Result: []byte(`{"status":"ok"}`)}
		}
		return jsonrpcResponse{ErrorText: "validation failed: invalid repository", Envelope: qrdbsdk.MCPCodeInvalidArgument}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	for name, call := range signingkeytest.Calls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) { assert.ErrorContains(t, call(), "invalid repository") })
	}
}

// TestSigningKey_NotConnected proves every signing-key method refuses
// before the transport is connected.
func TestSigningKey_NotConnected(t *testing.T) {
	for name, call := range signingkeytest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}
