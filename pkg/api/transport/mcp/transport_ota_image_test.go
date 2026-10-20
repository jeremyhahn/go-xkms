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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

const otaBadBoard = "Bad--Board"

// newOTAImageMCPServer answers the OTA image-key methods the way the xkmsd
// MCP server does: a malformed board id is invalid params, any other board
// gets a result naming its key.
func newOTAImageMCPServer(t *testing.T) *Transport {
	t.Helper()
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		var params struct {
			BoardID string `json:"board_id"`
		}
		if len(req.Params) > 0 {
			require.NoError(t, json.Unmarshal(req.Params, &params))
		}
		if params.BoardID == otaBadBoard {
			return jsonrpcResponse{ErrorText: "validation failed: invalid board id", Envelope: qrdbsdk.MCPCodeInvalidArgument}
		}
		var result interface{}
		switch req.Method {
		case "health":
			result = map[string]string{"status": "ok"}
		case "xkms.createOTAImageKey":
			result = map[string]string{"key_id": "ota-image-" + params.BoardID}
		case "xkms.rotateOTAImageKey":
			result = map[string]interface{}{"key_id": "ota-image-" + params.BoardID, "key_version": 2}
		case "xkms.signOTAImage":
			result = map[string]interface{}{"signature": []byte("sig"), "key_version": 2}
		default:
			return jsonrpcResponse{ErrorText: "unexpected method " + req.Method, Envelope: qrdbsdk.MCPCodeUnimplemented}
		}
		data, err := json.Marshal(result)
		require.NoError(t, err)
		return jsonrpcResponse{Result: data}
	})
	t.Cleanup(cleanup)
	tr := connectToMockServer(t, addr)
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })
	return tr
}

func TestOTAImageKey_MCP(t *testing.T) {
	tr := newOTAImageMCPServer(t)
	ctx := context.Background()

	created, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, "ota-image-cm4", created.KeyID)

	rotated, err := tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	signed, err := tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("image")})
	require.NoError(t, err)
	assert.Equal(t, []byte("sig"), signed.Signature)
	assert.Equal(t, uint32(2), signed.KeyVersion)
}

func TestOTAImageKey_MCP_InvalidBoard(t *testing.T) {
	tr := newOTAImageMCPServer(t)
	ctx := context.Background()

	calls := map[string]func() error{
		"create": func() error {
			_, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: otaBadBoard})
			return err
		},
		"rotate": func() error {
			_, err := tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: otaBadBoard})
			return err
		},
		"sign": func() error {
			_, err := tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: otaBadBoard, Data: []byte("image")})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			var rpcErr *RPCError
			require.True(t, errors.As(err, &rpcErr), "error %T is not an RPCError", err)
			assert.Equal(t, xkmsmcp.ErrCodeInvalidParams, rpcErr.Code)
		})
	}
}
