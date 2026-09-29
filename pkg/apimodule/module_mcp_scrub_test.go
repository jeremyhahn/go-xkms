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

package apimodule

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	wire "github.com/jeremyhahn/go-qrdb/pkg/api/mcp/wire"

	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// scrubMarker is a distinctive string standing in for internal detail (a
// storage path, a library message) that must never reach an MCP client.
const scrubMarker = "SCRUB-MARKER-/var/lib/xkms/secret-path-1118"

// newScrubMCPClientTool registers the module's MCP tools over a single mock
// backend named "mock" whose ListKeys returns listErr, returning a caller
// for the xkms_listKeys tool and the MCP surface's log buffer.
func newScrubMCPClientTool(t *testing.T, listErr error) (func() *mcpgo.CallToolResult, *bytes.Buffer) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	ks := xkmsmocks.NewMockKeyStore()
	ks.ListKeysFunc = func() ([]*types.KeyAttributes, error) { return nil, listErr }
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mock": ks},
		DefaultBackend: "mock",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	var logs bytes.Buffer
	backend, err := xkmsmcp.NewServer(&xkmsmcp.Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(&logs, nil)),
	})
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithMCPServer(func() *xkmsmcp.Server { return backend }))
	require.NoError(t, err)
	srv := mcpserver.NewMCPServer("xkms-mcp-scrub-test", "0.0.0", mcpserver.WithToolCapabilities(true))
	m.RegisterMCP(srv)
	client := newInProcessMCPClient(t, srv)

	return func() *mcpgo.CallToolResult {
		return callXKMSTool(t, client, context.Background(), "xkms_listKeys", map[string]any{"backend": "mock"})
	}, &logs
}

// toolResultText concatenates a tool result's text content and its
// structured envelope, everything a client can read.
func toolResultText(t *testing.T, res *mcpgo.CallToolResult) string {
	t.Helper()
	var out bytes.Buffer
	for _, c := range res.Content {
		if text, ok := c.(mcpgo.TextContent); ok {
			out.WriteString(text.Text)
		}
	}
	structured, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	out.Write(structured)
	return out.String()
}

// TestMCPToolHandler_InternalErrorWithheld verifies an unclassified service
// error reaches the MCP client as CodeInternal with the fixed message and no
// trace of the marker, while the server log carries the marker.
func TestMCPToolHandler_InternalErrorWithheld(t *testing.T) {
	call, logs := newScrubMCPClientTool(t, errors.New("storage backend failed at "+scrubMarker))

	res := call()
	payload := decodeToolErrorCode(t, res)
	assert.Equal(t, wire.CodeInternal, payload.Code)
	assert.Equal(t, xkmsmcp.ErrInternal.Error(), payload.Message)
	assert.NotContains(t, toolResultText(t, res), scrubMarker)

	assert.Contains(t, logs.String(), scrubMarker)
	assert.Contains(t, logs.String(), "tool=xkms_listKeys")
}

// TestMCPToolHandler_ClientFaultKeepsMessage verifies a classified client
// fault still reaches the MCP client with its own message.
func TestMCPToolHandler_ClientFaultKeepsMessage(t *testing.T) {
	notFound := fmt.Errorf("key signing-key: %w", xkms.ErrKeyNotFound)
	call, logs := newScrubMCPClientTool(t, notFound)

	res := call()
	payload := decodeToolErrorCode(t, res)
	assert.Equal(t, wire.CodeNotFound, payload.Code)
	assert.Contains(t, payload.Message, xkms.ErrKeyNotFound.Error())
	assert.Contains(t, payload.Message, "signing-key")
	assert.NotContains(t, logs.String(), "internal error withheld")
}
