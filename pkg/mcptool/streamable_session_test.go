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

package mcptool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionCall is one request a scripted MCP server received.
type sessionCall struct {
	method string
	params map[string]json.RawMessage
	header http.Header
}

// scriptedServer answers each JSON-RPC method with the result (or error)
// reply returns and records every message it receives. Notifications get 202.
func scriptedServer(t *testing.T, reply func(method string) (result string, rpcErr string)) (*httptest.Server, func() []sessionCall) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls []sessionCall
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			ID     json.RawMessage            `json:"id"`
			Method string                     `json:"method"`
			Params map[string]json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		calls = append(calls, sessionCall{method: msg.Method, params: msg.Params, header: r.Header.Clone()})
		mu.Unlock()
		if len(msg.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		result, rpcErr := reply(msg.Method)
		body := `{"jsonrpc":"2.0","id":` + string(msg.ID) + `,"result":` + result + `}`
		if rpcErr != "" {
			body = `{"jsonrpc":"2.0","id":` + string(msg.ID) + `,"error":` + rpcErr + `}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []sessionCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]sessionCall(nil), calls...)
	}
}

func sessionMethods(calls []sessionCall) []string {
	methods := make([]string, 0, len(calls))
	for _, c := range calls {
		methods = append(methods, c.method)
	}
	return methods
}

const echoResult = `{"content":[{"type":"text","text":"ok"}]}`

func TestStreamSession_DiscoverOpensStatelessSession(t *testing.T) {
	srv, calls := scriptedServer(t, func(method string) (string, string) {
		if method == string(mcp.MethodServerDiscover) {
			return `{"supportedVersions":["` + mcp.ProtocolVersion20260728 + `","` + mcp.ProtocolVersion20251125 + `"],"capabilities":{"tools":{}}}`, ""
		}
		return echoResult, ""
	})
	session := &streamSession{transport: newStreamableHTTP(srv.URL, http.DefaultTransport, nil)}
	info := mcp.Implementation{Name: "xkms-test", Version: "1.2.3"}
	require.NoError(t, session.initialize(context.Background(), info))

	result, err := session.CallTool(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "echo"}})
	require.NoError(t, err)
	require.Len(t, result.Content, 1)

	got := calls()
	assert.Equal(t, []string{string(mcp.MethodServerDiscover), string(mcp.MethodToolsCall)}, sessionMethods(got),
		"a stateless server is never sent initialize")
	for _, c := range got {
		assert.Equal(t, mcp.ProtocolVersion20260728, c.header.Get(headerProtocolVersion), c.method)
		assert.Equal(t, c.method, c.header.Get(mcp.HeaderMethod), c.method)
		var meta map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(c.params["_meta"], &meta), c.method)
		assert.JSONEq(t, `"`+mcp.ProtocolVersion20260728+`"`, string(meta[mcp.MetaKeyProtocolVersion]), c.method)
		assert.JSONEq(t, `{"name":"xkms-test","version":"1.2.3"}`, string(meta[mcp.MetaKeyClientInfo]), c.method)
		assert.Contains(t, meta, mcp.MetaKeyClientCapabilities, c.method)
	}
	assert.Equal(t, "echo", got[1].header.Get(mcp.HeaderName))
	assert.JSONEq(t, `"echo"`, string(got[1].params["name"]))
}

func TestStreamSession_LegacyServerGetsInitialize(t *testing.T) {
	for name, discover := range map[string]struct{ result, rpcErr string }{
		"discover unknown":    {rpcErr: `{"code":-32601,"message":"method not found"}`},
		"only legacy offered": {result: `{"supportedVersions":["` + mcp.ProtocolVersion20251125 + `"],"capabilities":{}}`},
	} {
		t.Run(name, func(t *testing.T) {
			srv, calls := scriptedServer(t, func(method string) (string, string) {
				switch method {
				case string(mcp.MethodServerDiscover):
					return discover.result, discover.rpcErr
				case string(mcp.MethodInitialize):
					return `{"protocolVersion":"` + mcp.ProtocolVersion20251125 + `","capabilities":{},"serverInfo":{"name":"legacy","version":"1"}}`, ""
				}
				return echoResult, ""
			})
			session := &streamSession{transport: newStreamableHTTP(srv.URL, http.DefaultTransport, nil)}
			require.NoError(t, session.initialize(context.Background(), mcp.Implementation{Name: "xkms-test", Version: "1"}))
			_, err := session.CallTool(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "echo"}})
			require.NoError(t, err)

			got := calls()
			assert.Equal(t, []string{
				string(mcp.MethodServerDiscover), string(mcp.MethodInitialize),
				methodNotificationInitialized, string(mcp.MethodToolsCall),
			}, sessionMethods(got))
			call := got[3]
			assert.Equal(t, mcp.ProtocolVersion20251125, call.header.Get(headerProtocolVersion))
			assert.NotContains(t, call.params, "_meta", "a legacy request carries no per-request metadata")
		})
	}
}
