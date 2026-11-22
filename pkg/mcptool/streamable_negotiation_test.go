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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// negotiationRecord is what the controlled server received in one HTTP
// request: the HTTP method, the JSON-RPC method and id, the session and
// protocol version headers, the _meta protocol version, and the params.
type negotiationRecord struct {
	httpMethod    string
	method        string
	id            json.RawMessage
	sessionID     string
	headerVersion string
	metaVersion   string
	params        json.RawMessage
}

// negotiationServer starts an httptest server that records every request
// and answers each JSON-RPC request with reply. A nil reply body answers
// 202 Accepted (notifications). Non-POST requests are recorded and answered
// 405.
func negotiationServer(t *testing.T, reply func(rec negotiationRecord, w http.ResponseWriter)) (*httptest.Server, func() []negotiationRecord) {
	t.Helper()
	var mu sync.Mutex
	var records []negotiationRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := negotiationRecord{
			httpMethod:    r.Method,
			sessionID:     r.Header.Get(headerSessionID),
			headerVersion: r.Header.Get(headerProtocolVersion),
		}
		if r.Method != http.MethodPost {
			mu.Lock()
			records = append(records, rec)
			mu.Unlock()
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rec.method, rec.id, rec.params = msg.Method, msg.ID, msg.Params
		var meta struct {
			Meta map[string]any `json:"_meta"`
		}
		if len(msg.Params) > 0 && json.Unmarshal(msg.Params, &meta) == nil {
			if v, ok := meta.Meta[mcp.MetaKeyProtocolVersion].(string); ok {
				rec.metaVersion = v
			}
		}
		mu.Lock()
		records = append(records, rec)
		mu.Unlock()
		if len(msg.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		reply(rec, w)
	}))
	t.Cleanup(server.Close)
	return server, func() []negotiationRecord {
		mu.Lock()
		defer mu.Unlock()
		return append([]negotiationRecord(nil), records...)
	}
}

func writeRPCResult(t *testing.T, w http.ResponseWriter, id json.RawMessage, result any) {
	t.Helper()
	w.Header().Set("Content-Type", contentTypeJSON)
	_, _ = w.Write(mustJSON(t, map[string]any{"jsonrpc": mcp.JSONRPC_VERSION, "id": id, "result": result}))
}

func writeRPCError(t *testing.T, w http.ResponseWriter, status int, id json.RawMessage, rpcErr map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(mustJSON(t, map[string]any{"jsonrpc": mcp.JSONRPC_VERSION, "id": id, "error": rpcErr}))
}

func toolTextResult(text string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

// postRecords drops the non-POST requests (the DELETE that Close sends).
func postRecords(records []negotiationRecord) []negotiationRecord {
	var out []negotiationRecord
	for _, r := range records {
		if r.httpMethod == http.MethodPost {
			out = append(out, r)
		}
	}
	return out
}

func connectTo(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	cfg := transport.DefaultConfig()
	cfg.Address = server.Listener.Addr().String()
	c := NewClient(cfg)
	require.NoError(t, c.Connect(context.Background()))
	return c
}

// TestConnect_RetriesDiscoverAtVersionTheServerNames covers the modern retry:
// the server rejects the first server/discover with
// UNSUPPORTED_PROTOCOL_VERSION naming the versions it supports, the client
// retries at the mutually supported modern version, and every later request
// carries that version in Mcp-Protocol-Version and _meta.
func TestConnect_RetriesDiscoverAtVersionTheServerNames(t *testing.T) {
	// The server supports only a modern version newer than the one Connect
	// sends first, so the retry must switch versions. The SDK knows a single
	// modern version, so the test registers a second one for its duration
	// (no test in this package runs in parallel).
	const serverVersion = "2026-12-01"
	require.NotEqual(t, serverVersion, mcp.LATEST_PROTOCOL_VERSION)
	require.True(t, mcp.IsModernProtocol(serverVersion))
	saved := mcp.ValidProtocolVersions
	mcp.ValidProtocolVersions = append([]string{serverVersion}, saved...)
	t.Cleanup(func() { mcp.ValidProtocolVersions = saved })

	reject := func(rec negotiationRecord, w http.ResponseWriter) {
		writeRPCError(t, w, http.StatusBadRequest, rec.id, map[string]any{
			"code":    mcp.UNSUPPORTED_PROTOCOL_VERSION,
			"message": "unsupported protocol version",
			"data": mcp.UnsupportedProtocolVersionData{
				Supported: []string{serverVersion},
				Requested: rec.metaVersion,
			},
		})
	}
	server, records := negotiationServer(t, func(rec negotiationRecord, w http.ResponseWriter) {
		if rec.metaVersion != serverVersion || rec.headerVersion != serverVersion {
			reject(rec, w)
			return
		}
		switch rec.method {
		case string(mcp.MethodServerDiscover):
			writeRPCResult(t, w, rec.id, map[string]any{
				"supportedVersions": []string{serverVersion},
				"capabilities":      map[string]any{},
			})
		case string(mcp.MethodToolsCall):
			writeRPCResult(t, w, rec.id, toolTextResult(`{"ok":true}`))
		default:
			writeRPCError(t, w, http.StatusOK, rec.id, map[string]any{"code": mcp.METHOD_NOT_FOUND, "message": "method not found"})
		}
	})

	c := connectTo(t, server)
	var out struct {
		OK bool `json:"ok"`
	}
	require.NoError(t, c.Call(context.Background(), "health", nil, &out))
	assert.True(t, out.OK)
	require.NoError(t, c.Close())

	got := postRecords(records())
	require.Len(t, got, 3, "discover, retried discover, tools/call")
	methods := []string{got[0].method, got[1].method, got[2].method}
	assert.Equal(t, []string{string(mcp.MethodServerDiscover), string(mcp.MethodServerDiscover), string(mcp.MethodToolsCall)}, methods)
	assert.NotContains(t, methods, string(mcp.MethodInitialize), "a modern retry must not fall back to the legacy handshake")
	assert.Equal(t, mcp.LATEST_PROTOCOL_VERSION, got[0].metaVersion, "the first discover carries the client's preferred version")
	for i, r := range got[1:] {
		assert.Equal(t, serverVersion, r.metaVersion, "request %d (%s) _meta protocol version", i+1, r.method)
		assert.Equal(t, serverVersion, r.headerVersion, "request %d (%s) Mcp-Protocol-Version header", i+1, r.method)
	}
}

// legacyReply answers server/discover with METHOD_NOT_FOUND (a legacy
// server), initialize with a legacy result and the given session ID, and
// tools/call with toolText.
func legacyReply(t *testing.T, sessionID, toolText string) func(rec negotiationRecord, w http.ResponseWriter) {
	return func(rec negotiationRecord, w http.ResponseWriter) {
		switch rec.method {
		case string(mcp.MethodServerDiscover):
			writeRPCError(t, w, http.StatusOK, rec.id, map[string]any{"code": mcp.METHOD_NOT_FOUND, "message": "method not found"})
		case string(mcp.MethodInitialize):
			if sessionID != "" {
				w.Header().Set(headerSessionID, sessionID)
			}
			writeRPCResult(t, w, rec.id, map[string]any{
				"protocolVersion": mcp.LATEST_LEGACY_PROTOCOL_VERSION,
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "legacy", "version": "1"},
			})
		case string(mcp.MethodToolsCall):
			writeRPCResult(t, w, rec.id, toolTextResult(toolText))
		default:
			writeRPCError(t, w, http.StatusOK, rec.id, map[string]any{"code": mcp.METHOD_NOT_FOUND, "message": "method not found"})
		}
	}
}

// TestConnect_LegacyServerGetsInitializeThenInitialized covers the legacy
// fallback: a server that does not know server/discover gets the initialize
// handshake at the latest legacy version, then notifications/initialized.
func TestConnect_LegacyServerGetsInitializeThenInitialized(t *testing.T) {
	server, records := negotiationServer(t, legacyReply(t, "", "{}"))

	c := connectTo(t, server)
	require.NoError(t, c.Close())

	got := postRecords(records())
	require.Len(t, got, 3, "discover, initialize, initialized")
	assert.Equal(t, string(mcp.MethodServerDiscover), got[0].method)
	assert.Equal(t, string(mcp.MethodInitialize), got[1].method)
	assert.Equal(t, string(mcp.MethodNotificationInitialized), got[2].method)
	assert.Empty(t, got[2].id, "notifications/initialized is a notification")

	var initParams struct {
		ProtocolVersion string             `json:"protocolVersion"`
		ClientInfo      mcp.Implementation `json:"clientInfo"`
	}
	require.NoError(t, json.Unmarshal(got[1].params, &initParams))
	assert.Equal(t, mcp.LATEST_LEGACY_PROTOCOL_VERSION, initParams.ProtocolVersion)
	assert.Equal(t, clientName, initParams.ClientInfo.Name)
	assert.Empty(t, got[1].headerVersion, "initialize goes out before a version is negotiated")
	assert.Empty(t, got[1].metaVersion, "legacy initialize carries no _meta protocol version")
	assert.Equal(t, mcp.LATEST_LEGACY_PROTOCOL_VERSION, got[2].headerVersion, "initialized carries the negotiated version")
}

// TestConnect_SessionIDSentOnEveryLaterMessage covers session ID
// propagation: the Mcp-Session-Id the server returns on initialize is sent
// on the initialized notification, on tools/call and on the DELETE that
// ends the session.
func TestConnect_SessionIDSentOnEveryLaterMessage(t *testing.T) {
	const sessionID = "session-6911"
	server, records := negotiationServer(t, legacyReply(t, sessionID, "{}"))

	c := connectTo(t, server)
	require.NoError(t, c.Call(context.Background(), "health", nil, nil))
	require.NoError(t, c.Close())

	got := records()
	require.GreaterOrEqual(t, len(got), 4, "discover, initialize, initialized, tools/call")
	assert.Equal(t, string(mcp.MethodServerDiscover), got[0].method)
	assert.Empty(t, got[0].sessionID, "no session before initialize")
	assert.Equal(t, string(mcp.MethodInitialize), got[1].method)
	assert.Empty(t, got[1].sessionID, "no session before initialize")
	for _, r := range got[2:] {
		assert.Equal(t, sessionID, r.sessionID, "%s %s carries the session ID", r.httpMethod, r.method)
	}
	assert.Equal(t, string(mcp.MethodNotificationInitialized), got[2].method)
	assert.Equal(t, string(mcp.MethodToolsCall), got[3].method)
}

// TestCall_ToolsCallAfterNegotiationDecodesResult covers a tools/call after
// the modern negotiation: the server receives the tool name and arguments
// at the negotiated version, and the client decodes the text result.
func TestCall_ToolsCallAfterNegotiationDecodesResult(t *testing.T) {
	server, records := negotiationServer(t, func(rec negotiationRecord, w http.ResponseWriter) {
		switch rec.method {
		case string(mcp.MethodServerDiscover):
			writeRPCResult(t, w, rec.id, map[string]any{
				"supportedVersions": []string{mcp.LATEST_PROTOCOL_VERSION},
				"capabilities":      map[string]any{},
			})
		case string(mcp.MethodToolsCall):
			writeRPCResult(t, w, rec.id, toolTextResult(`{"name":"xkms","count":7}`))
		default:
			writeRPCError(t, w, http.StatusOK, rec.id, map[string]any{"code": mcp.METHOD_NOT_FOUND, "message": "method not found"})
		}
	})

	c := connectTo(t, server)
	var out struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	require.NoError(t, c.Call(context.Background(), "keys.list", map[string]string{"filter": "rsa"}, &out))
	assert.Equal(t, "xkms", out.Name)
	assert.Equal(t, 7, out.Count)
	require.NoError(t, c.Close())

	got := postRecords(records())
	require.Len(t, got, 2, "discover, tools/call")
	assert.Equal(t, string(mcp.MethodServerDiscover), got[0].method)
	call := got[1]
	assert.Equal(t, string(mcp.MethodToolsCall), call.method)
	assert.NotEmpty(t, call.id, "tools/call is a request")
	assert.Equal(t, mcp.LATEST_PROTOCOL_VERSION, call.headerVersion)
	assert.Equal(t, mcp.LATEST_PROTOCOL_VERSION, call.metaVersion)

	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	require.NoError(t, json.Unmarshal(call.params, &params))
	assert.Equal(t, ToolName("keys.list"), params.Name)
	assert.JSONEq(t, `{"filter":"rsa"}`, params.Arguments["params_json"])
}
