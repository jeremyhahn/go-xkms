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

// versionRejectBody is a JSON-RPC UNSUPPORTED_PROTOCOL_VERSION error for id.
func versionRejectBody(t *testing.T, id json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": mcp.JSONRPC_VERSION,
		"id":      id,
		"error": map[string]any{
			"code":    mcp.UNSUPPORTED_PROTOCOL_VERSION,
			"message": "unsupported protocol version",
			"data": mcp.UnsupportedProtocolVersionData{
				Supported: []string{"1999-01-01"},
				Requested: "requested",
			},
		},
	})
	require.NoError(t, err)
	return body
}

// A modern server that rejects the protocol version answers with HTTP 400 and
// a JSON-RPC error that lists the versions it supports. The client must see
// that typed rejection and must not fall back to the legacy initialize
// handshake.
func TestConnect_VersionRejectedWithHTTP400IsNotALegacyServer(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		methods = append(methods, msg.Method)
		mu.Unlock()
		if len(msg.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(versionRejectBody(t, msg.ID))
	}))
	defer server.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = server.Listener.Addr().String()
	c := NewClient(cfg)
	err := c.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1999-01-01", "the server's supported versions reach the caller")
	require.NoError(t, c.Close())

	mu.Lock()
	defer mu.Unlock()
	// Sessions open with a bare initialize (row 11, #2183): the rejection
	// ends Connect, with no second handshake.
	assert.Equal(t, []string{string(mcp.MethodInitialize)}, methods, "a version rejection ends the handshake")
}

// The transport returns an HTTP 400 JSON-RPC error response as the response,
// with its error details, and keeps an HTTP 400 without one an HTTP error.
func TestStreamableHTTP_HTTP400JSONRPCError(t *testing.T) {
	cases := []struct {
		name      string
		body      func(id json.RawMessage) []byte
		ctype     string
		wantError bool
	}{
		{name: "jsonrpc error", ctype: contentTypeJSON, body: func(id json.RawMessage) []byte { return versionRejectBody(t, id) }},
		{name: "plain text", ctype: "text/plain", wantError: true, body: func(json.RawMessage) []byte { return []byte("bad request") }},
		{name: "result not error", ctype: contentTypeJSON, wantError: true, body: func(id json.RawMessage) []byte {
			return []byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{}}`)
		}},
		{name: "wrong id", ctype: contentTypeJSON, wantError: true, body: func(json.RawMessage) []byte { return versionRejectBody(t, json.RawMessage(`999`)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var msg struct {
					ID json.RawMessage `json:"id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&msg)
				w.Header().Set("Content-Type", tc.ctype)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(tc.body(msg.ID))
			}))
			defer server.Close()

			s := newStreamableHTTP(server.URL, http.DefaultTransport, nil)
			defer func() { _ = s.Close() }()
			resp, err := s.SendRequest(context.Background(), initRequest())
			if tc.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "HTTP status 400")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp.Error)
			assert.Equal(t, mcp.UNSUPPORTED_PROTOCOL_VERSION, resp.Error.Code)
			assert.Contains(t, string(mustJSON(t, resp.Error.Data)), "1999-01-01")
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
