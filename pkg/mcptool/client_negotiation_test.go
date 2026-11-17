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

// TestConnect_VersionRejectionOverHTTP400IsNotALegacyProbe: an MCP server
// rejects the protocol version of server/discover with HTTP 400 and a JSON-RPC
// UnsupportedProtocolVersionError. That identifies a modern server, so Connect
// must fail on the rejection and never fall back to the legacy initialize
// handshake.
func TestConnect_VersionRejectionOverHTTP400IsNotALegacyProbe(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		methods = append(methods, req.Method)
		mu.Unlock()

		rejection := mcp.UnsupportedProtocolVersionError{
			Version:   mcp.LATEST_PROTOCOL_VERSION,
			Supported: []string{"1999-01-01"},
		}.JSONRPCError()
		body, err := json.Marshal(map[string]any{
			"jsonrpc": rejection.JSONRPC,
			"id":      req.ID,
			"error":   rejection.Error,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = srv.Listener.Addr().String()
	c := NewClient(cfg)
	err := c.Connect(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1999-01-01", "the rejection's supported versions reach the caller")
	require.NoError(t, c.Close())

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, methods)
	assert.NotContains(t, methods, string(mcp.MethodInitialize), "a version rejection must not trigger the legacy handshake")
}
