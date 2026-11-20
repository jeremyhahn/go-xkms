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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

const (
	mcpGoClientPkg    = "github.com/mark3labs/mcp-go/client"
	mcpGoTransportPkg = "github.com/mark3labs/mcp-go/client/transport"
)

// TestPackage_NoPathIntoMCPGoStreamableClient guards GO-2026-6911: mcp-go's
// client.Client calls its transport through an interface that, in a binary
// linking go-qrdb, can hold mcp-go's transport.StreamableHTTP (which follows
// a Location header with the bearer token). The package's production code
// therefore must not use mcp-go's client package at all, nor name the
// vulnerable transport type or its constructors.
func TestPackage_NoPathIntoMCPGoStreamableClient(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err, name)
		transportName := ""
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			require.NoError(t, err)
			assert.NotEqual(t, mcpGoClientPkg, path, "%s imports mcp-go's client package (GO-2026-6911)", name)
			if path == mcpGoTransportPkg {
				transportName = "transport"
				if imp.Name != nil {
					transportName = imp.Name.Name
				}
			}
		}
		if transportName == "" {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == transportName {
				switch sel.Sel.Name {
				case "StreamableHTTP", "NewStreamableHTTP", "StreamableHTTPCOption":
					t.Errorf("%s: %s names mcp-go's transport.%s (GO-2026-6911)", name, fset.Position(sel.Pos()), sel.Sel.Name)
				}
			}
			return true
		})
	}
}

// TestCall_RedirectOnToolCallNeverReachesAnotherOrigin: a server that
// completes the handshake and then answers a tools/call with a redirect must
// not get the call, the bearer token or the extra headers forwarded to the
// Location target.
func TestCall_RedirectOnToolCallNeverReachesAnotherOrigin(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var mu sync.Mutex
			var reached int
			var leaked []string
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				reached++
				for _, h := range []string{"Authorization", "X-Tenant-Secret"} {
					if v := r.Header.Get(h); v != "" {
						leaked = append(leaked, h+": "+v)
					}
				}
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()

			srv := mcpserver.NewMCPServer("mcptool-6911", "1.0.0")
			srv.AddTool(mcpgo.Tool{Name: ToolName("echo")}, func(context.Context, mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
				return mcpgo.NewToolResultText(`{}`), nil
			})
			mcpHandler := mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithEndpointPath(endpointPath))
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				var msg struct {
					Method string `json:"method"`
				}
				_ = json.Unmarshal(body, &msg)
				if msg.Method == string(mcpgo.MethodToolsCall) {
					w.Header().Set("Location", target.URL+endpointPath)
					w.WriteHeader(code)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				mcpHandler.ServeHTTP(w, r)
			}))
			defer origin.Close()

			cfg := transport.DefaultConfig()
			cfg.Address = origin.Listener.Addr().String()
			cfg.JWTToken = "tok-6911"
			cfg.Headers = map[string]string{"X-Tenant-Secret": "s3cret"}
			c := NewClient(cfg)
			require.NoError(t, c.Connect(context.Background()))
			defer func() { require.NoError(t, c.Close()) }()

			err := c.Call(context.Background(), "echo", nil, nil)
			require.Error(t, err, "a redirect is not a tool result")
			assert.True(t, errors.Is(err, ErrRedirectRefused), "got %v", err)

			mu.Lock()
			defer mu.Unlock()
			assert.Zero(t, reached, "no request may reach the redirect target")
			assert.Empty(t, leaked, "no credential header may reach the redirect target")
		})
	}
}
