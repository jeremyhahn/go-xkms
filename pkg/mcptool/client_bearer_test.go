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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestConnect_SendsBearerToken proves the configured JWT reaches the server
// as an Authorization header on the MCP session's HTTP requests.
func TestConnect_SendsBearerToken(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := transport.DefaultConfig()
	cfg.Address = srv.Listener.Addr().String()
	cfg.JWTToken = "tok-xyz"
	c := NewClient(cfg)
	require.Error(t, c.Connect(context.Background()), "the server refuses the session")

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, seen)
	assert.Equal(t, "Bearer tok-xyz", seen[0])
}

func TestRequestHeaders(t *testing.T) {
	cfg := transport.DefaultConfig()
	assert.Empty(t, NewClient(cfg).requestHeaders(), "no token, no headers: nothing is invented")

	cfg.Headers = map[string]string{"X-Trace": "1"}
	cfg.JWTToken = "t"
	assert.Equal(t, map[string]string{"X-Trace": "1", "Authorization": "Bearer t"}, NewClient(cfg).requestHeaders())
}
