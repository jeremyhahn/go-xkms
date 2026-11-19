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
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestConnect_NeverFollowsRedirectToAnotherOrigin covers GO-2026-6911: an MCP
// server that answers with a Location header must not make the client send a
// request, or its bearer token, to the origin the header names.
func TestConnect_NeverFollowsRedirectToAnotherOrigin(t *testing.T) {
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
				if auth := r.Header.Get("Authorization"); auth != "" {
					leaked = append(leaked, auth)
				}
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()

			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL+endpointPath)
				w.WriteHeader(code)
			}))
			defer origin.Close()

			cfg := transport.DefaultConfig()
			cfg.Address = origin.Listener.Addr().String()
			cfg.JWTToken = "tok-redirect"
			c := NewClient(cfg)
			require.Error(t, c.Connect(context.Background()), "a redirect is not an MCP response")
			require.NoError(t, c.Close())

			mu.Lock()
			defer mu.Unlock()
			assert.Zero(t, reached, "no request may reach the redirect target")
			assert.Empty(t, leaked, "no Authorization header may reach the redirect target")
		})
	}
}
