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

package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newARISupportedServer builds a self-contained httptest ACME server whose
// directory advertises RFC 9773 "renewalInfo" support and whose new-order
// endpoint succeeds, so CreateOrderWithReplaces can be driven through its
// full success path (SupportsARI -> true, createOrderWithReplacesInternal ->
// AuthorizeOrder succeeds) rather than only the validation/error branches
// already covered by TestARICreateOrderWithReplaces.
func newARISupportedServer(t *testing.T, failNewOrder bool) *httptest.Server {
	t.Helper()

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "test-nonce-"+time.Now().String())

		switch r.URL.Path {
		case "/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"newNonce":    server.URL + "/new-nonce",
				"newAccount":  server.URL + "/new-account",
				"newOrder":    server.URL + "/new-order",
				"renewalInfo": server.URL + "/renewal-info",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-account":
			w.Header().Set("Location", server.URL+"/acct/1")
			w.WriteHeader(http.StatusOK) // account already exists; JWK-signed requests still work
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "valid",
				"contact": []string{"mailto:test@example.com"},
			})
		case "/new-order":
			if failNewOrder {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"type":   "urn:ietf:params:acme:error:malformed",
					"detail": "order rejected",
				})
				return
			}
			w.Header().Set("Location", server.URL+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "pending",
				"expires":     time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				"identifiers": []map[string]string{{"type": "dns", "value": "example.com"}},
				"authorizations": []string{
					server.URL + "/authz/1",
				},
				"finalize": server.URL + "/finalize/1",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server
}

func TestARICreateOrderWithReplaces_Success(t *testing.T) {
	server := newARISupportedServer(t, false)
	defer server.Close()

	client := createTestARIClientSimple(t, server.URL)

	order, err := client.CreateOrderWithReplaces(t.Context(), []string{"example.com"}, "YWJj.MTIz")
	require.NoError(t, err)
	require.NotNil(t, order)
	require.Equal(t, "pending", order.Status)
	require.Equal(t, server.URL+"/order/1", order.URI)
}

func TestARICreateOrderWithReplaces_SupportsARICheckFails(t *testing.T) {
	// A directory endpoint that is unreachable after the client is
	// constructed (server closed) forces the ARI capability check itself to
	// fail with a connection error, distinct from the "not supported"
	// (successful fetch, no renewalInfo field) branch already covered.
	server := newARISupportedServer(t, false)
	client := createTestARIClientSimple(t, server.URL)
	server.Close()

	_, err := client.CreateOrderWithReplaces(t.Context(), []string{"example.com"}, "YWJj.MTIz")
	require.Error(t, err)
}

func TestARICreateOrderWithReplaces_OrderCreationFails(t *testing.T) {
	// ARI is supported, but the new-order request itself is rejected by the
	// server, exercising the createOrderWithReplacesInternal error-wrapping
	// branch that TestARICreateOrderWithReplaces's validation-only subtests
	// never reach.
	server := newARISupportedServer(t, true)
	defer server.Close()

	client := createTestARIClientSimple(t, server.URL)

	_, err := client.CreateOrderWithReplaces(t.Context(), []string{"example.com"}, "YWJj.MTIz")
	require.Error(t, err)
	require.Contains(t, err.Error(), "order creation failed")
}
