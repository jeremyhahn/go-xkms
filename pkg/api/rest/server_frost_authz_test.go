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

package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// frostRoutePermissions ties every REST FROST route to the resource:action
// pair the RequirePermission decorator must demand. FROST is threshold
// signing, so these routes carry distributed key generation, share
// distribution, and signing; registering them without a decorator let any
// authenticated caller — including one holding no key grant at all — reach
// threshold key material.
//
// The pairs are the QUIC FROST handlers (pkg/api/quic/handlers_frost.go) and
// the MCP frost.* rpcMethods registrations (pkg/api/mcp/server.go) verbatim; a
// divergence here is a cross-transport authorization bug, not a test detail.
// They are spelled out literally rather than built from the
// auth.Resource*/auth.Action* constants because this table is the wire
// contract, so it must fail if a constant is retyped or repointed.
var frostRoutePermissions = []struct {
	name     string
	method   string
	path     string
	resource string
	action   string
}{
	{"generate key", http.MethodPost, "/api/v1/frost/keys", "keys", "create"},
	{"import key", http.MethodPost, "/api/v1/frost/keys/import", "keys", "import"},
	{"list keys", http.MethodGet, "/api/v1/frost/keys", "keys", "list"},
	{"get key", http.MethodGet, "/api/v1/frost/keys/k1", "keys", "get"},
	{"delete key", http.MethodDelete, "/api/v1/frost/keys/k1", "keys", "delete"},
	{"generate nonces", http.MethodPost, "/api/v1/frost/keys/k1/nonces", "keys", "sign"},
	{"sign round", http.MethodPost, "/api/v1/frost/keys/k1/sign", "keys", "sign"},
	{"aggregate", http.MethodPost, "/api/v1/frost/aggregate", "keys", "sign"},
	{"verify", http.MethodPost, "/api/v1/frost/verify", "keys", "verify"},
}

// TestFrostRoutes_RBACDenied proves every FROST route is behind the
// RequirePermission decorator: a caller whose every permission check is
// refused receives 403 from the middleware before the handler runs.
func TestFrostRoutes_RBACDenied(t *testing.T) {
	for _, tc := range frostRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			requireRBACDenied(t, tc.method, tc.path, nil)
		})
	}
}

// TestFrostRoutes_RBACRequiredPermission is the positive control the denial
// test needs to mean anything: a decorator that refused unconditionally would
// satisfy every 403 assertion above. It proves each FROST route demands
// exactly the cross-transport pair, and that a caller holding that grant
// passes the gate — the middleware admits the request to the handler instead
// of answering 401 or 403.
func TestFrostRoutes_RBACRequiredPermission(t *testing.T) {
	for _, tc := range frostRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			rbac := &recordingRBACClient{
				allowResource: tc.resource,
				allowAction:   tc.action,
			}

			server, err := NewServer(&Config{
				Authenticator:  auth.NewNoOpAuthenticator(),
				Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
				EnableRBAC:     true,
				RBACAuthorizer: auth.NewAuthorizer(rbac),
			})
			require.NoError(t, err)

			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(w, req)

			// The decorator must have asked the qrdb PDP for exactly the
			// cross-transport canonical pair.
			assert.Equal(t, tc.resource, rbac.gotResource, "decorator asked for wrong resource")
			assert.Equal(t, tc.action, rbac.gotAction, "decorator asked for wrong action")

			// The right grant passes the gate. The handler behind it may still
			// fail (no FROST backend is registered on this server), but never
			// with the middleware's 401/403.
			assert.NotEqual(t, http.StatusUnauthorized, w.Code)
			assert.NotEqual(t, http.StatusForbidden, w.Code)
		})
	}
}
