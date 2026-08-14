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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// barrierRoutePermissions ties every REST barrier route to the go-qrdb
// resource:action pair the RequirePermission decorator must demand. The pairs
// are the MCP barrier.* methodPermissions map (pkg/api/mcp/authz.go) and the
// QUIC barrier handlers verbatim; a divergence here is a cross-transport
// authorization bug, not a test detail. The pairs are spelled out literally
// rather than built from the auth.Resource*/auth.Action* constants: this table
// is the wire contract, so it must fail if a constant is retyped or repointed.
var barrierRoutePermissions = []struct {
	name     string
	method   string
	path     string
	resource string
	action   string
}{
	{"initialize", http.MethodPost, "/api/v1/barrier/initialize", "seal", "bootstrap"},
	{"unseal", http.MethodPost, "/api/v1/barrier/unseal", "seal", "unseal"},
	{"seal", http.MethodPost, "/api/v1/barrier/seal", "seal", "seal"},
	{"status", http.MethodGet, "/api/v1/barrier/status", "seal", "status"},
	{"shamir initialize", http.MethodPost, "/api/v1/barrier/shamir/initialize", "seal", "initialize_shamir"},
	{"shamir unseal-share", http.MethodPost, "/api/v1/barrier/shamir/unseal-share", "barrier", "unseal-share"},
	{"shamir unseal-shares", http.MethodPost, "/api/v1/barrier/shamir/unseal-shares", "seal", "unseal"},
	{"rekey", http.MethodPost, "/api/v1/barrier/rekey", "seal", "rekey"},
	{"recovery generate", http.MethodPost, "/api/v1/barrier/recovery/generate", "seal", "generate_recovery"},
	{"recovery recover", http.MethodPost, "/api/v1/barrier/recovery/recover", "seal", "recover_with_keys"},
	{"recovery delete keys", http.MethodDelete, "/api/v1/barrier/recovery/keys", "seal", "generate_recovery"},
	{"recovery root-token", http.MethodPost, "/api/v1/barrier/recovery/root-token", "seal", "rotate_root_key"},
	{"enable-encryption", http.MethodPost, "/api/v1/barrier/enable-encryption", "seal", "enable_encryption"},
}

// recordingRBACClient implements qrdbtransport.RBACClient, records the
// resource:action pair it was asked to authorize, and allows exactly one
// configured pair. Driving a request through the real chi router with this
// client proves both that the RequirePermission decorator is attached to the
// route and that it demands the expected permission — a decorator asking for
// the wrong pair records the mismatch and is denied.
type recordingRBACClient struct {
	allowResource string
	allowAction   string

	gotResource string
	gotAction   string
}

func (c *recordingRBACClient) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	c.gotResource = resource
	c.gotAction = action
	if resource == c.allowResource && action == c.allowAction {
		return nil
	}
	return errors.New("permission denied")
}

func (c *recordingRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("not implemented")
}

// TestBarrierRoutes_RBACDenied proves every barrier route is behind the
// RequirePermission decorator: a caller whose every permission check is
// refused receives 403 from the middleware before the handler runs.
func TestBarrierRoutes_RBACDenied(t *testing.T) {
	for _, tc := range barrierRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			requireRBACDenied(t, tc.method, tc.path, nil)
		})
	}
}

// TestBarrierRoutes_RBACRequiredPermission proves each barrier route demands
// exactly the resource:action pair the MCP and QUIC transports gate the
// equivalent verb with, and that a caller holding that grant passes the gate
// (the middleware admits the request to the handler instead of answering 401
// or 403).
func TestBarrierRoutes_RBACRequiredPermission(t *testing.T) {
	for _, tc := range barrierRoutePermissions {
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
			// fail (no barrier is configured on this server), but never with
			// the middleware's 401/403.
			assert.NotEqual(t, http.StatusUnauthorized, w.Code)
			assert.NotEqual(t, http.StatusForbidden, w.Code)
		})
	}
}

// TestNewServer_RBACAuthorizerConstructionAssert exercises the fail-closed
// construction contract: EnableRBAC demands a usable authorizer, while RBAC
// disabled is the documented open-gate configuration regardless of the
// authorizer field.
func TestNewServer_RBACAuthorizerConstructionAssert(t *testing.T) {
	newConfig := func() *Config {
		return &Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		}
	}

	t.Run("rbac enabled with nil authorizer is refused", func(t *testing.T) {
		cfg := newConfig()
		cfg.EnableRBAC = true

		server, err := NewServer(cfg)
		require.ErrorIs(t, err, ErrAuthorizerRequired)
		assert.Nil(t, server)
	})

	t.Run("rbac enabled with disabled authorizer is refused", func(t *testing.T) {
		cfg := newConfig()
		cfg.EnableRBAC = true
		// auth.NewAuthorizer(nil) is Enabled() == false: it has no backing
		// qrdb RBAC client and would allow every request.
		cfg.RBACAuthorizer = auth.NewAuthorizer(nil)

		server, err := NewServer(cfg)
		require.ErrorIs(t, err, ErrAuthorizerRequired)
		assert.Nil(t, server)
	})

	t.Run("rbac disabled with nil authorizer constructs open gate", func(t *testing.T) {
		cfg := newConfig()

		server, err := NewServer(cfg)
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.Nil(t, server.rbacMiddleware)
	})

	t.Run("rbac enabled with usable authorizer wires middleware", func(t *testing.T) {
		cfg := newConfig()
		cfg.EnableRBAC = true
		cfg.RBACAuthorizer = auth.NewAuthorizer(&recordingRBACClient{})

		server, err := NewServer(cfg)
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.NotNil(t, server.rbacMiddleware)
	})
}
