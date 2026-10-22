// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// sshRoutePermissions ties every REST SSH route to the ssh:* action its
// RequirePermission decorator must demand (go-xkms#1230). Before, every route
// -- delete and import included -- demanded the single blanket ssh:use, so a
// grant meant for signing also deleted keys and planted authorized_keys
// entries. The read/write/delete pairs are the MCP ssh.* rpcMethods
// (pkg/api/mcp/authz.go) and the gRPC qrdb.v1.permission options verbatim;
// signing is ssh:write, as on gRPC and MCP. The pairs are spelled out literally rather than built
// from the auth constants because this table is the wire contract.
var sshRoutePermissions = []struct {
	name   string
	method string
	path   string
	action string
}{
	{"generate key", http.MethodPost, "/xkms/v1/ssh/keys", "write"},
	{"import key", http.MethodPost, "/xkms/v1/ssh/keys/import", "write"},
	{"list keys", http.MethodGet, "/xkms/v1/ssh/keys", "read"},
	{"get key", http.MethodGet, "/xkms/v1/ssh/keys/user/alice/k", "read"},
	{"delete key", http.MethodDelete, "/xkms/v1/ssh/keys/user/alice/k", "delete"},
	{"export public", http.MethodGet, "/xkms/v1/ssh/keys/user/alice/k/public", "read"},
	{"sign", http.MethodPost, "/xkms/v1/ssh/keys/user/alice/k/sign", "write"},
	{"add known host", http.MethodPost, "/xkms/v1/ssh/known-hosts", "write"},
	{"list known hosts", http.MethodGet, "/xkms/v1/ssh/known-hosts", "read"},
	{"remove known host", http.MethodDelete, "/xkms/v1/ssh/known-hosts/h.example.com", "delete"},
	{"verify known host", http.MethodPost, "/xkms/v1/ssh/known-hosts/h.example.com/verify", "read"},
	{"add authorized key", http.MethodPost, "/xkms/v1/ssh/authorized-keys", "write"},
	{"list authorized keys", http.MethodGet, "/xkms/v1/ssh/authorized-keys", "read"},
	{"get authorized key", http.MethodGet, "/xkms/v1/ssh/authorized-keys/user/alice/e", "read"},
	{"remove authorized key", http.MethodDelete, "/xkms/v1/ssh/authorized-keys/user/alice/e", "delete"},
	{"emit authorized line", http.MethodPost, "/xkms/v1/ssh/authorized-keys/emit", "read"},
	{"verify authorized key", http.MethodPost, "/xkms/v1/ssh/authorized-keys/verify", "read"},
}

// sshActions are every action of the ssh resource family.
var sshActions = []string{"read", "write", "delete", "use"}

// grantSetRBACClient admits exactly the ssh actions it holds and records
// every pair it is asked for.
type grantSetRBACClient struct {
	held  map[string]bool
	asked []string
}

func (c *grantSetRBACClient) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	c.asked = append(c.asked, resource+":"+action)
	if resource == "ssh" && c.held[action] {
		return nil
	}
	return errors.New("permission denied")
}

func (c *grantSetRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("not implemented")
}

func (c *grantSetRBACClient) ListOwnPermissions(ctx context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return c.ListPermissions(ctx, nil)
}

// serveSSHRouteWithGrants sends one request to a full REST server whose
// caller holds exactly held, and returns the status and the RBAC client.
func serveSSHRouteWithGrants(t *testing.T, method, path string, held ...string) (int, *grantSetRBACClient) {
	t.Helper()
	rbac := &grantSetRBACClient{held: map[string]bool{}}
	for _, action := range held {
		rbac.held[action] = true
	}
	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(rbac),
		SSHClient:      newMockSSHClient(),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(method, path, http.NoBody)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	return w.Code, rbac
}

// TestSSHRoutes_RBACDenied proves every SSH route is behind the
// RequirePermission decorator: a caller holding no grant gets 403.
func TestSSHRoutes_RBACDenied(t *testing.T) {
	for _, tc := range sshRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := serveSSHRouteWithGrants(t, tc.method, tc.path)
			assert.Equal(t, http.StatusForbidden, code)
		})
	}
}

// TestSSHRoutes_RBACRequiredPermission proves each SSH route demands exactly
// its ssh:* pair, and that holding that pair alone passes the gate.
func TestSSHRoutes_RBACRequiredPermission(t *testing.T) {
	for _, tc := range sshRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			code, rbac := serveSSHRouteWithGrants(t, tc.method, tc.path, tc.action)
			assert.Contains(t, rbac.asked, "ssh:"+tc.action, "decorator asked for the wrong pair")
			assert.NotEqual(t, http.StatusUnauthorized, code)
			assert.NotEqual(t, http.StatusForbidden, code)
		})
	}
}

// TestSSHRoutes_OtherSSHGrantsDenied proves no ssh:* grant stands in for
// another: a caller holding every ssh action except the route's own is
// refused. This is the regression the blanket ssh:use gate hid -- a signing
// grant that also deleted keys and authorized foreign logins.
func TestSSHRoutes_OtherSSHGrantsDenied(t *testing.T) {
	for _, tc := range sshRoutePermissions {
		t.Run(tc.name, func(t *testing.T) {
			others := make([]string, 0, len(sshActions)-1)
			for _, action := range sshActions {
				if action != tc.action {
					others = append(others, action)
				}
			}
			code, _ := serveSSHRouteWithGrants(t, tc.method, tc.path, others...)
			assert.Equal(t, http.StatusForbidden, code)
		})
	}
}

// TestSSHRoutes_TableCoversEveryRoute proves the table above is the whole
// SSH surface, so a new route cannot ship without a pinned permission.
func TestSSHRoutes_TableCoversEveryRoute(t *testing.T) {
	var registered int
	for _, spec := range Routes() {
		if spec.Group != GroupSSH {
			continue
		}
		registered++
		assert.Equal(t, RouteAuthPermission, spec.Auth, "%s %s must be permission-gated", spec.Method, spec.Pattern)
		assert.Equal(t, auth.ResourceSSH, spec.Resource, "%s %s", spec.Method, spec.Pattern)
		assert.Contains(t, sshActions, spec.Action, "%s %s gates on a non-ssh action", spec.Method, spec.Pattern)
	}
	assert.Equal(t, len(sshRoutePermissions), registered, "every SSH route must appear in sshRoutePermissions")
}
