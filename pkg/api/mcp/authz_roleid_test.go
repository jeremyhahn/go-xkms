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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// signCSRAs drives xkms.ca.sign-csr through the full MCP pipeline -- tenant
// scoping, the qrdb-backed permission gate, dispatch into
// XKMSService.SignCSR -- for a system-tenant identity holding roles.
func signCSRAs(t *testing.T, s *Server, roles ...string) *JSONRPCResponse {
	t.Helper()
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "caller",
		TenantID: qrdbsdk.SystemTenantID,
		Roles:    roles,
	})
	params, err := json.Marshal(map[string][]byte{"csr_pem": []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----")})
	require.NoError(t, err)
	return invokeRequest(s, ctx, &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.ca.sign-csr", Params: params, ID: 1})
}

// newSeededRBACServer returns an MCP server whose permission gate is the RBAC
// service of a first-boot-seeded qrdb node -- the production decision point --
// together with that node.
func newSeededRBACServer(t *testing.T) (*Server, *testutil.FirstBootNode) {
	t.Helper()
	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)

	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
		Authorizer:    auth.NewAuthorizer(n.Client().RBAC()),
		EnableRBAC:    true,
	})
	require.NoError(t, err)
	return server, n
}

// TestSignCSR_SeededAdminRoleIDAdmitted proves the CSR-signing site admits an
// identity carrying the Admin role by the identifier qrdb persisted it under:
// the gate passes and the request reaches the servicer, which answers from
// the (unconfigured) CA rather than with a permission denial.
func TestSignCSR_SeededAdminRoleIDAdmitted(t *testing.T) {
	s, n := newSeededRBACServer(t)
	adminID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)

	resp := signCSRAs(t, s, adminID)
	require.NotNil(t, resp.Error, "the fixture has no CA, so an admitted request fails in the servicer")
	assert.NotEqual(t, ErrCodeForbidden, resp.Error.Code, "Admin must pass certs:issue")
	assert.Equal(t, xkms.ErrNotConfigured.Error(), resp.Error.Message,
		"the admitted request must reach XKMSService.SignCSR, which reports the missing CA")
}

// TestSignCSR_NonAdminRoleIDRefused proves roles without certs:issue are
// refused at the gate.
func TestSignCSR_NonAdminRoleIDRefused(t *testing.T) {
	s, n := newSeededRBACServer(t)

	for _, roleName := range []string{qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser, qrdbsdk.RoleNameAuditor} {
		id, err := n.RoleID(qrdbsdk.SystemTenantID, roleName)
		require.NoError(t, err)

		resp := signCSRAs(t, s, id)
		require.NotNil(t, resp.Error, roleName)
		assert.Equal(t, ErrCodeForbidden, resp.Error.Code, roleName)
	}
}

// TestSignCSR_RoleNameConfersNothing is the #1074 regression at the
// transport: an identity whose Roles spell "admin" -- the shape of an
// unverified token claim -- holds no grant and is refused.
func TestSignCSR_RoleNameConfersNothing(t *testing.T) {
	s, _ := newSeededRBACServer(t)

	resp := signCSRAs(t, s, qrdbsdk.RoleNameAdmin)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeForbidden, resp.Error.Code)
}
