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

// server_route_authz_test.go pins the permission of every REST route that
// go-xkms#780 moved off the session-only tier (authenticated, no RBAC check)
// onto the RequirePermission decorator, end to end through the real chi
// router, and pins the set of routes that deliberately remain session-only.
package rest

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// gatedRoute ties one REST route to the go-qrdb resource:action pair its
// RequirePermission decorator must demand.
type gatedRoute struct {
	method   string
	path     string
	resource string
	action   string
}

// gatedRoutePermissions is the wire contract for the go-xkms#780 routes. Each
// pair is the one pkg/api/grpc authorizes (and the xkms.proto
// qrdb.v1.permission option declares) for the same operation, which is also
// the MCP methodPermissions entry; a divergence here is a cross-transport
// authorization bug, not a test detail. Pairs are spelled out literally rather
// than built from the auth constants so the table fails if a constant is
// retyped or repointed.
var gatedRoutePermissions = []gatedRoute{
	// PIN management — service_barrier_pin.go.
	{http.MethodPost, "/api/v1/pin/so/set", "pin", "write"},
	{http.MethodPost, "/api/v1/pin/user/set", "pin", "write"},
	{http.MethodPost, "/api/v1/pin/so/change", "pin", "write"},
	{http.MethodPost, "/api/v1/pin/user/change", "pin", "write"},
	{http.MethodPost, "/api/v1/pin/so/verify", "pin", "read"},
	{http.MethodPost, "/api/v1/pin/user/verify", "pin", "read"},
	{http.MethodGet, "/api/v1/pin/lockout", "pin", "read"},
	{http.MethodPost, "/api/v1/pin/lockout/reset", "pin", "write"},

	// PIV — service_piv.go.
	{http.MethodGet, "/api/v1/piv/slots", "piv", "read"},
	{http.MethodGet, "/api/v1/piv/slots/9a/certificate", "piv", "read"},
	{http.MethodPost, "/api/v1/piv/slots/9a/certificate", "piv", "write"},
	{http.MethodDelete, "/api/v1/piv/slots/9a/certificate", "piv", "delete"},
	{http.MethodPost, "/api/v1/piv/slots/9a/generate", "piv", "write"},
	{http.MethodPost, "/api/v1/piv/slots/9a/import", "piv", "write"},
	{http.MethodGet, "/api/v1/piv/slots/9a/export", "piv", "read"},
	{http.MethodPost, "/api/v1/piv/slots/9a/csr", "piv", "use"},

	// CA — service_ca.go, service_ca_tcg.go, service_ca_bundle.go.
	{http.MethodGet, "/api/v1/ca/bundle", "certs", "read"},
	{http.MethodGet, "/api/v1/ca/certificate", "certs", "read"},
	{http.MethodPost, "/api/v1/ca/sign-csr", "certs", "generate"},
	{http.MethodPost, "/api/v1/ca/issue", "certs", "generate"},
	{http.MethodPost, "/api/v1/ca/revoke", "certs", "revoke"},
	{http.MethodPost, "/api/v1/ca/crl", "certs", "read"},
	{http.MethodGet, "/api/v1/ca/revoked/01", "certs", "read"},
	{http.MethodPost, "/api/v1/ca/tcg/ek", "certs", "generate"},
	{http.MethodPost, "/api/v1/ca/tcg/ak", "certs", "generate"},
	{http.MethodPost, "/api/v1/ca/tcg/sign-csr", "certs", "generate"},
	{http.MethodPost, "/api/v1/ca/tcg/enroll", "certs", "generate"},

	// Custodian groups — service_custodian_share_tenant.go.
	{http.MethodPost, "/api/v1/custodian/groups/", "ceremony", "enroll_custodian"},
	{http.MethodGet, "/api/v1/custodian/groups/", "ceremony", "status"},
	{http.MethodGet, "/api/v1/custodian/groups/g1", "ceremony", "status"},
	{http.MethodDelete, "/api/v1/custodian/groups/g1", "ceremony", "revoke_custodian"},
	{http.MethodPost, "/api/v1/custodian/groups/g1/members", "ceremony", "enroll_custodian"},
	{http.MethodDelete, "/api/v1/custodian/groups/g1/members/u1", "ceremony", "revoke_custodian"},
	{http.MethodPost, "/api/v1/custodian/groups/g1/distribute", "ceremony", "claim_share_begin"},

	// Shares — service_custodian_share_tenant.go.
	{http.MethodPost, "/api/v1/shares/submit", "barrier", "unseal-share"},
	{http.MethodGet, "/api/v1/shares/", "ceremony", "status"},
	{http.MethodGet, "/api/v1/shares/srv/g1/1", "ceremony", "status"},
	{http.MethodDelete, "/api/v1/shares/srv/g1/1", "barrier", "unseal-share"},
	{http.MethodGet, "/api/v1/shares/status/g1", "ceremony", "status"},

	// Tenants — service_custodian_share_tenant.go.
	{http.MethodPost, "/api/v1/tenants/", "tenants", "create"},
	{http.MethodGet, "/api/v1/tenants/", "tenants", "list"},
	{http.MethodGet, "/api/v1/tenants/t1", "tenants", "read"},
	{http.MethodDelete, "/api/v1/tenants/t1", "tenants", "delete"},
	{http.MethodGet, "/api/v1/tenants/t1/barrier/status", "tenant_barrier", "status"},
	{http.MethodPost, "/api/v1/tenants/t1/barrier/init", "tenant_barrier", "init"},
	{http.MethodPost, "/api/v1/tenants/t1/barrier/unseal", "tenant_barrier", "unseal"},
	{http.MethodPut, "/api/v1/tenants/t1/entitlements", "tenants", "set_entitlements"},
	{http.MethodPut, "/api/v1/tenants/t1/quotas", "tenants", "set_quotas"},

	// Password vault — service_password.go.
	{http.MethodPost, "/api/v1/passwords/", "passwords", "write"},
	{http.MethodGet, "/api/v1/passwords/", "passwords", "read"},
	{http.MethodGet, "/api/v1/passwords/p1", "passwords", "read"},
	{http.MethodPut, "/api/v1/passwords/p1", "passwords", "write"},
	{http.MethodDelete, "/api/v1/passwords/p1", "passwords", "delete"},
	{http.MethodPost, "/api/v1/passwords/unlock", "passwords", "unlock"},
	{http.MethodPost, "/api/v1/passwords/lock", "passwords", "lock"},
	{http.MethodGet, "/api/v1/passwords/status", "passwords", "read"},
	{http.MethodPost, "/api/v1/passwords/generate", "passwords", "generate"},

	// Credentials — the MCP credentials.* methods.
	{http.MethodPost, "/api/v1/credentials/submit", "credentials", "submit"},
	{http.MethodGet, "/api/v1/credentials/strategy", "credentials", "strategy"},

	// PCR policies — service_policy.go.
	{http.MethodPost, "/api/v1/policies/", "policy", "create"},
	{http.MethodGet, "/api/v1/policies/", "policy", "list"},
	{http.MethodGet, "/api/v1/policies/boot", "policy", "get"},
	{http.MethodDelete, "/api/v1/policies/boot", "policy", "delete"},
	{http.MethodPost, "/api/v1/policies/boot/refresh", "policy", "refresh"},
	{http.MethodPost, "/api/v1/policies/boot/verify", "policy", "verify"},
	{http.MethodGet, "/api/v1/policies/boot/export", "policy", "export"},
}

// sessionOnlyRoutes is the golden set of REST routes that still require only
// an authenticated identity. Each is either intrinsically per-caller or has
// no permission on any other transport to adopt (go-xkms#780 records the
// reason per route). A new session-only route fails this test, so exposing an
// operation without a permission is always a reviewed decision.
var sessionOnlyRoutes = []string{
	"GET /api/v1/auth/me",
	"GET /api/v1/auth/validate",
	"GET /api/v1/ca/crl",
	"GET /api/v1/credentials/",
	"GET /api/v1/init/officer/status",
	"GET /api/v1/init/status",
	"POST /api/v1/auth/logout",
	"POST /api/v1/init/claim-cert/begin",
	"POST /api/v1/init/claim-cert/complete",
	"POST /api/v1/init/claim-share/begin",
	"POST /api/v1/init/claim-share/complete",
	"POST /api/v1/passwords/access-mode",
}

// routeAuthzRecordingClient records the resource:action pair it was asked to
// authorize and allows exactly one configured pair.
type routeAuthzRecordingClient struct {
	allowResource string
	allowAction   string

	gotResource string
	gotAction   string
}

func (c *routeAuthzRecordingClient) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	c.gotResource = resource
	c.gotAction = action
	if resource == c.allowResource && action == c.allowAction {
		return nil
	}
	return &routeAuthzDeniedError{resource: resource, action: action}
}

func (c *routeAuthzRecordingClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, &routeAuthzDeniedError{resource: "permissions", action: "list"}
}

// routeAuthzDeniedError is the recording client's refusal.
type routeAuthzDeniedError struct {
	resource string
	action   string
}

func (e *routeAuthzDeniedError) Error() string {
	return "permission denied: " + e.resource + ":" + e.action
}

// newGatedRouteServer builds an RBAC-enabled REST server with every subsystem
// behind a go-xkms#780 route configured, so each route's Enabled guard mounts
// it. The tenant subsystem needs a real barrier registry and a composed
// TenantService on the XKMS service; tenantID, when non-empty, is registered
// and unsealed in that registry.
func newGatedRouteServer(t *testing.T, rbac qrdbtransport.RBACClient, authn auth.Authenticator, ca any, tenantID string) *Server {
	t.Helper()

	logger := slog.New(slog.DiscardHandler)
	registry := testTenantMiddlewareRegistry(t)
	if tenantID != "" {
		testTenantMiddlewareRegisteredTenant(t, registry, tenantID)
	}

	ks := newMockKeyStore()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": ks},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	tenantSvc, err := seal.NewHardwareTenantService(registry.SystemBarrier(), registry, logger, nil)
	require.NoError(t, err)
	svc.SetTenantService(tenantSvc)

	policyMgr, err := policy.NewManager(fakePCRReader{}, policy.NewMemoryPolicyStore())
	require.NoError(t, err)
	svc.SetPolicyManager(policyMgr)
	svc.SetCredentialService(&credentialspkg.Service{})

	server, err := NewServer(&Config{
		Authenticator:    authn,
		Backends:         map[string]xkms.Backend{"test": ks},
		Logger:           logger,
		XKMSService:      svc,
		CustodianEnabled: true,
		ShareEnabled:     true,
		BarrierRegistry:  registry,
		PasswordStore:    staticpw.NewStore(storage.NewMemory()),
		CA:               ca,
		EnableRBAC:       true,
		RBACAuthorizer:   auth.NewAuthorizer(rbac),
	})
	require.NoError(t, err)
	return server
}

func serveRoute(s *Server, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, http.NoBody)
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, req)
	return w
}

// TestGatedRoutes_RBACDenied proves every go-xkms#780 route is behind the
// RequirePermission decorator: an authenticated caller whose every permission
// check is refused receives 403 before the handler runs. Before #780 each of
// these was reachable with authentication alone.
func TestGatedRoutes_RBACDenied(t *testing.T) {
	server := newGatedRouteServer(t, denyingRBACClient{}, auth.NewNoOpAuthenticator(), &mockTCGCAServicer{}, "")

	for _, tc := range gatedRoutePermissions {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := serveRoute(server, tc.method, tc.path)
			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

// TestGatedRoutes_RequirePermission proves each go-xkms#780 route asks the
// qrdb PDP for exactly the pair gRPC and MCP gate the same operation with,
// and that a caller holding that grant passes the gate. The handler behind it
// may still refuse the empty request, but never with the middleware's 401 or
// 403. The caller is tenant-scoped because the password vault's session
// handlers (unlock, lock) refuse a system-tenant identity with their own 401.
func TestGatedRoutes_RequirePermission(t *testing.T) {
	const tenantID = "tenant-a"
	authn := tenantScopedAuthenticator{tenantID: tenantID}

	// One server serves every subtest; the recording client is re-armed with
	// the route's expected pair before each request.
	rbac := &routeAuthzRecordingClient{}
	server := newGatedRouteServer(t, rbac, authn, &mockTCGCAServicer{}, tenantID)

	for _, tc := range gatedRoutePermissions {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			*rbac = routeAuthzRecordingClient{allowResource: tc.resource, allowAction: tc.action}

			w := serveRoute(server, tc.method, tc.path)

			assert.Equal(t, tc.resource, rbac.gotResource, "decorator asked for wrong resource")
			assert.Equal(t, tc.action, rbac.gotAction, "decorator asked for wrong action")
			assert.NotEqual(t, http.StatusUnauthorized, w.Code)
			assert.NotEqual(t, http.StatusForbidden, w.Code)
		})
	}
}

// TestGatedRoutes_WrongGrantDenied proves holding a sibling permission is not
// enough: a caller granted only the read half of a family is refused the
// write half. pin:read must not reach SetSOPIN; tenants:read must not reach
// DeleteTenant.
func TestGatedRoutes_WrongGrantDenied(t *testing.T) {
	cases := []struct {
		grant gatedRoute
		route gatedRoute
	}{
		{gatedRoute{resource: "pin", action: "read"}, gatedRoute{method: http.MethodPost, path: "/api/v1/pin/so/set"}},
		{gatedRoute{resource: "tenants", action: "read"}, gatedRoute{method: http.MethodDelete, path: "/api/v1/tenants/t1"}},
		{gatedRoute{resource: "ceremony", action: "status"}, gatedRoute{method: http.MethodPost, path: "/api/v1/custodian/groups/g1/members"}},
		{gatedRoute{resource: "passwords", action: "read"}, gatedRoute{method: http.MethodPost, path: "/api/v1/passwords/unlock"}},
	}
	rbac := &routeAuthzRecordingClient{}
	server := newGatedRouteServer(t, rbac, auth.NewNoOpAuthenticator(), &mockTCGCAServicer{}, "")

	for _, tc := range cases {
		t.Run(tc.route.method+" "+tc.route.path, func(t *testing.T) {
			*rbac = routeAuthzRecordingClient{allowResource: tc.grant.resource, allowAction: tc.grant.action}

			w := serveRoute(server, tc.route.method, tc.route.path)
			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

// TestGatedRoutes_BootstrapOnlyCABundle covers the second variant of
// GET /api/v1/ca/bundle — served by the bootstrap-only handler when no CA
// subsystem is configured. It must carry the same certs:read pair as the
// full-CA variant: the unified-server module registers a multi-variant route
// once, under its first variant's permission.
func TestGatedRoutes_BootstrapOnlyCABundle(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		server := newGatedRouteServer(t, denyingRBACClient{}, auth.NewNoOpAuthenticator(), nil, "")
		require.Nil(t, server.caHandlers)

		w := serveRoute(server, http.MethodGet, "/api/v1/ca/bundle")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("certs:read admitted", func(t *testing.T) {
		rbac := &routeAuthzRecordingClient{allowResource: "certs", allowAction: "read"}
		server := newGatedRouteServer(t, rbac, auth.NewNoOpAuthenticator(), nil, "")

		w := serveRoute(server, http.MethodGet, "/api/v1/ca/bundle")
		assert.Equal(t, "certs", rbac.gotResource)
		assert.Equal(t, "read", rbac.gotAction)
		assert.NotEqual(t, http.StatusUnauthorized, w.Code)
		assert.NotEqual(t, http.StatusForbidden, w.Code)
	})
}

// tenantScopedAuthenticator authenticates every request as a tenant-scoped
// (not system-tenant) identity.
type tenantScopedAuthenticator struct {
	tenantID string
}

func (a tenantScopedAuthenticator) Name() string { return "tenant-scoped-test" }

func (a tenantScopedAuthenticator) AuthenticateHTTP(*http.Request) (*auth.Identity, error) {
	return &auth.Identity{Subject: "tenant-user", TenantID: a.tenantID}, nil
}

func (a tenantScopedAuthenticator) AuthenticateGRPC(context.Context, metadata.MD) (*auth.Identity, error) {
	return &auth.Identity{Subject: "tenant-user", TenantID: a.tenantID}, nil
}

// TestTenantRoutes_AntiEnumerationPreserved proves the permission gate adds no
// tenant-existence oracle. A tenant-scoped caller holding tenants:read still
// receives the handler's identical 404 for another tenant's ID and for an ID
// that does not exist; a caller without the grant receives the identical 403
// for both, because the gate decides before any tenant lookup.
func TestTenantRoutes_AntiEnumerationPreserved(t *testing.T) {
	const own, other = "tenant-a", "tenant-b"
	authn := tenantScopedAuthenticator{tenantID: own}

	t.Run("granted caller cannot tell another tenant from a missing one", func(t *testing.T) {
		rbac := &routeAuthzRecordingClient{allowResource: "tenants", allowAction: "read"}
		server := newGatedRouteServer(t, rbac, authn, nil, own)
		_, err := server.barrierRegistry.RegisterTenant(other)
		require.NoError(t, err)

		existing := serveRoute(server, http.MethodGet, "/api/v1/tenants/"+other)
		missing := serveRoute(server, http.MethodGet, "/api/v1/tenants/no-such-tenant")

		assert.Equal(t, http.StatusNotFound, existing.Code)
		assert.Equal(t, http.StatusNotFound, missing.Code)
		assert.Equal(t, missing.Body.String(), existing.Body.String())
	})

	t.Run("ungranted caller is refused before any lookup", func(t *testing.T) {
		server := newGatedRouteServer(t, denyingRBACClient{}, authn, nil, own)
		_, err := server.barrierRegistry.RegisterTenant(other)
		require.NoError(t, err)

		existing := serveRoute(server, http.MethodGet, "/api/v1/tenants/"+other)
		missing := serveRoute(server, http.MethodGet, "/api/v1/tenants/no-such-tenant")

		assert.Equal(t, http.StatusForbidden, existing.Code)
		assert.Equal(t, http.StatusForbidden, missing.Code)
		assert.Equal(t, missing.Body.String(), existing.Body.String())
	})
}

// TestRoutes_SessionOnlySurfaceIsPinned pins the exact set of routes the
// route table serves with authentication but no permission. It fails when a
// route joins or leaves the session-only tier without this table changing.
func TestRoutes_SessionOnlySurfaceIsPinned(t *testing.T) {
	var got []string
	for _, spec := range Routes() {
		if spec.Auth == RouteAuthSession {
			got = append(got, spec.Method+" "+spec.Pattern)
		}
	}
	sort.Strings(got)

	want := append([]string(nil), sessionOnlyRoutes...)
	sort.Strings(want)
	assert.Equal(t, want, got)
}

// TestRoutes_GatedRoutesDeclarePermission checks the go-xkms#780 routes at the
// table level, independent of the router: every one is RouteAuthPermission
// and carries a non-empty pair, which is what the unified-server module
// registers under and contributes to the Admin and Owner role grants.
func TestRoutes_GatedRoutesDeclarePermission(t *testing.T) {
	byRoute := map[string]RouteSpec{}
	for _, spec := range Routes() {
		byRoute[spec.Method+" "+spec.Pattern] = spec
	}

	for _, pattern := range []string{
		"POST /api/v1/pin/so/set",
		"GET /api/v1/piv/slots/{slot}/certificate",
		"GET /api/v1/ca/bundle",
		"DELETE /api/v1/custodian/groups/{id}/members/{userID}",
		"DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex}",
		"POST /api/v1/tenants/{tenantID}/barrier/unseal",
		"POST /api/v1/passwords/unlock",
		"POST /api/v1/credentials/submit",
	} {
		spec, ok := byRoute[pattern]
		require.True(t, ok, "route %s missing from the table", pattern)
		assert.Equal(t, RouteAuthPermission, spec.Auth, pattern)
		assert.NotEmpty(t, spec.Resource, pattern)
		assert.NotEmpty(t, spec.Action, pattern)
	}
}
