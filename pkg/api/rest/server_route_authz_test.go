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
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
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
	// PIN management — service_pin.go.
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
	{http.MethodPost, "/api/v1/ca/sign-csr", "certs", "issue"},
	{http.MethodPost, "/api/v1/ca/issue", "certs", "issue"},
	{http.MethodPost, "/api/v1/ca/revoke", "certs", "revoke"},
	{http.MethodPost, "/api/v1/ca/crl", "certs", "read"},
	{http.MethodGet, "/api/v1/ca/revoked/01", "certs", "read"},
	{http.MethodPost, "/api/v1/ca/tcg/ek", "certs", "issue"},
	{http.MethodPost, "/api/v1/ca/tcg/ak", "certs", "issue"},
	{http.MethodPost, "/api/v1/ca/tcg/sign-csr", "certs", "issue"},
	{http.MethodPost, "/api/v1/ca/tcg/enroll", "certs", "issue"},
	{http.MethodPost, "/api/v1/ca/tcg/lak", "certs", "issue"},

	// Tenants — service_tenant.go.
	{http.MethodPost, "/api/v1/tenants/", "tenants", "create"},
	{http.MethodGet, "/api/v1/tenants/", "tenants", "list"},
	{http.MethodGet, "/api/v1/tenants/t1", "tenants", "read"},
	{http.MethodDelete, "/api/v1/tenants/t1", "tenants", "delete"},
	{http.MethodPut, "/api/v1/tenants/t1/entitlements", "tenants", "set_entitlements"},
	{http.MethodPut, "/api/v1/tenants/t1/quotas", "tenants", "set_quotas"},

	// Password vault — service_password.go.
	{http.MethodPost, "/api/v1/passwords/", "passwords", "write"},
	{http.MethodGet, "/api/v1/passwords/", "passwords", "read"},
	{http.MethodGet, "/api/v1/passwords/p1", "passwords", "read"},
	{http.MethodPut, "/api/v1/passwords/p1", "passwords", "write"},
	{http.MethodDelete, "/api/v1/passwords/p1", "passwords", "delete"},
	{http.MethodPost, "/api/v1/password-vault/unlock", "passwords", "unlock"},
	{http.MethodPost, "/api/v1/password-vault/lock", "passwords", "lock"},
	{http.MethodGet, "/api/v1/password-vault/session", "passwords", "read"},
	{http.MethodPost, "/api/v1/passwords/generate", "passwords", "generate"},
	{http.MethodGet, "/api/v1/password-vault", "passwords", "read"},
	{http.MethodPost, "/api/v1/password-vault/factors", "passwords", "unlock"},
	{http.MethodPut, "/api/v1/password-vault/factors/f1", "passwords", "unlock"},
	{http.MethodDelete, "/api/v1/password-vault/factors/f1", "passwords", "unlock"},
	{http.MethodPost, "/api/v1/password-vault/recover", "passwords", "unlock"},

	// Credentials — the MCP credentials.* methods.
	{http.MethodPost, "/api/v1/credentials/submit", "credentials", "submit"},
	{http.MethodGet, "/api/v1/credentials/strategy", "credentials", "strategy"},

	// TPM policies — service_tpm_policy.go.
	{http.MethodPost, "/api/v1/tpm/policies", "tpm_policy", "create"},
	{http.MethodGet, "/api/v1/tpm/policies", "tpm_policy", "list"},
	{http.MethodGet, "/api/v1/tpm/policies/boot", "tpm_policy", "get"},
	{http.MethodDelete, "/api/v1/tpm/policies/boot", "tpm_policy", "delete"},
	{http.MethodPost, "/api/v1/tpm/policies/boot/update", "tpm_policy", "update"},
	{http.MethodPost, "/api/v1/tpm/policies/boot/revoke", "tpm_policy", "revoke"},
	{http.MethodPost, "/api/v1/tpm/policies/boot/verify", "tpm_policy", "verify"},
	{http.MethodGet, "/api/v1/tpm/policies/boot/objects", "tpm_policy", "get"},
	{http.MethodPost, "/api/v1/tpm/policies/boot/auto-unseal", "tpm_policy", "update"},
	{http.MethodPost, "/api/v1/tpm/authority/rotate", "tpm_policy", "rotate"},
	{http.MethodGet, "/api/v1/keys/k1/tpm-policy", "tpm_policy", "get"},
	{http.MethodGet, "/api/v1/tenants/tenant-b/tpm", "tenants", "read"},
	{http.MethodPut, "/api/v1/tenants/tenant-b/tpm", "tenants", "set_tpm_mode"},
	{http.MethodGet, "/api/v1/tenants/tenant-b/tpm/vtpm", "tenants", "read"},
	{http.MethodPost, "/api/v1/tenants/tenant-b/tpm/vtpm/start", "tenants", "set_tpm_mode"},
	{http.MethodPost, "/api/v1/tenants/tenant-b/tpm/vtpm/stop", "tenants", "set_tpm_mode"},

	// OIDC credentials — the gRPC OIDCCredential* RPCs.
	{http.MethodPost, "/api/v1/oidc/credentials", "oidc_credentials", "create"},
	{http.MethodGet, "/api/v1/oidc/credentials", "oidc_credentials", "list"},
	{http.MethodGet, "/api/v1/oidc/credentials/tenant/ci", "oidc_credentials", "get"},
	{http.MethodDelete, "/api/v1/oidc/credentials/tenant/ci", "oidc_credentials", "delete"},
	{http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/import", "oidc_credentials", "update"},
	{http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/refresh", "oidc_credentials", "update"},
	{http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/token", "oidc_credentials", "token"},
	{http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/device", "oidc_credentials", "update"},
	{http.MethodPost, "/api/v1/oidc/credentials/tenant/ci/device/poll", "oidc_credentials", "update"},
	{http.MethodPost, "/api/v1/peer-attestation/challenge", "peer_attestation", "challenge"},
	{http.MethodPost, "/api/v1/peer-attestation/evidence", "peer_attestation", "submit"},

	// 2026-09-30, go-xkms#728). Mirrors go-qrdb's own backup:* permission
	// family verbatim; restore is gated separately because it overwrites
	// live shard state.
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
	"GET /api/v1/credentials",
	"POST /api/v1/auth/logout",
	// Adds a passkey to the caller's OWN account; the account comes from
	// the session, never the request (go-xkms#1294).
	"POST /api/v1/webauthn/credentials/begin",
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

	// The TPM policy service runs without a TPM; the caller's tenant is in
	// TPM mode none, so every TPM policy route answers from the registry.
	tpmPolicies, tpmRegistry := tpmpolicytest.NewOffline(t)
	require.NoError(t, tpmRegistry.PutScope(context.Background(), &tpmpolicy.Scope{Tenant: "tenant-a", Mode: tpmpolicy.ModeNone}))
	svc.SetTPMPolicyService(tpmPolicies)
	svc.SetCredentialService(&credentialspkg.Service{})

	server, err := NewServer(&Config{
		Authenticator:   authn,
		Backends:        map[string]xkms.Backend{"test": ks},
		Logger:          logger,
		XKMSService:     svc,
		BarrierRegistry: registry,
		PasswordStore:   newTestPasswordStore(t),
		CA:              ca,
		EnableRBAC:      true,
		RBACAuthorizer:  auth.NewAuthorizer(rbac),
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
		{gatedRoute{resource: "passwords", action: "read"}, gatedRoute{method: http.MethodPost, path: "/api/v1/password-vault/unlock"}},
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
		_, err := server.barrierRegistry.RegisterTenantDefault(other)
		require.NoError(t, err)

		existing := serveRoute(server, http.MethodGet, "/api/v1/tenants/"+other)
		missing := serveRoute(server, http.MethodGet, "/api/v1/tenants/no-such-tenant")

		assert.Equal(t, http.StatusNotFound, existing.Code)
		assert.Equal(t, http.StatusNotFound, missing.Code)
		assert.Equal(t, missing.Body.String(), existing.Body.String())
	})

	t.Run("ungranted caller is refused before any lookup", func(t *testing.T) {
		server := newGatedRouteServer(t, denyingRBACClient{}, authn, nil, own)
		_, err := server.barrierRegistry.RegisterTenantDefault(other)
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
		"POST /api/v1/password-vault/unlock",
		"POST /api/v1/credentials/submit",
	} {
		spec, ok := byRoute[pattern]
		require.True(t, ok, "route %s missing from the table", pattern)
		assert.Equal(t, RouteAuthPermission, spec.Auth, pattern)
		assert.NotEmpty(t, spec.Resource, pattern)
		assert.NotEmpty(t, spec.Action, pattern)
	}
}
