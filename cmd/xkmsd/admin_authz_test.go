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

package main

// Authorization tests for the ACME admin plane as xkmsd composes it
// (finalizeAdminModule), against a real embedded qrdb node whose first boot
// has seeded the system tenant, the built-in roles and the administrator.
//
// They exist because of go-xkms#1069: the admin plane's mTLS authenticator
// was built without the qrdb user store, so every identity reaching the
// permission gate carried no roles and no tenant, and qrdb's authorizer
// denied every admin route -- even to the first-boot administrator. The
// crypto plane never showed it because qrdb's own middleware resolves its
// identities.
//
// On the unified server qrdb authorizes every admin route before the router
// below it runs: AdminModule mounts each route of admin.Routes() under that
// route's own permission. These tests therefore check the two halves the
// composition rests on -- qrdb grants the first-boot administrator every
// route's permission and refuses an identity holding no role, and the router
// finalizeAdminModule publishes serves exactly the routes qrdb mounts and
// lets the administrator through its own authentication and tenant checks.
// The route set is never hand-listed: it is admin.Routes() and the router's
// own walk.
//
// ACME is disabled in this fixture (finalizeAdminModule receives a nil
// *acmeServer, as run() does when acme.enabled is false), so a handler may
// be unable to complete its work. That is outside what these tests measure,
// so serveAdminRoute contains a handler panic to the one request and reports
// it as 500.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// adminRoute is one method+path the published admin router answers.
type adminRoute struct {
	method string
	path   string
}

func (r adminRoute) String() string { return r.method + " " + r.path }

// insideTenant reports whether r addresses a tenant's own roles or users,
// which qrdb's strict tenant isolation keeps the platform out of.
func (r adminRoute) insideTenant() bool {
	return strings.HasPrefix(r.path, "/api/v1/tenants/") &&
		(strings.Contains(r.path, "/roles") || strings.Contains(r.path, "/users"))
}

// adminAuthzFixture is an embedded, first-boot-seeded qrdb node with the ACME
// admin plane composed on it exactly as xkmsd composes it.
type adminAuthzFixture struct {
	client     *qrdbsdk.Client
	authorizer *auth.Authorizer
	router     http.Handler
	routes     []adminRoute
	adminCert  *x509.Certificate
}

// newAdminAuthzFixture builds the fixture. server.New runs qrdb's canonical
// first boot, so the node already holds the system tenant, the built-in roles
// and the administrator when finalizeAdminModule composes the admin plane.
func newAdminAuthzFixture(t *testing.T) *adminAuthzFixture {
	t.Helper()
	original := adminRouterState.Load()
	t.Cleanup(func() { adminRouterState.Store(original) })

	// The node runs qrdb's auth chain, so first boot must bind the bootstrap
	// admin's certificate; the serve fixture's TLS + mTLS configuration is
	// what makes the ceremony issue one.
	cfg := newServeTestConfig(t)
	srv, err := server.New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, srv.Shutdown()) })
	require.NoError(t, finalizeAdminModule(srv, nil, slog.New(slog.DiscardHandler)))

	published := adminRouterState.Load()
	require.NotNil(t, published, "finalizeAdminModule must publish the admin router")
	muxRouter, ok := (*published).(*mux.Router)
	require.True(t, ok, "published admin router is %T, want *mux.Router", *published)

	client := srv.QRDBClient()
	return &adminAuthzFixture{
		client:     client,
		authorizer: auth.NewAuthorizer(client.RBAC()),
		router:     muxRouter,
		routes:     walkAdminRoutes(t, muxRouter),
		adminCert:  firstBootAdminCert(t, cfg),
	}
}

// pathVariable matches a gorilla/mux path variable such as {id}.
var pathVariable = regexp.MustCompile(`\{[^}]+\}`)

// walkAdminRoutes enumerates every method+path the router serves, filling
// each path variable with a placeholder. Prefix-only subrouter entries carry
// no methods and are not routes.
func walkAdminRoutes(t *testing.T, router *mux.Router) []adminRoute {
	t.Helper()
	var routes []adminRoute
	err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		tmpl, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		path := pathVariable.ReplaceAllString(tmpl, "authz-1069")
		for _, m := range methods {
			routes = append(routes, adminRoute{method: m, path: path})
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, routes, "the admin router registered no routes")
	return routes
}

// mountedRoute is the published router entry walkAdminRoutes reports for an
// admin.Routes entry.
func mountedRoute(route admin.Route) adminRoute {
	return adminRoute{method: route.Method, path: pathVariable.ReplaceAllString(route.Path, "authz-1069")}
}

// oracleContext is the context the fixtures' own qrdb calls run under. The
// node runs qrdb's auth chain and its strict tenant isolation, so those calls
// act as an Admin and SO of tenantID itself (the SO holds roles:create); the
// admin plane under test never sees this identity.
func oracleContext(tenantID string) context.Context {
	oracle := &qrdbsdk.Identity{
		Subject:  "admin-plane-oracle",
		TenantID: tenantID,
		Roles: []string{
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameAdmin),
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameSO),
			// go-qrdb v0.58 (#1278): a grantor may grant only what it holds,
			// and the data-plane kv permissions the fixtures' roles carry are
			// the Operator's.
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameOperator),
		},
	}
	return qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(context.Background(), oracle), tenantID)
}

// systemRole resolves a built-in role of the system tenant.
func systemRole(t *testing.T, client *qrdbsdk.Client, name string) *qrdbtransport.Role {
	t.Helper()
	r, err := client.Roles().GetRoleByName(oracleContext(qrdbsdk.SystemTenantID),
		&qrdbtransport.GetRoleByNameRequest{TenantID: qrdbsdk.SystemTenantID, Name: name})
	require.NoError(t, err, "first boot must seed the %q role", name)
	return r
}

// firstBootAdmin returns the administrator first boot created: the system
// tenant user holding the built-in Admin role.
func firstBootAdmin(t *testing.T, client *qrdbsdk.Client) *qrdbtransport.User {
	t.Helper()
	adminRole := systemRole(t, client, qrdbsdk.RoleNameAdmin)
	list, err := client.Users().ListUsers(oracleContext(qrdbsdk.SystemTenantID),
		&qrdbtransport.ListUsersRequest{TenantID: qrdbsdk.SystemTenantID})
	require.NoError(t, err)
	for _, u := range list.Users {
		if slices.Contains(u.RoleIDs, adminRole.ID) {
			return u
		}
	}
	t.Fatal("first boot created no system-tenant user holding the Admin role")
	return nil
}

// firstBootAdminCert returns the certificate the first-boot ceremony issued
// and bound to the bootstrap administrator. qrdb refuses to bind any other
// certificate to a system Admin, so this is the administrator's only
// credential.
func firstBootAdminCert(t *testing.T, cfg *config.Config) *x509.Certificate {
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join(cfg.Datastore.Path, "admin-cert.pem"))
	require.NoError(t, err, "first boot must persist the administrator's certificate")
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "admin-cert.pem holds no PEM block")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// newClientCert returns a self-signed client certificate for commonName. The
// admin plane's authenticator resolves a certificate by its SPKI thumbprint;
// chain verification is the TLS listener's job and is not exercised here.
func newClientCert(t *testing.T, commonName, tenantID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// go-qrdb v0.51 binds the tenant only when the first OU and the SPIFFE
	// SAN's trust domain agree.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName, OrganizationalUnit: []string{tenantID}},
		URIs:         []*url.URL{{Scheme: "spiffe", Host: tenantID, Path: "/user/" + commonName}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// bindClientCert issues a client certificate and binds its SPKI thumbprint
// to the user, as xkmsctl's enrollment does.
func bindClientCert(t *testing.T, client *qrdbsdk.Client, u *qrdbtransport.User) *x509.Certificate {
	t.Helper()
	// The certificate names the user's tenant in its OU, as the certificates
	// xkms issues do, so the admin plane looks the binding up in that tenant
	// (go-xkms#1240).
	cert := newClientCert(t, u.Username, u.TenantID)
	// qrdb resolves the user within the context's tenant.
	_, err := client.Users().AddCertBinding(oracleContext(u.TenantID), u.ID, qrdbsdk.ComputeSPKIThumbprint(cert), 0)
	require.NoError(t, err)
	return cert
}

// serveAdminRoute dispatches one request for route, presenting cert as the
// verified mTLS peer certificate, and returns the status. A handler panic
// behind a passed gate (ACME disabled; see the file comment) is contained to
// this request and reported as 500.
func serveAdminRoute(t *testing.T, router http.Handler, route adminRoute, cert *x509.Certificate) (status int) {
	t.Helper()
	req := httptest.NewRequest(route.method, route.path, nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	defer func() {
		if recover() != nil {
			status = http.StatusInternalServerError
		}
	}()
	router.ServeHTTP(rec, req)
	return rec.Code
}

// userIdentity is the identity qrdb resolves for a user's bound certificate:
// the user's name, tenant and role assignments.
func userIdentity(u *qrdbtransport.User) *auth.Identity {
	return &auth.Identity{Subject: u.Username, TenantID: u.TenantID, Roles: u.RoleIDs}
}

// authorizeRoute asks qrdb whether identity holds route's permission, the
// decision qrdb's chain makes before the admin router runs.
func (f *adminAuthzFixture) authorizeRoute(identity *auth.Identity, route admin.Route) error {
	return f.authorizer.Authorize(context.Background(), identity,
		qrdbsdk.PermissionResource(route.Permission), qrdbsdk.PermissionAction(route.Permission))
}

// TestAdminPlane_FirstBootAdminAuthorizedOnEveryRoute is the go-xkms#1069
// regression: qrdb grants the first-boot administrator every admin route's
// permission, and the published router, given the administrator's bound
// client certificate, authenticates it and lets it through on every route.
// Under the strict FIPS posture the grant is exactly the Admin role's.
func TestAdminPlane_FirstBootAdminAuthorizedOnEveryRoute(t *testing.T) {
	f := newAdminAuthzFixture(t)
	administrator := userIdentity(firstBootAdmin(t, f.client))

	// In FIPS mode pkg/server boots qrdb under the strict separation-of-duties
	// posture: the administrator holds only the Admin role, so a route outside
	// that role's grants is withheld from it rather than allowed.
	var withheld []string
	if fips140.Enabled() {
		adminRole := systemRole(t, f.client, qrdbsdk.RoleNameAdmin)
		for _, route := range admin.Routes() {
			if !slices.Contains(adminRole.Permissions, string(route.Permission)) {
				withheld = append(withheld, mountedRoute(route).String())
			}
		}
	}

	for _, route := range admin.Routes() {
		err := f.authorizeRoute(administrator, route)
		if slices.Contains(withheld, mountedRoute(route).String()) {
			assert.Error(t, err, "%s %s: the strict posture must withhold %s from the Admin role",
				route.Method, route.Path, route.Permission)
			continue
		}
		assert.NoError(t, err,
			"%s %s: qrdb denied %s to the first-boot administrator", route.Method, route.Path, route.Permission)
	}

	for _, route := range f.routes {
		status := serveAdminRoute(t, f.router, route, f.adminCert)
		assert.NotEqual(t, http.StatusUnauthorized, status, "%s", route)
		if route.insideTenant() || slices.Contains(withheld, route.String()) {
			// qrdb refuses the platform a tenant's own roles and users, and
			// the strict posture withholds what Admin does not hold; the
			// grants above are what this test proves.
			continue
		}
		assert.NotEqual(t, http.StatusForbidden, status, "%s", route)
	}
}

// TestAdminPlane_IdentityWithoutRoleRefusedOnEveryRoute proves the admin
// plane still fails closed: qrdb refuses every admin route's permission to an
// authenticated identity holding no role -- a real user with no role
// assignment.
func TestAdminPlane_IdentityWithoutRoleRefusedOnEveryRoute(t *testing.T) {
	f := newAdminAuthzFixture(t)

	roleless, err := f.client.Users().CreateUser(oracleContext(qrdbsdk.SystemTenantID), &qrdbtransport.CreateUserRequest{
		Username:             "roleless-1069",
		TenantID:             qrdbsdk.SystemTenantID,
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	require.Empty(t, roleless.RoleIDs, "fixture: the user must hold no role")

	for _, route := range admin.Routes() {
		assert.Error(t, f.authorizeRoute(userIdentity(roleless), route),
			"%s %s: qrdb granted %s to an identity holding no role", route.Method, route.Path, route.Permission)
	}
}

// TestAdminPlane_PublishedRoutesAreTheMountedRoutes proves the router
// finalizeAdminModule publishes serves exactly the routes AdminModule mounts
// on qrdb, each under its own permission: a route the router answered that
// admin.Routes() did not list would reach a handler with no permission
// checked at all.
func TestAdminPlane_PublishedRoutesAreTheMountedRoutes(t *testing.T) {
	f := newAdminAuthzFixture(t)

	var mounted []string
	for _, route := range admin.Routes() {
		mounted = append(mounted, mountedRoute(route).String())
	}
	var published []string
	for _, route := range f.routes {
		published = append(published, route.String())
	}
	assert.ElementsMatch(t, mounted, published)
}

// TestAdminPlane_UnboundCertificateRefusedAtAuthentication proves a client
// certificate bound to no user never becomes an identity on the admin plane:
// the embedded qrdb reports its typed not-found, the mTLS authenticator
// refuses with ErrCertNotBound, and the request is answered 401 before any
// handler runs. A certificate-derived identity would carry the caller-chosen
// CN and OU as its Subject and TenantID (go-xkms#1096).
func TestAdminPlane_UnboundCertificateRefusedAtAuthentication(t *testing.T) {
	f := newAdminAuthzFixture(t)
	cert := newClientCert(t, "nobody-1096", qrdbsdk.SystemTenantID)

	for _, route := range f.routes {
		assert.Equal(t, http.StatusUnauthorized, serveAdminRoute(t, f.router, route, cert), "%s", route)
	}
}

// TestAdminPlane_RoutePermissionsRegisteredAndGranted proves every
// permission an admin route is mounted under is registered in qrdb's
// permission registry and materialized into the seeded Owner role, which
// holds every permission by default, or under the strict FIPS posture into
// one of the five built-in roles. A route mounted under a permission qrdb
// does not know fails here rather than as a production 403. Placement on the
// other built-in roles is qrdb's decision and xkms's role grants, deliberately
// not restated here.
func TestAdminPlane_RoutePermissionsRegisteredAndGranted(t *testing.T) {
	f := newAdminAuthzFixture(t)

	// In FIPS mode pkg/server boots qrdb under the strict separation-of-duties
	// posture, which seeds no Owner role, so there the grant is proved across
	// the five built-in roles first boot does seed.
	var granted []string
	if fips140.Enabled() {
		_, err := f.client.Roles().GetRoleByName(oracleContext(qrdbsdk.SystemTenantID),
			&qrdbtransport.GetRoleByNameRequest{TenantID: qrdbsdk.SystemTenantID, Name: qrdbsdk.RoleNameOwner})
		assert.Error(t, err, "the strict posture must not seed the Owner role")
		for _, name := range []string{qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator,
			qrdbsdk.RoleNameUser, qrdbsdk.RoleNameAuditor} {
			granted = append(granted, systemRole(t, f.client, name).Permissions...)
		}
	} else {
		granted = systemRole(t, f.client, qrdbsdk.RoleNameOwner).Permissions
	}

	for _, route := range admin.Routes() {
		assert.True(t, qrdbsdk.IsPermissionRegistered(route.Permission),
			"admin route permission %s is not registered with qrdb", route.Permission)
		assert.True(t, slices.Contains(granted, string(route.Permission)),
			"no seeded built-in role holds admin route permission %s", route.Permission)
	}
}
