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
// The route set is never hand-listed: every test walks the router
// finalizeAdminModule publishes, and learns which resource:action each route
// demands from the permission gate's own decision log. A route added to
// pkg/acme/admin is covered the moment it is registered.
//
// ACME is disabled in this fixture (finalizeAdminModule receives a nil
// *acmeServer, as run() does when acme.enabled is false), so a handler behind
// a passed gate may be unable to complete its work. That is outside what
// these tests measure -- the gate's decision -- so serveAdminRoute contains a
// handler panic to the one request and reports it as a completed, authorized
// dispatch.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// Messages the admin PermissionGate logs for each decision
// (pkg/acme/admin/authz.go). The tests read decisions from them rather than
// from status codes alone, because a handler behind a granted gate may itself
// answer 403 for a reason unrelated to RBAC.
const (
	gateGrantedMsg = "ACME admin authorization granted"
	gateDeniedMsg  = "ACME admin authorization denied"
)

// gateDecision is one PermissionGate decision, as logged.
type gateDecision struct {
	granted    bool
	subject    string
	permission string
}

// gateLog is a slog.Handler that records every PermissionGate decision.
type gateLog struct {
	mu        sync.Mutex
	decisions []gateDecision
}

func (l *gateLog) Enabled(context.Context, slog.Level) bool { return true }

func (l *gateLog) Handle(_ context.Context, r slog.Record) error {
	if r.Message != gateGrantedMsg && r.Message != gateDeniedMsg {
		return nil
	}
	d := gateDecision{granted: r.Message == gateGrantedMsg}
	var resource, action string
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "subject":
			d.subject = a.Value.String()
		case "resource":
			resource = a.Value.String()
		case "action":
			action = a.Value.String()
		}
		return true
	})
	d.permission = resource + ":" + action
	l.mu.Lock()
	l.decisions = append(l.decisions, d)
	l.mu.Unlock()
	return nil
}

func (l *gateLog) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *gateLog) WithGroup(string) slog.Handler      { return l }

// take returns and clears the decisions recorded so far.
func (l *gateLog) take() []gateDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.decisions
	l.decisions = nil
	return out
}

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
	client    *qrdbsdk.Client
	router    http.Handler
	routes    []adminRoute
	log       *gateLog
	adminCert *x509.Certificate
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
	log := &gateLog{}
	require.NoError(t, finalizeAdminModule(srv, nil, slog.New(log)))

	published := adminRouterState.Load()
	require.NotNil(t, published, "finalizeAdminModule must publish the admin router")
	muxRouter, ok := (*published).(*mux.Router)
	require.True(t, ok, "published admin router is %T, want *mux.Router", *published)

	return &adminAuthzFixture{
		client:    srv.QRDBClient(),
		router:    muxRouter,
		routes:    walkAdminRoutes(t, muxRouter),
		log:       log,
		adminCert: firstBootAdminCert(t, cfg),
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

// oracleContext is the context the fixtures' own qrdb calls run under. The
// node runs qrdb's auth chain and its strict tenant isolation, so those calls
// act as an Admin and SO of tenantID itself (the SO holds roles:create); the
// admin plane under test never sees this identity.
func oracleContext(tenantID string) context.Context {
	admin := &qrdbsdk.Identity{
		Subject:  "admin-plane-oracle",
		TenantID: tenantID,
		Roles: []string{
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameAdmin),
			qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameSO),
		},
	}
	return qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(context.Background(), admin), tenantID)
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
func newClientCert(t *testing.T, commonName string, organizationalUnits ...string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName, OrganizationalUnit: organizationalUnits},
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

// TestAdminPlane_FirstBootAdminAuthorizedOnEveryRoute is the go-xkms#1069
// regression: the first-boot administrator, presenting its bound client
// certificate, passes the permission gate on every admin route.
func TestAdminPlane_FirstBootAdminAuthorizedOnEveryRoute(t *testing.T) {
	f := newAdminAuthzFixture(t)
	admin := firstBootAdmin(t, f.client)

	for _, route := range f.routes {
		status := serveAdminRoute(t, f.router, route, f.adminCert)
		decisions := f.log.take()

		require.Len(t, decisions, 1, "%s: want exactly one gate decision", route)
		assert.True(t, decisions[0].granted, "%s: gate denied %s to the first-boot administrator",
			route, decisions[0].permission)
		assert.Equal(t, admin.Username, decisions[0].subject, "%s: gate saw the wrong subject", route)
		assert.NotEqual(t, http.StatusUnauthorized, status, "%s", route)
		if route.insideTenant() {
			// Past the gate, qrdb refuses the platform a tenant's own roles
			// and users; the gate's grant above is what this test proves.
			continue
		}
		assert.NotEqual(t, http.StatusForbidden, status, "%s", route)
	}
}

// TestAdminPlane_IdentityWithoutRoleRefusedOnEveryRoute proves the gate still
// fails closed: an authenticated identity holding no role -- a real user with
// no role assignment -- is refused on every admin route.
func TestAdminPlane_IdentityWithoutRoleRefusedOnEveryRoute(t *testing.T) {
	f := newAdminAuthzFixture(t)

	roleless, err := f.client.Users().CreateUser(oracleContext(qrdbsdk.SystemTenantID), &qrdbtransport.CreateUserRequest{
		Username:             "roleless-1069",
		TenantID:             qrdbsdk.SystemTenantID,
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	require.Empty(t, roleless.RoleIDs, "fixture: the user must hold no role")
	cert := bindClientCert(t, f.client, roleless)

	for _, route := range f.routes {
		status := serveAdminRoute(t, f.router, route, cert)
		decisions := f.log.take()

		assert.Equal(t, http.StatusForbidden, status, "%s", route)
		require.Len(t, decisions, 1, "%s: want exactly one gate decision", route)
		assert.False(t, decisions[0].granted, "%s: gate granted %s to an identity holding no role",
			route, decisions[0].permission)
	}
}

// TestAdminPlane_UnboundCertificateRefusedAtAuthentication proves a client
// certificate bound to no user never becomes an identity on the admin plane:
// the embedded qrdb reports its typed not-found, the mTLS authenticator
// refuses with ErrCertNotBound, and the request is answered 401 before the
// permission gate runs. A certificate-derived identity would carry the
// caller-chosen CN and OU as its Subject and TenantID (go-xkms#1096).
func TestAdminPlane_UnboundCertificateRefusedAtAuthentication(t *testing.T) {
	f := newAdminAuthzFixture(t)
	cert := newClientCert(t, "nobody-1096")

	for _, route := range f.routes {
		status := serveAdminRoute(t, f.router, route, cert)
		decisions := f.log.take()

		assert.Equal(t, http.StatusUnauthorized, status, "%s", route)
		assert.Empty(t, decisions, "%s: an unbound certificate must not reach the gate", route)
	}
}

// TestAdminPlane_RoutePermissionsRegisteredAndGranted proves every
// resource:action the admin route tables demand (learned from the gate, not
// hand-listed) is registered in qrdb's permission registry and materialized
// into the seeded Owner role, which holds every permission by default.
//
// The admin plane declares no permission of its own: every one it demands is
// a qrdb-owned permission that qrdb registers and places on its built-in
// roles. So this test also pins that ownership -- a route demanding a
// permission qrdb does not know fails here rather than as a production 403,
// and there is no xkms-side registration that could drift from the routes.
// Placement on the other built-in roles is qrdb's decision, deliberately not
// restated here (the Admin role, for one, does not hold roles:create,
// roles:update or roles:delete).
func TestAdminPlane_RoutePermissionsRegisteredAndGranted(t *testing.T) {
	f := newAdminAuthzFixture(t)
	cert := f.adminCert

	demanded := map[string]bool{}
	for _, route := range f.routes {
		serveAdminRoute(t, f.router, route, cert)
		for _, d := range f.log.take() {
			demanded[d.permission] = true
		}
	}
	require.NotEmpty(t, demanded)

	owner := systemRole(t, f.client, qrdbsdk.RoleNameOwner)
	for perm := range demanded {
		assert.True(t, qrdbsdk.IsPermissionRegistered(qrdbsdk.Permission(perm)),
			"admin route permission %s is not registered with qrdb", perm)
		assert.True(t, slices.Contains(owner.Permissions, perm),
			"seeded Owner role does not hold admin route permission %s", perm)
	}
}
