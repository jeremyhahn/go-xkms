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

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	adminweb "github.com/jeremyhahn/go-xkms/pkg/acme/web/packages/admin"
	"github.com/jeremyhahn/go-xkms/pkg/apimodule"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// ErrAdminQRDBClientRequired is returned by finalizeAdminModule when the
// embedded qrdb node has not published its SDK client
// (server.Server.QRDBClient returns nil). The ACME admin service delegates
// tenant identity, roles and users to that node, so construction is refused
// rather than publishing a surface that cannot serve them.
var ErrAdminQRDBClientRequired = errors.New("admin: qrdb client is required to build the ACME admin service")

// ErrAdminXKMSServiceRequired is returned by finalizeAdminModule when the
// server has not composed its XKMSService (server.Server.XKMSService returns
// nil). The admin plane's /admin/barrier/* routes operate the system barrier
// only through the XKMSService, whose platform-scope check refuses a
// tenant-scoped caller (go-xkms#1244); there is no other barrier handle to
// give them.
var ErrAdminXKMSServiceRequired = errors.New("admin: xkms service is required to mount the ACME admin barrier routes")

// adminUIPrefix is the admin SPA's mount prefix on the unified server.
// Deliberately distinct from the crypto-plane Module's "/ui" (WithWebUI in
// pkg/apimodule/module.go): the two SPAs are independent applications with
// independent asset bundles.
const adminUIPrefix = "/admin-ui"

// adminRoutes converts the ACME admin API's route table
// (pkg/acme/admin's Routes) into the routes apimodule.AdminModule mounts on
// the unified server, each with its own qrdb permission: qrdb's
// authentication chain refuses an anonymous caller and its RBAC decision
// refuses a caller without the route's grant before the admin router runs.
//
// The admin package binds the caller's tenant itself: its authentication
// boundary binds the caller's tenant as the context's qrdb tenant
// (pkg/acme/admin withUser), which confines every identity-plane call the
// admin service makes through the embedded client, and its service binds
// every tenant, role, user, account and certificate the request names to
// that tenant (pkg/acme/admin tenant_binding.go, go-xkms#1225).
func adminRoutes() []apimodule.AdminRoute {
	routes := admin.Routes()
	out := make([]apimodule.AdminRoute, len(routes))
	for i, rt := range routes {
		out[i] = apimodule.AdminRoute(rt)
	}
	return out
}

// adminRouterState holds the ACME admin surface's fully-assembled,
// self-authenticating http.Handler. It starts nil (every admin route answers
// 503) and is published once by finalizeAdminModule, after both server.New
// and startACMEServer have completed: the admin surface administers the
// same ACME CA and storage the ACME protocol listener uses, and delegates
// tenant identity to the same embedded qrdb node, so it cannot compose until
// both exist. AdminModule's RegisterHTTP runs during server.New itself
// (embedded qrdb node construction), long before either is ready, hence the
// same lazy-resolver pattern pkg/apimodule's ServiceResolver already uses
// for the crypto-plane module.
var adminRouterState atomic.Pointer[http.Handler]

// newAdminModule constructs the ACME admin ServiceModule ahead of
// server.New, so it can be registered via server.WithExtraModules before the
// embedded qrdb node — and therefore the unified mTLS listener that module
// registration mounts routes on — exists. Never wired onto the ACME
// protocol listener (startACMEServer / acme.go), which binds its own
// dedicated net.Listener for public RFC 8555 traffic.
func newAdminModule() (*apimodule.AdminModule, error) {
	uiFS, err := fs.Sub(adminweb.Assets, "dist")
	if err != nil {
		return nil, &acmeInitError{Stage: "admin SPA assets", Err: err}
	}
	return apimodule.NewAdminModule(
		func() http.Handler {
			if h := adminRouterState.Load(); h != nil {
				return *h
			}
			return nil
		},
		adminRoutes(),
		apimodule.WithAdminWebUI(adminUIPrefix, uiFS, false),
	)
}

// finalizeAdminModule builds the ACME admin surface's service, HTTP
// handlers and mTLS authentication, then publishes the resulting router so the AdminModule registered in newAdminModule
// starts serving it. Call once, after both srv (server.New) and acme
// (startACMEServer) have succeeded: the admin service administers the same
// TCG CA and ACME storage factory the ACME listener uses (acme.CA(),
// acme.StorageFactory()) and delegates tenant identity, roles, and users to
// the same embedded qrdb node (srv.TenantService(), srv.QRDBClient()).
//
// A nil acme (ACME disabled) is not an error here: the admin surface's CA-
// and storage-backed routes answer a typed "not configured" response
// (pkg/acme/admin's ErrCANotConfigured / ErrStorageNotConfigured, go-xkms#1075)
// instead of failing to mount. A nil qrdb client is a different case and IS
// an error: see ErrAdminQRDBClientRequired.
func finalizeAdminModule(srv *server.Server, acme *acmeServer, logger *slog.Logger) error {
	qrdbClient := srv.QRDBClient()
	if qrdbClient == nil {
		return &acmeInitError{
			Stage:    "resolve qrdb client for admin authorization",
			Sentinel: ErrAdminQRDBClientRequired,
		}
	}

	adminSvc, err := admin.NewTenantAwareAdminService(
		acme.CA(),
		acme.StorageFactory(),
		qrdbClient,
		logger,
		version,
	)
	if err != nil {
		return &acmeInitError{Stage: "construct tenant-aware admin service", Err: err}
	}
	adminSvc.SetTenantService(srv.TenantService())
	adminSvc.SetClusterTrustDomain(srv.TrustDomain())

	// The core /api/v1/tenants routes own the tenant lifecycle; the admin
	// service keeps each tenant's CA record beside it (go-xkms#794).
	xkmsService := srv.XKMSService()
	if xkmsService == nil {
		return &acmeInitError{
			Stage:    "resolve xkms service for the tenant records",
			Sentinel: ErrAdminXKMSServiceRequired,
		}
	}
	xkmsService.SetTenantRecords(adminSvc)

	handlers := admin.NewHandlers(adminSvc, logger)
	tenantHandlers := admin.NewTenantHandlers(adminSvc, logger)

	// The client certificate is resolved to its qrdb user through the same
	// SPKI-thumbprint store the crypto plane's mTLS authenticator uses, so the
	// identity the handlers bind their tenant checks to carries the user's
	// tenant and qrdb role IDs (go-xkms#1069). The certificate's tenant is
	// read under the deployment's own trust domain, and its thumbprint is
	// looked up in that tenant only, so a tenant user authenticates in its
	// own tenant (go-xkms#1240).
	mtlsConfig := &auth.MTLSConfig{UserStore: srv.QRDBUserStore()}
	authHandler := admin.NewMTLSAuthHandler(auth.NewMTLSAuthenticator(mtlsConfig), srv.TrustDomain())

	// The unified server authorizes every route against its own permission
	// before this router runs (apimodule.AdminModule mounts adminRoutes), so
	// the routes are registered without a second, per-route gate. The tenant
	// lifecycle routes, gated by the tenant they reach, are mounted there
	// identity-gated and authorized here by gate.
	gate := admin.NewPermissionGate(auth.NewAuthorizer(qrdbClient.RBAC()), logger)
	router := mux.NewRouter()
	handlers.RegisterAuthorizedRoutes(router, authHandler, gate)
	tenantHandlers.RegisterAuthorizedRoutes(router, authHandler, gate)

	var h http.Handler = router
	adminRouterState.Store(&h)

	logger.Info("ACME admin surface mounted on the unified mTLS listener",
		slog.Int("routes", len(admin.Routes())),
		slog.String("ui_prefix", adminUIPrefix))
	return nil
}
