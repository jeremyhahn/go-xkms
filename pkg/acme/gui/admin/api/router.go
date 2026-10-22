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

// Package api implements the embedded REST API router for the admin GUI.
// Each handler delegates operations to the SDK client and returns a JSON
// response matching the admin API format.
package api

import (
	"log/slog"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/guard"
	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// NewRouter creates a gorilla/mux router with all admin GUI API routes.
// The router is reachable only through the Wails AssetServer Handler of the
// admin desktop application; opts must include WithInProcessTransport for
// that deployment, matching the ACME client GUI API's policy in
// pkg/acme/gui/client/api.
//
// The routes are the ACME admin API's own paths (pkg/acme/admin Routes):
// /admin/* for the CA-wide views and /api/v1/tenants/* for tenant
// management. The admin SPA calls exactly these paths, so the one bundle
// works unchanged against this desktop router and against xkmsd's
// /admin-ui host, which mounts the ACME admin API itself.
func NewRouter(client trustedca.Client, logger *slog.Logger, opts ...Option) *mux.Router {
	r := mux.NewRouter()
	h := newHandlers(client, logger)

	r.Use(guard.New(logger, denyOrigin, opts...).Middleware)

	admin := r.PathPrefix("/admin").Subrouter()

	// Status
	admin.HandleFunc("/status", h.getStatus).Methods("GET")
	admin.HandleFunc("/stats", h.getStats).Methods("GET")

	// Certificates
	admin.HandleFunc("/certificates", h.listCertificates).Methods("GET")
	admin.HandleFunc("/certificates/{serial}", h.getCertificate).Methods("GET")
	admin.HandleFunc("/certificates/{serial}/revoke", h.revokeCertificate).Methods("POST")

	// Accounts
	admin.HandleFunc("/accounts", h.listAccounts).Methods("GET")
	admin.HandleFunc("/accounts/{id}", h.getAccount).Methods("GET")
	admin.HandleFunc("/accounts/{id}", h.disableAccount).Methods("DELETE")

	// Orders
	admin.HandleFunc("/orders", h.listOrders).Methods("GET")
	admin.HandleFunc("/orders/{id}", h.getOrder).Methods("GET")

	tenants := r.PathPrefix("/api/v1/tenants").Subrouter()

	// Tenants. Create, list, get and delete take the paths of their one
	// owner, the core xkms REST table (pkg/api/rest Routes, go-xkms#794):
	// the collection is "/api/v1/tenants/", with the trailing slash.
	tenants.HandleFunc("/", h.listTenants).Methods("GET")
	tenants.HandleFunc("/", h.createTenant).Methods("POST")
	tenants.HandleFunc("/{id}", h.getTenant).Methods("GET")
	tenants.HandleFunc("/{id}", h.updateTenant).Methods("PUT")
	tenants.HandleFunc("/{id}", h.deleteTenant).Methods("DELETE")
	tenants.HandleFunc("/{id}/status", h.updateTenantStatus).Methods("PUT")

	// Tenant CA Operations
	tenants.HandleFunc("/{id}/root-ca", h.createTenantRootCA).Methods("POST")
	tenants.HandleFunc("/{id}/ca-status", h.getTenantCAStatus).Methods("GET")
	tenants.HandleFunc("/{id}/intermediate-cas", h.createIntermediateCA).Methods("POST")
	tenants.HandleFunc("/{id}/intermediate-cas/{caId}/status", h.updateIntermediateCAStatus).Methods("PUT")

	// Tenant EAB
	tenants.HandleFunc("/{id}/eab", h.listEABs).Methods("GET")
	tenants.HandleFunc("/{id}/eab", h.createEAB).Methods("POST")
	tenants.HandleFunc("/{id}/eab/{eabId}", h.deleteEAB).Methods("DELETE")

	// Tenant Roles
	tenants.HandleFunc("/{id}/roles", h.listRoles).Methods("GET")
	tenants.HandleFunc("/{id}/roles", h.createRole).Methods("POST")
	tenants.HandleFunc("/{id}/roles/{roleId}", h.getRole).Methods("GET")
	tenants.HandleFunc("/{id}/roles/{roleId}", h.updateRole).Methods("PUT")
	tenants.HandleFunc("/{id}/roles/{roleId}", h.deleteRole).Methods("DELETE")

	// Tenant Users
	tenants.HandleFunc("/{id}/users", h.listUsers).Methods("GET")
	tenants.HandleFunc("/{id}/users", h.createUser).Methods("POST")
	tenants.HandleFunc("/{id}/users/{userId}", h.getUser).Methods("GET")
	tenants.HandleFunc("/{id}/users/{userId}", h.updateUser).Methods("PUT")
	tenants.HandleFunc("/{id}/users/{userId}", h.deleteUser).Methods("DELETE")

	return r
}
