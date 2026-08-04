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
	"net/http"

	"github.com/gorilla/mux"

	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// NewRouter creates a gorilla/mux router with all admin GUI API routes.
func NewRouter(client trustedca.Client, logger *slog.Logger) *mux.Router {
	r := mux.NewRouter()
	h := newHandlers(client, logger)

	r.Use(corsMiddleware)

	v1 := r.PathPrefix("/api/v1").Subrouter()

	// Status
	v1.HandleFunc("/status", h.getStatus).Methods("GET")
	v1.HandleFunc("/stats", h.getStats).Methods("GET")

	// Certificates (expiring must be registered before the {serial} catch-all)
	v1.HandleFunc("/certificates/expiring", h.listExpiringCertificates).Methods("GET")
	v1.HandleFunc("/certificates", h.listCertificates).Methods("GET")
	v1.HandleFunc("/certificates/{serial}", h.getCertificate).Methods("GET")
	v1.HandleFunc("/certificates/{serial}/revoke", h.revokeCertificate).Methods("POST")

	// Orders
	v1.HandleFunc("/orders", h.listOrders).Methods("GET")
	v1.HandleFunc("/orders/{id}", h.getOrder).Methods("GET")

	// Accounts
	v1.HandleFunc("/accounts", h.listAccounts).Methods("GET")
	v1.HandleFunc("/accounts/{id}", h.getAccount).Methods("GET")
	v1.HandleFunc("/accounts/{id}", h.disableAccount).Methods("DELETE")

	// Tenants
	v1.HandleFunc("/tenants", h.listTenants).Methods("GET")
	v1.HandleFunc("/tenants", h.createTenant).Methods("POST")
	v1.HandleFunc("/tenants/{id}", h.getTenant).Methods("GET")
	v1.HandleFunc("/tenants/{id}", h.updateTenant).Methods("PUT")
	v1.HandleFunc("/tenants/{id}", h.deleteTenant).Methods("DELETE")
	v1.HandleFunc("/tenants/{id}/status", h.updateTenantStatus).Methods("PUT")

	// Tenant CA Operations
	v1.HandleFunc("/tenants/{id}/root-ca", h.createTenantRootCA).Methods("POST")
	v1.HandleFunc("/tenants/{id}/ca-status", h.getTenantCAStatus).Methods("GET")
	v1.HandleFunc("/tenants/{id}/intermediate-cas", h.listIntermediateCAs).Methods("GET")
	v1.HandleFunc("/tenants/{id}/intermediate-cas", h.createIntermediateCA).Methods("POST")
	v1.HandleFunc("/tenants/{id}/intermediate-cas/{caId}", h.getIntermediateCA).Methods("GET")
	v1.HandleFunc("/tenants/{id}/intermediate-cas/{caId}", h.updateIntermediateCAStatus).Methods("PUT")

	// Tenant EAB
	v1.HandleFunc("/tenants/{id}/eab", h.listEABs).Methods("GET")
	v1.HandleFunc("/tenants/{id}/eab", h.createEAB).Methods("POST")
	v1.HandleFunc("/tenants/{id}/eab/{eabId}", h.getEAB).Methods("GET")
	v1.HandleFunc("/tenants/{id}/eab/{eabId}", h.deleteEAB).Methods("DELETE")

	// Tenant Roles
	v1.HandleFunc("/tenants/{id}/roles", h.listRoles).Methods("GET")
	v1.HandleFunc("/tenants/{id}/roles", h.createRole).Methods("POST")
	v1.HandleFunc("/tenants/{id}/roles/{roleId}", h.getRole).Methods("GET")
	v1.HandleFunc("/tenants/{id}/roles/{roleId}", h.updateRole).Methods("PUT")
	v1.HandleFunc("/tenants/{id}/roles/{roleId}", h.deleteRole).Methods("DELETE")

	// Tenant Users
	v1.HandleFunc("/tenants/{id}/users", h.listUsers).Methods("GET")
	v1.HandleFunc("/tenants/{id}/users", h.createUser).Methods("POST")
	v1.HandleFunc("/tenants/{id}/users/{userId}", h.getUser).Methods("GET")
	v1.HandleFunc("/tenants/{id}/users/{userId}", h.updateUser).Methods("PUT")
	v1.HandleFunc("/tenants/{id}/users/{userId}", h.deleteUser).Methods("DELETE")

	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
