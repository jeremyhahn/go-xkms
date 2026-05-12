// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package embedded

import (
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
)

// AdminServicer defines the interface for Admin REST service handlers.
// This interface matches the admin handler patterns from pkg/api/rest/
// but is defined here to avoid circular dependencies in the SDK.
type AdminServicer interface {
	StatusHandler(w http.ResponseWriter, r *http.Request)
	StatsHandler(w http.ResponseWriter, r *http.Request)
	ListCertificatesHandler(w http.ResponseWriter, r *http.Request)
	GetCertificateHandler(w http.ResponseWriter, r *http.Request)
	RevokeCertificateHandler(w http.ResponseWriter, r *http.Request)
	ListAccountsHandler(w http.ResponseWriter, r *http.Request)
	GetAccountHandler(w http.ResponseWriter, r *http.Request)
	DisableAccountHandler(w http.ResponseWriter, r *http.Request)
	CreateTenantHandler(w http.ResponseWriter, r *http.Request)
	ListTenantsHandler(w http.ResponseWriter, r *http.Request)
	GetTenantHandler(w http.ResponseWriter, r *http.Request)
	UpdateTenantHandler(w http.ResponseWriter, r *http.Request)
	DeleteTenantHandler(w http.ResponseWriter, r *http.Request)
	UpdateTenantStatusHandler(w http.ResponseWriter, r *http.Request)
	CreateEABHandler(w http.ResponseWriter, r *http.Request)
	ListEABHandler(w http.ResponseWriter, r *http.Request)
	GetEABHandler(w http.ResponseWriter, r *http.Request)
	DeleteEABHandler(w http.ResponseWriter, r *http.Request)
	CreateRoleHandler(w http.ResponseWriter, r *http.Request)
	ListRolesHandler(w http.ResponseWriter, r *http.Request)
	GetRoleHandler(w http.ResponseWriter, r *http.Request)
	UpdateRoleHandler(w http.ResponseWriter, r *http.Request)
	DeleteRoleHandler(w http.ResponseWriter, r *http.Request)
	CreateUserHandler(w http.ResponseWriter, r *http.Request)
	ListUsersHandler(w http.ResponseWriter, r *http.Request)
	GetUserHandler(w http.ResponseWriter, r *http.Request)
	UpdateUserHandler(w http.ResponseWriter, r *http.Request)
	DeleteUserHandler(w http.ResponseWriter, r *http.Request)
	ListOrdersHandler(w http.ResponseWriter, r *http.Request)
	GetOrderHandler(w http.ResponseWriter, r *http.Request)
	CreateRootCAHandler(w http.ResponseWriter, r *http.Request)
	CAStatusHandler(w http.ResponseWriter, r *http.Request)
	CreateIntermediateCAHandler(w http.ResponseWriter, r *http.Request)
	ListIntermediateCAsHandler(w http.ResponseWriter, r *http.Request)
	GetIntermediateCAHandler(w http.ResponseWriter, r *http.Request)
	UpdateIntermediateCAStatusHandler(w http.ResponseWriter, r *http.Request)
}

// WithAdminService sets the Admin REST service for the embedded transport.
func WithAdminService(svc AdminServicer) Option {
	return func(t *Transport) error {
		if svc == nil {
			return errors.NewInvalidInput("embedded.WithAdminService", "admin service cannot be nil")
		}
		t.adminService = svc
		return nil
	}
}

// initAdminHandlers initializes admin handler dispatch entries if an admin service is configured.
func (t *Transport) initAdminHandlers() {
	if t.adminService == nil {
		return
	}

	adminHandlers := map[routeKey]HandlerFunc{
		// Status
		{service: "admin.status", method: "status"}: t.adminService.StatusHandler,
		{service: "admin.status", method: "stats"}:  t.adminService.StatsHandler,

		// Certificate
		{service: "admin.certificate", method: "list"}:   t.adminService.ListCertificatesHandler,
		{service: "admin.certificate", method: "get"}:    t.adminService.GetCertificateHandler,
		{service: "admin.certificate", method: "revoke"}: t.adminService.RevokeCertificateHandler,

		// Account
		{service: "admin.account", method: "list"}:    t.adminService.ListAccountsHandler,
		{service: "admin.account", method: "get"}:     t.adminService.GetAccountHandler,
		{service: "admin.account", method: "disable"}: t.adminService.DisableAccountHandler,

		// Tenant
		{service: "admin.tenant", method: "create"}:       t.adminService.CreateTenantHandler,
		{service: "admin.tenant", method: "list"}:         t.adminService.ListTenantsHandler,
		{service: "admin.tenant", method: "get"}:          t.adminService.GetTenantHandler,
		{service: "admin.tenant", method: "update"}:       t.adminService.UpdateTenantHandler,
		{service: "admin.tenant", method: "delete"}:       t.adminService.DeleteTenantHandler,
		{service: "admin.tenant", method: "updateStatus"}: t.adminService.UpdateTenantStatusHandler,

		// EAB
		{service: "admin.eab", method: "create"}: t.adminService.CreateEABHandler,
		{service: "admin.eab", method: "list"}:   t.adminService.ListEABHandler,
		{service: "admin.eab", method: "get"}:    t.adminService.GetEABHandler,
		{service: "admin.eab", method: "delete"}: t.adminService.DeleteEABHandler,

		// Role
		{service: "admin.role", method: "create"}: t.adminService.CreateRoleHandler,
		{service: "admin.role", method: "list"}:   t.adminService.ListRolesHandler,
		{service: "admin.role", method: "get"}:    t.adminService.GetRoleHandler,
		{service: "admin.role", method: "update"}: t.adminService.UpdateRoleHandler,
		{service: "admin.role", method: "delete"}: t.adminService.DeleteRoleHandler,

		// User
		{service: "admin.user", method: "create"}: t.adminService.CreateUserHandler,
		{service: "admin.user", method: "list"}:   t.adminService.ListUsersHandler,
		{service: "admin.user", method: "get"}:    t.adminService.GetUserHandler,
		{service: "admin.user", method: "update"}: t.adminService.UpdateUserHandler,
		{service: "admin.user", method: "delete"}: t.adminService.DeleteUserHandler,

		// Order
		{service: "admin.order", method: "list"}: t.adminService.ListOrdersHandler,
		{service: "admin.order", method: "get"}:  t.adminService.GetOrderHandler,

		// Tenant CA
		{service: "admin.tenant.ca", method: "createRootCA"}:               t.adminService.CreateRootCAHandler,
		{service: "admin.tenant.ca", method: "status"}:                     t.adminService.CAStatusHandler,
		{service: "admin.tenant.ca", method: "createIntermediateCA"}:       t.adminService.CreateIntermediateCAHandler,
		{service: "admin.tenant.ca", method: "listIntermediateCAs"}:        t.adminService.ListIntermediateCAsHandler,
		{service: "admin.tenant.ca", method: "getIntermediateCA"}:          t.adminService.GetIntermediateCAHandler,
		{service: "admin.tenant.ca", method: "updateIntermediateCAStatus"}: t.adminService.UpdateIntermediateCAStatusHandler,
	}

	for k, v := range adminHandlers {
		t.handlers[k] = v
	}
}

// isAdminService returns true if the service name is an admin service.
func isAdminService(service string) bool {
	return strings.HasPrefix(service, "admin.")
}
