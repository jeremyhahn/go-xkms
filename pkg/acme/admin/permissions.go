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

package admin

import qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

// Trusted CA permission constants in "resource:action" format.
const (
	// Certificate permissions
	PermCertificatesRead   qrdbsdk.Permission = "certificates:read"
	PermCertificatesList   qrdbsdk.Permission = "certificates:list"
	PermCertificatesCreate qrdbsdk.Permission = "certificates:create"
	PermCertificatesRevoke qrdbsdk.Permission = "certificates:revoke"

	// Account permissions
	PermAccountsRead    qrdbsdk.Permission = "accounts:read"
	PermAccountsList    qrdbsdk.Permission = "accounts:list"
	PermAccountsDisable qrdbsdk.Permission = "accounts:disable"

	// Order permissions
	PermOrdersRead qrdbsdk.Permission = "orders:read"
	PermOrdersList qrdbsdk.Permission = "orders:list"

	// Tenant permissions
	PermTenantsRead   qrdbsdk.Permission = "tenants:read"
	PermTenantsList   qrdbsdk.Permission = "tenants:list"
	PermTenantsCreate qrdbsdk.Permission = "tenants:create"
	PermTenantsUpdate qrdbsdk.Permission = "tenants:update"
	PermTenantsDelete qrdbsdk.Permission = "tenants:delete"

	// Tenant CA permissions
	PermTenantCARead   qrdbsdk.Permission = "tenant-ca:read"
	PermTenantCACreate qrdbsdk.Permission = "tenant-ca:create"
	PermTenantCAUpdate qrdbsdk.Permission = "tenant-ca:update"

	// EAB permissions
	PermEABRead   qrdbsdk.Permission = "eab:read"
	PermEABList   qrdbsdk.Permission = "eab:list"
	PermEABCreate qrdbsdk.Permission = "eab:create"
	PermEABDelete qrdbsdk.Permission = "eab:delete"

	// Role/User management permissions
	PermRolesRead   qrdbsdk.Permission = "roles:read"
	PermRolesList   qrdbsdk.Permission = "roles:list"
	PermRolesCreate qrdbsdk.Permission = "roles:create"
	PermRolesUpdate qrdbsdk.Permission = "roles:update"
	PermRolesDelete qrdbsdk.Permission = "roles:delete"

	PermUsersRead   qrdbsdk.Permission = "users:read"
	PermUsersList   qrdbsdk.Permission = "users:list"
	PermUsersCreate qrdbsdk.Permission = "users:create"
	PermUsersUpdate qrdbsdk.Permission = "users:update"
	PermUsersDelete qrdbsdk.Permission = "users:delete"

	// Admin status/stats permissions
	PermAdminStatus qrdbsdk.Permission = "admin:status"
	PermAdminStats  qrdbsdk.Permission = "admin:stats"

	// Barrier/Setup permissions
	PermBarrierRead   qrdbsdk.Permission = "barrier:read"
	PermBarrierManage qrdbsdk.Permission = "barrier:manage"
	PermSetupRead     qrdbsdk.Permission = "setup:read"
	PermSetupManage   qrdbsdk.Permission = "setup:manage"

	// Audit log permissions
	PermAuditRead qrdbsdk.Permission = "audit:read"

	// Write/delete variants used by integration tests and RBAC
	PermCertificatesWrite  qrdbsdk.Permission = "certificates:write"
	PermCertificatesDelete qrdbsdk.Permission = "certificates:delete"
	PermAccountsWrite      qrdbsdk.Permission = "accounts:write"
	PermAccountsCreate     qrdbsdk.Permission = "accounts:create"
	PermAccountsDelete     qrdbsdk.Permission = "accounts:delete"
	PermTenantsWrite       qrdbsdk.Permission = "tenants:write"
	PermEABWrite           qrdbsdk.Permission = "eab:write"
	PermRolesWrite         qrdbsdk.Permission = "roles:write"
	PermUsersWrite         qrdbsdk.Permission = "users:write"

	// Nested tenant resource permissions (resource:action format)
	PermTenantsCertificatesRead qrdbsdk.Permission = "tenants:certificates:read"
	PermTenantsCertificatesList qrdbsdk.Permission = "tenants:certificates:list"
	PermTenantsAccountsRead     qrdbsdk.Permission = "tenants:accounts:read"
	PermTenantsAccountsList     qrdbsdk.Permission = "tenants:accounts:list"
	PermTenantsEABsRead         qrdbsdk.Permission = "tenants:eabs:read"
	PermTenantsEABsList         qrdbsdk.Permission = "tenants:eabs:list"
	PermTenantsRolesRead        qrdbsdk.Permission = "tenants:roles:read"
	PermTenantsRolesList        qrdbsdk.Permission = "tenants:roles:list"
	PermTenantsUsersRead        qrdbsdk.Permission = "tenants:users:read"
	PermTenantsUsersList        qrdbsdk.Permission = "tenants:users:list"

	// Special characters test permissions
	PermSpecialRead  qrdbsdk.Permission = "special:read"
	PermSpecialWrite qrdbsdk.Permission = "special:write"
)

func init() {
	qrdbsdk.RegisterPermissions(
		PermCertificatesRead, PermCertificatesList, PermCertificatesCreate, PermCertificatesRevoke,
		PermAccountsRead, PermAccountsList, PermAccountsDisable,
		PermOrdersRead, PermOrdersList,
		PermTenantsRead, PermTenantsList, PermTenantsCreate, PermTenantsUpdate, PermTenantsDelete,
		PermTenantCARead, PermTenantCACreate, PermTenantCAUpdate,
		PermEABRead, PermEABList, PermEABCreate, PermEABDelete,
		PermRolesRead, PermRolesList, PermRolesCreate, PermRolesUpdate, PermRolesDelete,
		PermUsersRead, PermUsersList, PermUsersCreate, PermUsersUpdate, PermUsersDelete,
		PermAdminStatus, PermAdminStats,
		PermBarrierRead, PermBarrierManage,
		PermSetupRead, PermSetupManage,
		PermAuditRead,
		PermCertificatesWrite, PermCertificatesDelete,
		PermAccountsWrite, PermAccountsCreate, PermAccountsDelete,
		PermTenantsWrite,
		PermEABWrite,
		PermRolesWrite,
		PermUsersWrite,
		PermTenantsCertificatesRead, PermTenantsCertificatesList,
		PermTenantsAccountsRead, PermTenantsAccountsList,
		PermTenantsEABsRead, PermTenantsEABsList,
		PermTenantsRolesRead, PermTenantsRolesList,
		PermTenantsUsersRead, PermTenantsUsersList,
		PermSpecialRead, PermSpecialWrite,
	)
}
