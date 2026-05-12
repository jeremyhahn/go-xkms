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

package admin

import (
	"context"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Service defines the interface for admin operations
type Service interface {
	// Certificate operations
	ListCertificates(ctx context.Context, req ListCertificatesRequest) ([]*CertificateInfo, *Pagination, error)
	GetCertificate(ctx context.Context, serial string) (*CertificateInfo, error)
	RevokeCertificate(ctx context.Context, serial string, reason string) error
	ListExpiringCertificates(ctx context.Context, days int, page, perPage int) ([]*CertificateInfo, *Pagination, error)

	// Account operations
	ListAccounts(ctx context.Context, req ListAccountsRequest) ([]*AccountInfo, *Pagination, error)
	GetAccount(ctx context.Context, accountID uint64) (*AccountInfo, error)
	DisableAccount(ctx context.Context, accountID uint64) error

	// Order operations
	ListOrders(ctx context.Context, req ListOrdersRequest) ([]*OrderInfo, *Pagination, error)
	GetOrder(ctx context.Context, orderID uint64, accountID uint64) (*OrderInfo, error)

	// Status operations
	GetStatus(ctx context.Context) (*CAStatus, error)
	GetStats(ctx context.Context) (*CAStats, error)
}

// TenantService defines the interface for tenant management operations.
// This interface is implemented when multi-tenancy is enabled.
type TenantService interface {
	// Tenant CRUD operations
	CreateTenant(ctx context.Context, req CreateTenantRequest) (*TenantInfo, error)
	GetTenant(ctx context.Context, tenantID string) (*TenantInfo, error)
	UpdateTenant(ctx context.Context, tenantID string, req UpdateTenantRequest) (*TenantInfo, error)
	UpdateTenantStatus(ctx context.Context, tenantID string, status string) error
	DeleteTenant(ctx context.Context, tenantID string) error
	ListTenants(ctx context.Context, req ListTenantsRequest) ([]*TenantInfo, *Pagination, error)

	// Tenant CA operations
	CreateTenantRootCA(ctx context.Context, tenantID string, req CreateTenantRootCARequest) (*TenantRootCAInfo, error)
	CreateTenantIntermediateCA(ctx context.Context, tenantID string, req CreateTenantIntermediateCARequest) (*TenantIntCAInfo, error)
	GetTenantIntermediateCA(ctx context.Context, tenantID string, caID string) (*TenantIntCAInfo, error)
	ListTenantIntermediateCAs(ctx context.Context, tenantID string) ([]*TenantIntCAInfo, error)
	UpdateTenantIntermediateCAStatus(ctx context.Context, tenantID string, caID string, status string) error
	SetTenantDefaultIntermediateCA(ctx context.Context, tenantID string, caID string) error
	GetTenantCAStatus(ctx context.Context, tenantID string) (*TenantCAStatusInfo, error)

	// Tenant EAB operations
	CreateTenantEAB(ctx context.Context, tenantID string, req CreateEABRequest) (*CreateEABResponse, error)
	GetTenantEAB(ctx context.Context, tenantID string, kid string) (*EABInfo, error)
	DeleteTenantEAB(ctx context.Context, tenantID string, kid string) error
	ListTenantEABs(ctx context.Context, tenantID string, req ListEABRequest) ([]*EABInfo, *Pagination, error)

	// Tenant Role operations (RBAC) - delegates to QRDB SDK
	CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error)
	GetTenantRole(ctx context.Context, tenantID string, roleID string) (*db.Role, error)
	UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error)
	DeleteTenantRole(ctx context.Context, tenantID string, roleID string) error
	ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error)

	// Tenant User operations (RBAC) - delegates to QRDB SDK
	CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error)
	GetTenantUser(ctx context.Context, tenantID string, userID string) (*db.User, error)
	UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error)
	DeleteTenantUser(ctx context.Context, tenantID string, userID string) error
	ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error)
}

// TenantAwareService combines Service with TenantService for multi-tenant deployments.
type TenantAwareService interface {
	Service
	TenantService

	// BarrierSvc returns the barrier service for seal/unseal operations.
	BarrierSvc() BarrierService

	// SetupSvc returns the setup service for first-run initialization.
	SetupSvc() SetupService
}

// Ensure AdminService implements Service interface
var _ Service = (*AdminService)(nil)
