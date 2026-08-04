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

package storage

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// Factory creates GenericDAO instances with proper key prefixing.
// All DAOs returned are qrdbsdk.GenericDAO instances that provide
// type-safe CRUD operations, pagination, and index-based queries.
type Factory interface {
	// AccountDAO returns a GenericDAO for ACME accounts.
	AccountDAO() (qrdbsdk.GenericDAO[*entities.ACMEAccount], error)

	// OrderDAO returns a GenericDAO for ACME orders scoped to a specific account.
	OrderDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEOrder], error)

	// AuthorizationDAO returns a GenericDAO for ACME authorizations scoped to a specific account.
	AuthorizationDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEAuthorization], error)

	// ChallengeDAO returns a GenericDAO for ACME challenges scoped to a specific account.
	ChallengeDAO(accountID uint64) (qrdbsdk.GenericDAO[*entities.ACMEChallenge], error)

	// CertificateDAO returns a GenericDAO for ACME certificates.
	CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error)

	// NonceDAO returns a GenericDAO for ACME nonces.
	NonceDAO() (qrdbsdk.GenericDAO[*entities.ACMENonce], error)

	// ExternalAccountBindingDAO returns a GenericDAO for external account bindings.
	ExternalAccountBindingDAO() (qrdbsdk.GenericDAO[*entities.ExternalAccountBinding], error)
}

// TenantAwareFactory extends Factory with tenant-scoped DAO creation.
// In multi-tenant deployments, DAOs created by this factory operate within
// a specific tenant's data namespace.
type TenantAwareFactory interface {
	Factory

	// TenantDAO returns a GenericDAO for managing tenants.
	// This is only accessible to super-admin roles.
	TenantDAO() (qrdbsdk.GenericDAO[*entities.Tenant], error)

	// ForTenant returns a tenant-scoped Factory.
	// All DAOs created by the returned factory operate within the specified tenant's namespace.
	ForTenant(tenantID string) (Factory, error)

	// GetTenantID returns the current tenant ID, or empty string if not in tenant context.
	GetTenantID() string
}
