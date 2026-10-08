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

package transport

import qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

// --- Tenant types aliased from go-qrdb ---

// TenantInfo contains information about a tenant.
type TenantInfo = qrdbtransport.TenantInfo

// CreateTenantRequest contains parameters for creating a tenant.
type CreateTenantRequest = qrdbtransport.CreateTenantRequest

// CreateTenantResponse contains the created tenant.
type CreateTenantResponse = qrdbtransport.CreateTenantResponse

// GetTenantResponse contains a tenant.
type GetTenantResponse = qrdbtransport.GetTenantResponse

// ListTenantsResponse contains a list of tenants.
type ListTenantsResponse = qrdbtransport.ListTenantsResponse

// TenantIsolationType identifies a tenant's isolation mode (prefix / barrier /
// volume / raft).
type TenantIsolationType = qrdbtransport.TenantIsolationType

// TenantQuotas describes a tenant's resource quotas.
type TenantQuotas = qrdbtransport.TenantQuotas

// TenantEntitlements describes which isolation tiers and dedicated-storage
// features a tenant's plan permits.
type TenantEntitlements = qrdbtransport.TenantEntitlements

// UpdateTenantEntitlementsRequest updates a tenant's feature entitlements.
type UpdateTenantEntitlementsRequest = qrdbtransport.UpdateTenantEntitlementsRequest

// UpdateTenantEntitlementsResponse contains the updated tenant.
type UpdateTenantEntitlementsResponse = qrdbtransport.UpdateTenantEntitlementsResponse

// UpdateTenantQuotasRequest updates a tenant's resource quotas.
type UpdateTenantQuotasRequest = qrdbtransport.UpdateTenantQuotasRequest

// UpdateTenantQuotasResponse contains the updated tenant.
type UpdateTenantQuotasResponse = qrdbtransport.UpdateTenantQuotasResponse
