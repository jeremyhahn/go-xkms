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

import (
	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Tenant types.
type TenantInfo = pkgtransport.TenantInfo
type CreateTenantRequest = pkgtransport.CreateTenantRequest
type CreateTenantResponse = pkgtransport.CreateTenantResponse
type GetTenantResponse = pkgtransport.GetTenantResponse
type ListTenantsResponse = pkgtransport.ListTenantsResponse

// TenantIsolationType identifies a tenant's isolation mode (prefix / barrier /
// volume / raft).
type TenantIsolationType = pkgtransport.TenantIsolationType

// TenantQuotas describes a tenant's resource quotas.
type TenantQuotas = pkgtransport.TenantQuotas

// TenantEntitlements describes which isolation tiers and dedicated-storage
// features a tenant's plan permits.
type TenantEntitlements = pkgtransport.TenantEntitlements

// UpdateTenantEntitlementsRequest updates a tenant's feature entitlements.
type UpdateTenantEntitlementsRequest = pkgtransport.UpdateTenantEntitlementsRequest

// UpdateTenantEntitlementsResponse contains the updated tenant.
type UpdateTenantEntitlementsResponse = pkgtransport.UpdateTenantEntitlementsResponse

// UpdateTenantQuotasRequest updates a tenant's resource quotas.
type UpdateTenantQuotasRequest = pkgtransport.UpdateTenantQuotasRequest

// UpdateTenantQuotasResponse contains the updated tenant.
type UpdateTenantQuotasResponse = pkgtransport.UpdateTenantQuotasResponse
