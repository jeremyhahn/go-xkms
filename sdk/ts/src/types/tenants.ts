// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * Tenant DTOs. Requests/responses mirror pkg/api/rest/handlers_tenant.go
 * local shapes; entitlements/quotas mirror go-qrdb/sdk/go/transport
 * tenant_types.go (the handlers decode/encode those transport shapes
 * directly for PUT entitlements/quotas).
 */

import type { Base64, PageResponse, RFC3339 } from './common.js';

/** Mirrors pkg/api/rest/handlers_tenant.go createTenantRequest. */
export interface CreateTenantRequest {
  id: string;
  name: string;
  isolation_type?: string;
  barrier_auto_unseal?: boolean;
}

/** Mirrors pkg/api/rest/handlers_tenant.go tenantInfoResponse. */
export interface TenantInfoResponse {
  id: string;
  name?: string;
  sealed: boolean;
  isolation_type?: string;
  created_at?: string;
  updated_at?: string;
}

/** Mirrors pkg/api/rest/handlers_tenant.go wrappedTenantResponse. */
export interface WrappedTenantResponse {
  tenant: TenantInfoResponse;
}

/** Mirrors pkg/api/rest/handlers_tenant.go listTenantsResponse. */
export interface ListTenantsResponse {
  tenants: TenantInfoResponse[];
  pagination: PageResponse;
}

/** Mirrors pkg/api/rest/handlers_tenant.go tenantBarrierStatusResponse. */
export interface TenantBarrierStatusResponse {
  tenant_id: string;
  sealed: boolean;
  strategy?: string;
  hardware_backed: boolean;
  /** Present when the servicer path reports full status (qrdb transport shape). */
  initialized?: boolean;
  shamir_threshold?: number;
  shamir_total?: number;
}

/** Mirrors pkg/api/rest/handlers_tenant.go tenantBarrierInitRequest. */
export interface TenantBarrierInitRequest {
  passphrase?: string;
  strategy?: string;
  threshold?: number;
  shares?: number;
}

/** Mirrors pkg/api/rest/handlers_tenant.go tenantBarrierUnsealRequest. */
export interface TenantBarrierUnsealRequest {
  share?: Base64;
  key?: Base64;
}

/** Mirrors go-qrdb/sdk/go/transport tenant_types.go TenantQuotas. */
export interface TenantQuotas {
  max_databases: number;
  max_raft_groups: number;
  max_replicas_per_group: number;
  max_total_replicas: number;
  max_collections: number;
  max_keys: number;
  max_storage_bytes: number;
  max_database_size_bytes: number;
  max_users: number;
  max_roles: number;
  max_certificates: number;
  max_backups: number;
  max_vector_dims: number;
  max_ts_metrics: number;
  system_barrier_quota: number;
  max_dedicated_wal_groups: number;
}

/** Mirrors go-qrdb/sdk/go/transport tenant_types.go TenantEntitlements. */
export interface TenantEntitlements {
  allowed_isolation_modes?: string[];
  allow_dedicated_raft?: boolean;
  allow_volume_storage?: boolean;
  allow_system_managed_barrier?: boolean;
  allowed_barrier_modes?: string[];
  allow_dedicated_wal?: boolean;
}

/** Mirrors go-qrdb/sdk/go/transport tenant_types.go TenantInfo. */
export interface TenantInfo {
  id: string;
  name: string;
  isolation_type?: string;
  data_root?: string;
  quotas?: TenantQuotas;
  entitlements?: TenantEntitlements;
  created_at: RFC3339;
  updated_at: RFC3339;
}

/** Mirrors go-qrdb transport UpdateTenantEntitlementsRequest. */
export interface UpdateTenantEntitlementsRequest {
  tenant_id: string;
  entitlements: TenantEntitlements;
}

/** Mirrors go-qrdb transport UpdateTenantEntitlementsResponse. */
export interface UpdateTenantEntitlementsResponse {
  tenant: TenantInfo;
}

/** Mirrors go-qrdb transport UpdateTenantQuotasRequest. */
export interface UpdateTenantQuotasRequest {
  tenant_id: string;
  quotas: TenantQuotas;
}

/** Mirrors go-qrdb transport UpdateTenantQuotasResponse. */
export interface UpdateTenantQuotasResponse {
  tenant: TenantInfo;
}

/**
 * Mirrors pkg/api/transport/types.go TenantTPMModeResponse. System-scope
 * only: a tenant-scoped caller is refused even for its own tenant.
 */
export interface TenantTPMModeResponse {
  tenant_id: string;
  /** "none", "shared" or "vtpm". */
  mode: string;
}

/**
 * Mirrors pkg/api/transport/types.go SetTenantTPMModeRequest. Refused while
 * the tenant's scope holds objects or policies, which cannot move between
 * TPMs.
 */
export interface SetTenantTPMModeRequest {
  tenant_id: string;
  mode: string;
  owner_auth?: Base64;
}

/** Mirrors pkg/api/transport/types.go TenantVTPMStatusResponse. */
export interface TenantVTPMStatusResponse {
  tenant_id: string;
  running: boolean;
  pid?: number;
  socket?: string;
  restarts?: number;
}
