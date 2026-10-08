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

import type { HttpCore } from '../http.js';
import type { PageQuery } from '../types/common.js';
import type {
  CreateTenantRequest,
  ListTenantsResponse,
  SetTenantTPMModeRequest,
  TenantTPMModeResponse,
  TenantVTPMStatusResponse,
  UpdateTenantEntitlementsRequest,
  UpdateTenantEntitlementsResponse,
  UpdateTenantQuotasRequest,
  UpdateTenantQuotasResponse,
  WrappedTenantResponse,
} from '../types/tenants.js';

const BASE = '/api/v1/tenants';

function tenantPath(id: string, suffix = ''): string {
  return `${BASE}/${encodeURIComponent(id)}${suffix}`;
}

/** Tenant lifecycle, entitlements, and quotas. */
export class TenantsClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/tenants/ */
  create(req: CreateTenantRequest): Promise<WrappedTenantResponse> {
    return this.http.request('POST', `${BASE}/`, { body: req });
  }

  /** GET /api/v1/tenants/ */
  list(page?: PageQuery): Promise<ListTenantsResponse> {
    return this.http.request('GET', `${BASE}/`, { query: { ...page } });
  }

  /** GET /api/v1/tenants/{tenantID} */
  get(tenantId: string): Promise<WrappedTenantResponse> {
    return this.http.request('GET', tenantPath(tenantId));
  }

  /** DELETE /api/v1/tenants/{tenantID} (204). */
  async delete(tenantId: string): Promise<void> {
    await this.http.request<void>('DELETE', tenantPath(tenantId), { parse: 'void' });
  }

  /** PUT /api/v1/tenants/{tenantID}/entitlements */
  updateEntitlements(
    tenantId: string,
    req: UpdateTenantEntitlementsRequest,
  ): Promise<UpdateTenantEntitlementsResponse> {
    return this.http.request('PUT', tenantPath(tenantId, '/entitlements'), { body: req });
  }

  /** PUT /api/v1/tenants/{tenantID}/quotas */
  updateQuotas(
    tenantId: string,
    req: UpdateTenantQuotasRequest,
  ): Promise<UpdateTenantQuotasResponse> {
    return this.http.request('PUT', tenantPath(tenantId, '/quotas'), { body: req });
  }

  /**
   * GET /api/v1/tenants/{tenantID}/tpm — a tenant's TPM mode. System-scope
   * only.
   */
  getTPMMode(tenantId: string): Promise<TenantTPMModeResponse> {
    return this.http.request('GET', tenantPath(tenantId, '/tpm'));
  }

  /**
   * PUT /api/v1/tenants/{tenantID}/tpm — changes a tenant's TPM mode.
   * Refused while the tenant's scope holds objects or policies.
   */
  setTPMMode(tenantId: string, req: SetTenantTPMModeRequest): Promise<TenantTPMModeResponse> {
    return this.http.request('PUT', tenantPath(tenantId, '/tpm'), { body: req });
  }

  /** GET /api/v1/tenants/{tenantID}/tpm/vtpm — a vtpm-mode tenant's virtual TPM. */
  vtpmStatus(tenantId: string): Promise<TenantVTPMStatusResponse> {
    return this.http.request('GET', tenantPath(tenantId, '/tpm/vtpm'));
  }

  /** POST /api/v1/tenants/{tenantID}/tpm/vtpm/start */
  vtpmStart(tenantId: string): Promise<TenantVTPMStatusResponse> {
    return this.http.request('POST', tenantPath(tenantId, '/tpm/vtpm/start'));
  }

  /** POST /api/v1/tenants/{tenantID}/tpm/vtpm/stop */
  vtpmStop(tenantId: string): Promise<TenantVTPMStatusResponse> {
    return this.http.request('POST', tenantPath(tenantId, '/tpm/vtpm/stop'));
  }
}
