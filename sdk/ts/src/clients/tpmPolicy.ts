// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
import type {
  TPMAuthorityRotateResponse,
  TPMObjectKind,
  TPMObjectPolicyResponse,
  TPMPolicy,
  TPMPolicyCreateRequest,
  TPMPolicyDeleteRequest,
  TPMPolicyListResponse,
  TPMPolicyObjectsResponse,
  TPMPolicyVerifyResponse,
} from '../types/tpmPolicy.js';

const BASE = '/api/v1/tpm/policies';

function policyPath(name: string, action?: string): string {
  const path = `${BASE}/${encodeURIComponent(name)}`;
  return action ? `${path}/${action}` : path;
}

/**
 * Named TPM policies: PCR-bank capture, approval lifecycle, auto-unseal, and
 * the objects (keys / sealed data) bound to them. Mirrors
 * pkg/api/rest/handlers_tpm_policy.go and pkg/api/rest/wire.TPMPolicyClient.
 * See docs/tpm-policies/api.md.
 */
export class TpmPolicyClient {
  constructor(private readonly http: HttpCore) {}

  /** POST /api/v1/tpm/policies — captures the tenant's live PCR values. */
  create(req: TPMPolicyCreateRequest): Promise<TPMPolicy> {
    return this.http.request('POST', BASE, { body: req });
  }

  /** GET /api/v1/tpm/policies?tenant_id= */
  list(tenantId?: string): Promise<TPMPolicyListResponse> {
    return this.http.request('GET', BASE, { query: { tenant_id: tenantId } });
  }

  /** GET /api/v1/tpm/policies/{name}?tenant_id= */
  get(name: string, tenantId?: string): Promise<TPMPolicy> {
    return this.http.request('GET', policyPath(name), { query: { tenant_id: tenantId } });
  }

  /** POST /api/v1/tpm/policies/{name}/update — re-captures and re-approves. */
  update(name: string, tenantId?: string): Promise<TPMPolicy> {
    return this.http.request('POST', policyPath(name, 'update'), {
      body: { tenant_id: tenantId, name },
    });
  }

  /** POST /api/v1/tpm/policies/{name}/revoke — withdraws the approval. */
  revoke(name: string, tenantId?: string): Promise<TPMPolicy> {
    return this.http.request('POST', policyPath(name, 'revoke'), {
      body: { tenant_id: tenantId, name },
    });
  }

  /** POST /api/v1/tpm/policies/{name}/verify — compares captured vs. live PCR values. */
  verify(name: string, tenantId?: string): Promise<TPMPolicyVerifyResponse> {
    return this.http.request('POST', policyPath(name, 'verify'), {
      body: { tenant_id: tenantId, name },
    });
  }

  /**
   * DELETE /api/v1/tpm/policies/{name} (204). Refused with 409 while any
   * object is assigned to the policy.
   */
  async delete(name: string, req: TPMPolicyDeleteRequest = {}): Promise<void> {
    await this.http.request<void>('DELETE', policyPath(name), {
      body: { tenant_id: req.tenant_id, owner_auth: req.owner_auth },
      parse: 'void',
    });
  }

  /** GET /api/v1/tpm/policies/{name}/objects?tenant_id= — objects bound to the policy. */
  objects(name: string, tenantId?: string): Promise<TPMPolicyObjectsResponse> {
    return this.http.request('GET', policyPath(name, 'objects'), {
      query: { tenant_id: tenantId },
    });
  }

  /**
   * POST /api/v1/tpm/policies/{name}/auto-unseal — setting it clears the
   * mark from every other policy of the tenant.
   */
  setAutoUnseal(name: string, enabled: boolean, tenantId?: string): Promise<TPMPolicy> {
    return this.http.request('POST', policyPath(name, 'auto-unseal'), {
      body: { tenant_id: tenantId, name, enabled },
    });
  }

  /** GET /api/v1/keys/{id}/tpm-policy?tenant_id=&kind= — the policy an object was created under. */
  keyPolicy(
    keyId: string,
    opts: { tenantId?: string; kind?: TPMObjectKind } = {},
  ): Promise<TPMObjectPolicyResponse> {
    return this.http.request('GET', `/api/v1/keys/${encodeURIComponent(keyId)}/tpm-policy`, {
      query: { tenant_id: opts.tenantId, kind: opts.kind },
    });
  }

  /** POST /api/v1/tpm/authority/rotate — rotates a tenant's policy authority. */
  rotateAuthority(tenantId?: string): Promise<TPMAuthorityRotateResponse> {
    return this.http.request('POST', '/api/v1/tpm/authority/rotate', {
      body: { tenant_id: tenantId },
    });
  }
}
