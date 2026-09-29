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

/**
 * TPM policy DTOs. Mirrors pkg/api/transport/types.go (the TPM policy
 * section) — served over REST at /api/v1/tpm/policies,
 * /api/v1/keys/{id}/tpm-policy, /api/v1/tpm/authority/rotate, and a
 * tenant's TPM mode/vTPM under /api/v1/tenants/{tenantID}/tpm. See
 * docs/tpm-policies/api.md.
 */

import type { Base64, RFC3339 } from './common.js';

/** Mirrors pkg/api/transport/types.go TPMPolicy. */
export interface TPMPolicy {
  name: string;
  /** Empty for the system scope. */
  tenant_id?: string;
  /** PCR bank: sha1, sha256, sha384 or sha512. */
  bank: string;
  pcrs: number[];
  /** Hex-encoded PCR values captured at create/update, keyed by PCR index. */
  pcr_values?: Record<string, string>;
  /** Hex-encoded PolicyPCR digest over pcr_values. */
  pcr_digest?: string;
  /** The policy's NV index; objects bound to it follow it. */
  index: number;
  /** False after a revoke until the next update. */
  approved: boolean;
  epoch?: number;
  authority_generation?: number;
  /** Marks the policy barrier auto-unseal uses. */
  auto_unseal?: boolean;
  created_at: RFC3339;
  updated_at?: RFC3339;
}

/**
 * Mirrors pkg/api/transport/types.go TPMPolicyCreateRequest. The PCR values
 * are always captured live from the tenant's TPM; the caller never supplies
 * them.
 */
export interface TPMPolicyCreateRequest {
  tenant_id?: string;
  name: string;
  bank: string;
  pcrs: number[];
  auto_unseal?: boolean;
  /** The physical TPM's owner-hierarchy authorization; never logged. */
  owner_auth?: Base64;
}

/** Mirrors pkg/api/transport/types.go TPMPolicyListResponse. */
export interface TPMPolicyListResponse {
  policies: TPMPolicy[];
}

/**
 * Mirrors pkg/api/transport/types.go TPMPolicyDeleteRequest. Deletion is
 * refused (409) while any object is assigned to the policy.
 */
export interface TPMPolicyDeleteRequest {
  tenant_id?: string;
  owner_auth?: Base64;
}

/**
 * Mirrors pkg/api/transport/types.go TPMPolicyVerifyResponse. Advisory: the
 * TPM itself enforces the policy on use.
 */
export interface TPMPolicyVerifyResponse {
  name: string;
  /** True when every selected PCR still holds its captured value. */
  match: boolean;
  /** PCR indices that no longer match, ascending. */
  mismatched?: number[];
  /** Whether the policy's approval is current. */
  approved: boolean;
}

/**
 * Mirrors pkg/api/transport/types.go TPMPolicyObjectsResponse. Objects are
 * "<kind>/<name>" IDs (kind is "key" or "sealed"), sorted.
 */
export interface TPMPolicyObjectsResponse {
  name: string;
  objects: string[];
}

/** TPM object kinds a policy is assigned to (pkg/api/transport/types.go). */
export type TPMObjectKind = 'key' | 'sealed';

/** Mirrors pkg/api/transport/types.go TPMObjectPolicyResponse. */
export interface TPMObjectPolicyResponse {
  object_id: string;
  kind: string;
  policy: string;
  /** Hex-encoded authPolicy digest at creation. */
  auth_policy?: string;
  created_at: RFC3339;
}

/** Mirrors pkg/api/transport/types.go TPMAuthorityRotateResponse. */
export interface TPMAuthorityRotateResponse {
  tenant_id?: string;
  /** Counts rotations. */
  generation: number;
  /** The new authority's hex-encoded TPM Name; every approval is now verified against it. */
  authority_name: string;
  /** The revocation counter's current value. */
  epoch: number;
}

// A tenant's TPM mode and vTPM (TenantTPMModeResponse, SetTenantTPMModeRequest,
// TenantVTPMStatusResponse) are defined in ./tenants.js: the operations are
// system-scope only and served by TenantsClient, not TpmPolicyClient.
