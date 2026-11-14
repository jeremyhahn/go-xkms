// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Read-only helpers for the TPM Policy Detail view. An undefined tenant ID
// means the caller's own scope; the server refuses a tenant-scoped caller
// asking for another tenant, and that error reaches the view as is.

import type { TPMPolicy, TPMPolicyCondition, TPMPolicyVerifyResponse } from "@go-xkms/sdk";
import { getSDKClient } from "$stores/sdkClient.ts";

/** Tenant IDs the caller may pick as a scope; [] when the list is refused. */
export async function listScopes(): Promise<string[]> {
  try {
    const res = await getSDKClient().tenants.list();
    return (res.tenants ?? []).map((t) => t.id);
  } catch {
    return [];
  }
}

export async function listPolicyNames(tenantId?: string): Promise<string[]> {
  const res = await getSDKClient().tpmPolicies.list(tenantId);
  return (res.policies ?? []).map((p) => p.name);
}

export function loadPolicy(name: string, tenantId?: string): Promise<TPMPolicy> {
  return getSDKClient().tpmPolicies.get(name, tenantId);
}

export async function policyObjects(name: string, tenantId?: string): Promise<string[]> {
  const res = await getSDKClient().tpmPolicies.objects(name, tenantId);
  return res.objects ?? [];
}

export function verifyPolicy(name: string, tenantId?: string): Promise<TPMPolicyVerifyResponse> {
  return getSDKClient().tpmPolicies.verify(name, tenantId);
}

/** The condition's captured PCR values as rows sorted by PCR index. */
export function pcrRows(c: TPMPolicyCondition): { pcr: number; value: string }[] {
  return Object.entries(c.pcr_values ?? {})
    .map(([k, value]) => ({ pcr: Number(k), value }))
    .sort((a, b) => a.pcr - b.pcr);
}
