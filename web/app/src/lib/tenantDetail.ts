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

// Typed helpers for the Tenant Detail view over the SDK's tenants client:
// GET /api/v1/tenants (list), GET and DELETE /api/v1/tenants/{tenantID}.

import type { TenantInfoResponse } from "@go-xkms/sdk";
import { getSDKClient } from "$stores/sdkClient.ts";

/** The IDs of the tenants the caller can see. */
export async function listTenantIds(): Promise<string[]> {
  const resp = await getSDKClient().tenants.list();
  return resp.tenants.map((t) => t.id);
}

/** One tenant's record. The raw ID is passed; the SDK encodes it. */
export async function loadTenant(id: string): Promise<TenantInfoResponse> {
  const resp = await getSDKClient().tenants.get(id);
  return resp.tenant;
}

/** Deletes one tenant (204 on success). */
export async function deleteTenant(id: string): Promise<void> {
  await getSDKClient().tenants.delete(id);
}

/** True when the error carries HTTP status 404, as XkmsApiError does. */
export function isNotFound(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { status?: unknown }).status === 404;
}
