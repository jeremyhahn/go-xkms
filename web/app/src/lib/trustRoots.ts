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

// Typed helpers over /api/v1/trust-roots (pkg/api/rest/routes.go). The
// wire types mirror pkg/api/transport/types_trust_roots.go; sdk/ts has no
// trust-roots client yet, so these call the SDK's HTTP core directly.

import { getSDKClient } from "$stores/sdkClient.ts";

export interface TrustRoot {
  fingerprint: string;
  purpose: string;
  subject: string;
  issuer: string;
  algorithm: string;
  not_before: string;
  not_after: string;
  added_at: string;
  source?: string;
  pem?: string;
}

export interface TrustRootListResponse {
  roots: TrustRoot[];
}

export interface TrustRootImportRequest {
  pem: string;
  purpose?: string;
  source?: string;
}

export interface TrustRootImportResponse {
  added: number;
  skipped: number;
}

export const TRUST_ROOT_PURPOSES = [
  "general",
  "user-ca",
  "bootstrap-ca",
  "tpm-manufacturer",
  "android-hardware",
  "idevid-issuer",
  "image-signer",
  "synced",
] as const;

const BASE = "/api/v1/trust-roots";

function rootPath(fingerprint: string): string {
  return `${BASE}/${encodeURIComponent(fingerprint)}`;
}

export async function listTrustRoots(purpose?: string): Promise<TrustRoot[]> {
  const opts = purpose ? { query: { purpose } } : {};
  const res = await getSDKClient().http.request<TrustRootListResponse>("GET", BASE, opts);
  return res?.roots ?? [];
}

export function importTrustRoots(req: TrustRootImportRequest): Promise<TrustRootImportResponse> {
  return getSDKClient().http.request<TrustRootImportResponse>("POST", BASE, { body: req });
}

export function quarantineTrustRoot(fingerprint: string): Promise<TrustRoot> {
  return getSDKClient().http.request<TrustRoot>("POST", `${rootPath(fingerprint)}/quarantine`);
}

export async function deleteTrustRoot(fingerprint: string): Promise<void> {
  await getSDKClient().http.request<void>("DELETE", rootPath(fingerprint), { parse: "void" });
}
