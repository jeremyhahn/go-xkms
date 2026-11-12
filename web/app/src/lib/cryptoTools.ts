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

// Random and hash helpers over the server's key-less crypto utility routes
// (pkg/api/transport/types_cryptoutil.go). sdk/ts has no method for them yet,
// so these call the SDK's HTTP core directly.

import { getSDKClient } from "$stores/sdkClient.ts";
import { b64ToBytes } from "./b64.ts";

export interface GenerateRandomRequest {
  length: number;
}

export interface GenerateRandomResponse {
  /** Standard base64 of the random bytes. */
  random: string;
}

export interface HashRequest {
  /** Standard base64 of the data to hash. */
  data: string;
  /** Algorithm name; omitted selects the server default. */
  hash?: string;
}

export interface HashResponse {
  /** Standard base64 of the digest. */
  digest: string;
  /** The algorithm the server used. */
  hash: string;
}

export const RANDOM_MIN = 1;
export const RANDOM_MAX = 1024;

export function generateRandom(length: number): Promise<GenerateRandomResponse> {
  const body: GenerateRandomRequest = { length };
  return getSDKClient().http.request<GenerateRandomResponse>("POST", "/api/v1/random", { body });
}

export function hashData(dataB64: string, hash?: string): Promise<HashResponse> {
  const body: HashRequest = { data: dataB64 };
  if (hash) body.hash = hash;
  return getSDKClient().http.request<HashResponse>("POST", "/api/v1/hash", { body });
}

export function b64ToHex(b64: string): string {
  return Array.from(b64ToBytes(b64), (b) => b.toString(16).padStart(2, "0")).join("");
}
