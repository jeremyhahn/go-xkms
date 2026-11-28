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

// Trust-bootstrap listener keys (GET /api/v1/bootstrap/keys, bootstrap:read).
// sdk/ts has no method for this route, so the console calls it through the
// client's public HTTP core.

import { XkmsApiError } from "@go-xkms/sdk";
import { getSDKClient } from "$stores/sdkClient.ts";

/** Wire shape of pkg/api/transport BootstrapListenerKeysResponse. */
export interface BootstrapListenerKeysResponse {
  /** Hex X25519 static key; the client's --noise-key / trust.bootstrap.noise.server_key. */
  noise_public_key?: string;
  /** Hex uncompressed P-256 key of TSBOOT1_P256_AESGCM_SHA256; the client's --p256-key. */
  p256_public_key?: string;
}

export function getBootstrapKeys(): Promise<BootstrapListenerKeysResponse> {
  return getSDKClient().http.request<BootstrapListenerKeysResponse>("GET", "/api/v1/bootstrap/keys");
}

/** True when the server has no listener (503) or no bootstrap handlers (404). */
export function isListenerDisabled(err: unknown): boolean {
  return err instanceof XkmsApiError && (err.status === 503 || err.status === 404);
}
