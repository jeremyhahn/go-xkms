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

/**
 * App-level auth wiring. initAuth() configures the shared svelte-auth package
 * against the SDK client once at bootstrap and caches the resulting context
 * (auth store + credential provider) for the login views.
 */

import { initAuth, type AuthContext } from "@go-xkms/svelte-auth";
import { getSDKClient } from "$stores/sdkClient.ts";

let _context: AuthContext | null = null;

/** setupAuth wires the auth package once. Safe to call repeatedly. */
export function setupAuth(): AuthContext {
  if (_context === null) {
    _context = initAuth({
      client: getSDKClient(),
      storagePrefix: "xkms",
      apiPrefixes: ["/api/", "/xkms/"],
    });
  }
  return _context;
}

/** getAuthContext returns the wired context, initialising it on demand. */
export function getAuthContext(): AuthContext {
  return setupAuth();
}
