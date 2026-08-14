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
 * Session store. Holds the authenticated identity, its effective UI
 * permissions, and the server capability flags — all sourced from
 * GET /api/v1/auth/me. Navigation and controls gate on `can()`; the server's
 * RBAC decorators remain the enforcement authority (views still handle 403).
 */

import type { AuthMeResponse } from "@go-xkms/sdk";
import { getSDKClient } from "./sdkClient.ts";

let _me = $state<AuthMeResponse | null>(null);
let _loading = $state<boolean>(false);
let _error = $state<string | null>(null);

export const sessionStore = {
  get me(): AuthMeResponse | null {
    return _me;
  },
  get loading(): boolean {
    return _loading;
  },
  get error(): string | null {
    return _error;
  },
  get username(): string {
    return _me?.username ?? _me?.subject ?? "";
  },
  get displayName(): string {
    return _me?.display_name ?? _me?.username ?? _me?.subject ?? "";
  },
  get roles(): string[] {
    return _me?.roles ?? [];
  },
  get capabilities(): Record<string, boolean> {
    return _me?.capabilities ?? {};
  },
};

/** loadSession fetches /auth/me and populates the store. */
export async function loadSession(): Promise<void> {
  _loading = true;
  _error = null;
  try {
    _me = await getSDKClient().auth.me();
  } catch (err) {
    _me = null;
    _error = err instanceof Error ? err.message : String(err);
  } finally {
    _loading = false;
  }
}

/** clearSession drops the cached identity (on logout). */
export function clearSession(): void {
  _me = null;
  _error = null;
}

/**
 * can reports whether the current identity holds resource:action. When no
 * session is loaded the answer is false. When the server has RBAC disabled it
 * returns an all-true permission map, so everything is permitted.
 */
export function can(resource: string, action: string): boolean {
  if (_me === null) {
    return false;
  }
  return _me.permissions[`${resource}:${action}`] === true;
}

/** hasCapability reports whether an optional server subsystem is wired. */
export function hasCapability(name: string): boolean {
  return _me?.capabilities?.[name] === true;
}
